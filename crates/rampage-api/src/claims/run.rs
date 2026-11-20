//! Claims checked by running the function: `returns` (one call's result) and `computes` (a known algorithm or an
//! integer expression, on generated inputs).

use serde::Deserialize;
use serde_json::{Value, json};

use super::expr::Expression;
use super::reference::{AlgorithmSpec, Reference, Shape, sha256_block};
use super::{Address, Budget, Confidence, Outcome, hex, hex_prefix};
use crate::Project;
use crate::evaluate::{
    Convention, DataReads, EvaluateArgument, EvaluateReport, EvaluateRequest, FloatText, ImageState, IntegerText,
    MemoryWrite, MmioValue, StopReason,
};

pub const DEFAULT_SAMPLES: usize = 16;
pub const MAX_SAMPLES: usize = 64;
/// The seed of generated inputs when a claim gives none.
pub const DEFAULT_SEED: u64 = 0x5eed_c1a1_0000_0001;
const MAX_SETUP: usize = 4;
/// Buffer lengths of generated inputs, in the order samples take them: empty, one byte, the CRC catalogue's
/// "123456789", short and block-boundary lengths, then long buffers. Samples past the list take seeded lengths.
const LENGTHS: [usize; 24] =
    [0, 1, 9, 2, 3, 4, 7, 8, 15, 16, 31, 32, 64, 255, 1024, 63, 5, 17, 33, 65, 127, 128, 256, 4096];
const RANDOM_LENGTH_LIMIT: usize = 512;
/// Input bytes a counterexample shows.
const SHOWN_INPUT: usize = 64;
/// Sample rows a verified computes claim shows.
const SHOWN_SAMPLES: usize = 4;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetupCall {
    at: Address,
    #[serde(default)]
    args: Vec<EvaluateArgument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedBuffer {
    /// The argument index of the buffer.
    argument: usize,
    hex: Option<String>,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReturnsClaim {
    function: Address,
    #[serde(default)]
    args: Vec<EvaluateArgument>,
    value: Option<IntegerText>,
    float: Option<FloatText>,
    /// Width the value is compared at; for `float`, 32 or 64 (default 64).
    bits: Option<u32>,
    #[serde(default)]
    buffers: Vec<ExpectedBuffer>,
    #[serde(default)]
    memory: Vec<MemoryWrite>,
    #[serde(default)]
    mmio: Vec<MmioValue>,
    #[serde(default)]
    setup: Vec<SetupCall>,
    #[serde(default)]
    convention: Convention,
    max_steps: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ComputesClaim {
    function: Address,
    algorithm: Option<AlgorithmSpec>,
    expression: Option<String>,
    /// Algorithm: argument roles in order (`data`, `length`, `out`, `state`) or fixed integers. Expression: variable
    /// names in order, or fixed integers.
    args: Option<Vec<Value>>,
    /// Expression width (8, 16, 32 or 64; default 32).
    bits: Option<u32>,
    samples: Option<usize>,
    seed: Option<u64>,
    #[serde(default)]
    memory: Vec<MemoryWrite>,
    #[serde(default)]
    mmio: Vec<MmioValue>,
    #[serde(default)]
    setup: Vec<SetupCall>,
    #[serde(default)]
    convention: Convention,
    max_steps: Option<u64>,
}

/// Runs of one function from one starting image: the file's, or as the claim's setup calls leave it.
struct Runner<'a> {
    project: &'a Project,
    at: String,
    state: ImageState,
    memory: Vec<MemoryWrite>,
    mmio: Vec<MmioValue>,
    convention: Convention,
    max_steps: Option<u64>,
    budget: Budget,
    /// The setup calls run, as evidence.
    setup: Vec<Value>,
}

fn at_text(address: &Address) -> String {
    match address {
        Address::Number(address) => format!("{address:#x}"),
        Address::Text(text) => text.clone(),
    }
}

/// What would let a run that stopped for `stop` finish.
fn needs_for(stop: StopReason) -> &'static str {
    match stop {
        StopReason::StepLimit => "a larger max_steps (at most 20000000), or smaller inputs",
        StopReason::Timeout => "more time: a larger timeout_ms, fewer samples, or smaller inputs",
        StopReason::ExternalCall | StopReason::ExternalRead => {
            "the import has no library model: check the function's callees instead, or give what it reads with memory"
        }
        StopReason::UnmappedRead | StopReason::UnmappedWrite => {
            "the memory it touches: map it with memory or mmio, or run its initialiser first with setup"
        }
        StopReason::UserOp | StopReason::UnsupportedOp | StopReason::InvalidInstruction => {
            "an instruction the interpreter cannot run: a different function, or a claim checked statically"
        }
        _ => "different arguments or setup",
    }
}

impl<'a> Runner<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        project: &'a Project,
        function: &Address,
        setup: &[SetupCall],
        memory: &[MemoryWrite],
        mmio: &[MmioValue],
        convention: Convention,
        max_steps: Option<u64>,
        budget: Budget,
    ) -> Result<Self, Outcome> {
        if setup.len() > MAX_SETUP {
            return Err(Outcome::invalid(format!("at most {MAX_SETUP} setup calls")));
        }
        let mut runner = Runner {
            project,
            at: at_text(function),
            state: ImageState::default(),
            memory: memory.to_vec(),
            mmio: mmio.to_vec(),
            convention,
            max_steps,
            budget,
            setup: Vec::new(),
        };
        for call in setup {
            let request = runner.request(at_text(&call.at), call.args.clone(), None, None)?;
            let (report, state, _) = project.evaluate_stateful(&request, &runner.state)?;
            if report.stop != StopReason::Returned {
                let outcome = Outcome::unknown(
                    "evaluate_function (setup)",
                    json!({"setup": at_text(&call.at), "stop": report.stop, "detail": report.detail}),
                    format!("the setup call {} did not return: {}", at_text(&call.at), report.detail),
                );
                return Err(outcome.needs(needs_for(report.stop)));
            }
            runner.state = state;
            runner.setup.push(json!({"at": at_text(&call.at), "steps": report.steps}));
        }
        Ok(runner)
    }

    fn request(
        &self,
        at: String,
        args: Vec<EvaluateArgument>,
        return_bits: Option<u32>,
        return_float: Option<u32>,
    ) -> Result<EvaluateRequest, Outcome> {
        if self.budget.expired() {
            return Err(Outcome::unknown("evaluate_function", Value::Null, "the call's time budget ran out")
                .needs("a larger timeout_ms, or fewer samples"));
        }
        Ok(EvaluateRequest {
            at,
            args,
            convention: self.convention,
            return_bits,
            return_float,
            memory: self.memory.clone(),
            mmio: self.mmio.clone(),
            max_steps: self.max_steps,
            timeout_ms: Some(self.budget.remaining_ms().clamp(1, crate::evaluate::MAX_TIMEOUT_MS)),
            stubs: None,
            trace: None,
        })
    }

    fn run(
        &self,
        args: Vec<EvaluateArgument>,
        return_bits: Option<u32>,
        return_float: Option<u32>,
    ) -> Result<(EvaluateReport, DataReads), Outcome> {
        let request = self.request(self.at.clone(), args, return_bits, return_float)?;
        let (report, _, reads) = self.project.evaluate_stateful(&request, &self.state)?;
        Ok((report, reads))
    }
}

/// The unknown a run that did not return gives.
fn stopped(report: &EvaluateReport, context: Value) -> Outcome {
    let mut evidence = json!({"stop": report.stop, "detail": report.detail, "steps": report.steps});
    if let Some(at) = &report.stopped_at {
        evidence["stopped_at"] = json!(format!("{:#x}", at.address));
    }
    if let (Value::Object(evidence), Value::Object(context)) = (&mut evidence, context) {
        evidence.extend(context);
    }
    Outcome::unknown("evaluate_function", evidence, format!("the run did not return: {}", report.detail))
        .needs(needs_for(report.stop))
}

fn reads_evidence(reads: &DataReads) -> Value {
    let list = |addresses: &[u64]| addresses.iter().map(|address| format!("{address:#x}")).collect::<Vec<_>>();
    let mut value = json!({});
    if reads.unset_count > 0 {
        value["unset"] = json!(list(&reads.unset));
    }
    if reads.initial_count > 0 {
        value["initial"] = json!(list(&reads.initial));
    }
    value
}

/// A mismatch's outcome: refuted with the counterexample, unless the run read writable data the program sets at run
/// time, which this run read unset: then the mismatch may be the missing initialisation, and the answer is unknown.
fn mismatch(method: String, mut counterexample: Value, reads: &DataReads, confidence: Confidence) -> Outcome {
    if reads.unset_count > 0 || reads.initial_count > 0 {
        counterexample["data_reads"] = reads_evidence(reads);
    }
    if reads.unset_count > 0 {
        let addresses: Vec<String> = reads.unset.iter().map(|address| format!("{address:#x}")).collect();
        return Outcome::unknown(
            method,
            counterexample,
            format!(
                "the result differs, but the run read writable data that has no initial value in the file ({}) and \
                 that nothing in the run set: the program may set it before the call",
                addresses.join(", ")
            ),
        )
        .needs("run its initialiser first with setup [{at, args}], or give its bytes with memory");
    }
    Outcome::refuted(confidence, method, counterexample)
}

pub(crate) fn parse_integer(text: &IntegerText) -> Result<(u64, bool), String> {
    match text {
        IntegerText::Unsigned(value) => Ok((*value, false)),
        IntegerText::Signed(value) => Ok((*value as u64, *value < 0)),
        IntegerText::Text(text) => {
            let clean = text.trim().replace('_', "");
            let (negative, body) = match clean.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, clean.as_str()),
            };
            let value = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16),
                None => body.parse(),
            }
            .map_err(|_| format!("{text:?} is not an integer"))?;
            Ok((if negative { value.wrapping_neg() } else { value }, negative))
        }
    }
}

fn mask(bits: u32) -> u128 {
    if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 }
}

fn result_bits(report: &EvaluateReport) -> Option<(u128, u32)> {
    let result = report.result.as_ref()?;
    let value = u128::from_str_radix(result.hex.trim_start_matches("0x"), 16).ok()?;
    Some((value, result.bits))
}

pub(crate) fn returns(project: &Project, claim: &ReturnsClaim, budget: Budget) -> Outcome {
    if claim.value.is_none() && claim.float.is_none() && claim.buffers.is_empty() {
        return Outcome::invalid("a returns claim states value, float or buffers");
    }
    if claim.value.is_some() && claim.float.is_some() {
        return Outcome::invalid("state value or float, not both");
    }
    let float_bits = match (&claim.float, claim.bits) {
        (Some(_), None) => Some(64),
        (Some(_), Some(bits @ (32 | 64))) => Some(bits),
        (Some(_), Some(_)) => return Outcome::invalid("a float result has 32 or 64 bits"),
        (None, _) => None,
    };
    let runner = match Runner::new(
        project,
        &claim.function,
        &claim.setup,
        &claim.memory,
        &claim.mmio,
        claim.convention,
        claim.max_steps,
        budget,
    ) {
        Ok(runner) => runner,
        Err(outcome) => return outcome,
    };
    let return_bits = if float_bits.is_some() { None } else { claim.bits };
    let (report, reads) = match runner.run(claim.args.clone(), return_bits, float_bits) {
        Ok(ran) => ran,
        Err(outcome) => return outcome,
    };
    let method = "evaluate_function on the stated arguments".to_owned();
    let mut evidence = json!({"function": format!("{:#x}", report.function), "steps": report.steps});
    if !runner.setup.is_empty() {
        evidence["setup"] = json!(runner.setup);
    }
    if report.stop != StopReason::Returned {
        return stopped(&report, evidence);
    }
    if reads.initial_count > 0 {
        evidence["assumes_initial_data"] = reads_evidence(&reads)["initial"].clone();
    }
    // The value.
    if let Some((actual, bits)) = result_bits(&report) {
        evidence["result"] = json!(format!("{actual:#x}"));
        if let Some(expected) = &claim.value {
            let (value, negative) = match parse_integer(expected) {
                Ok(parsed) => parsed,
                Err(error) => return Outcome::invalid(error),
            };
            let value = u128::from(value);
            let fits = negative || bits >= 64 || value <= mask(bits);
            if !fits && claim.bits.is_some() {
                return Outcome::invalid(format!("value {value:#x} does not fit in {bits} bits"));
            }
            let expected = if negative { value | !mask(64) } else { value } & mask(bits);
            evidence["expected"] = json!(format!("{expected:#x}"));
            evidence["bits"] = json!(bits);
            if actual != expected {
                // Without an explicit width, a wider register's upper bits may be undefined (a C int on a 64-bit
                // target): equal low 32 bits leave the claim open.
                if claim.bits.is_none() && bits > 32 && actual & mask(32) == expected & mask(32) {
                    return Outcome::unknown(
                        method,
                        evidence,
                        "the low 32 bits equal the value, the upper register bits do not",
                    )
                    .needs("bits 32 for a C int or 32-bit result, or bits 64 for a 64-bit one");
                }
                return mismatch(method, evidence, &reads, Confidence::Exact);
            }
        }
        if let (Some(expected), Some(bits)) = (&claim.float, float_bits) {
            let number = match expected {
                FloatText::Number(number) => *number,
                FloatText::Text(text) => match text.trim().to_ascii_lowercase().as_str() {
                    "inf" | "infinity" => f64::INFINITY,
                    "-inf" | "-infinity" => f64::NEG_INFINITY,
                    "nan" => f64::NAN,
                    other => match other.parse() {
                        Ok(number) => number,
                        Err(_) => return Outcome::invalid(format!("float {text:?} is not a number")),
                    },
                },
            };
            let (equal, expected_bits) = if bits == 32 {
                let got = f32::from_bits(actual as u32);
                let want = number as f32;
                (got == want || (got.is_nan() && want.is_nan()), u64::from(want.to_bits()))
            } else {
                let got = f64::from_bits(actual as u64);
                (got == number || (got.is_nan() && number.is_nan()), number.to_bits())
            };
            evidence["expected"] = json!(format!("{expected_bits:#x}"));
            if let Some(float) = report.result.as_ref().and_then(|result| result.float.clone()) {
                evidence["float"] = json!(float);
            }
            if !equal {
                return mismatch(method, evidence, &reads, Confidence::Exact);
            }
        }
    }
    // The buffers.
    for expected in &claim.buffers {
        let want = match (&expected.hex, &expected.text) {
            (Some(hex), None) => match super::decode_hex(hex) {
                Ok(bytes) => bytes,
                Err(error) => return Outcome::invalid(format!("buffer {}: {error}", expected.argument)),
            },
            (None, Some(text)) => text.as_bytes().to_vec(),
            _ => return Outcome::invalid("an expected buffer takes hex or text"),
        };
        let Some(buffer) = report.buffers.iter().find(|buffer| buffer.argument == expected.argument) else {
            return Outcome::invalid(format!("argument {} is not a buffer", expected.argument));
        };
        let got = super::decode_hex(&buffer.hex).unwrap_or_default();
        if want.len() > got.len() {
            let reason = if want.len() > buffer.size {
                format!("the expected bytes are longer than the buffer ({} bytes)", buffer.size)
            } else {
                "the buffer's bytes past the returned budget were not read back".to_owned()
            };
            return Outcome::unknown(method, evidence, reason);
        }
        let got = &got[..want.len()];
        let key = format!("buffer_{}", expected.argument);
        evidence[key.as_str()] = json!(hex_prefix(got, SHOWN_INPUT));
        if got != want.as_slice() {
            let at = got.iter().zip(&want).position(|(a, b)| a != b).unwrap_or(0);
            evidence["first_difference"] = json!(at);
            evidence["expected_buffer"] = json!(hex_prefix(&want, SHOWN_INPUT));
            return mismatch(method, evidence, &reads, Confidence::Exact);
        }
    }
    Outcome::verified(Confidence::Exact, method, evidence)
}

/// Seeded inputs: xorshift64*.
pub(crate) struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.next() as u8).collect()
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Role {
    Data,
    Length,
    Out,
    State,
    Fixed(u64),
}

fn roles(args: Option<&Vec<Value>>, shape: Shape) -> Result<Vec<Role>, String> {
    let Some(args) = args else {
        return Ok(match shape {
            Shape::Checksum(_) | Shape::Transform => vec![Role::Data, Role::Length],
            Shape::Digest(_) => vec![Role::Data, Role::Length, Role::Out],
            Shape::Block => vec![Role::State, Role::Data],
        });
    };
    let roles = args
        .iter()
        .map(|arg| match arg {
            Value::String(text) => match text.as_str() {
                "data" => Ok(Role::Data),
                "length" => Ok(Role::Length),
                "out" => Ok(Role::Out),
                "state" => Ok(Role::State),
                other => match parse_integer(&IntegerText::Text(other.to_owned())) {
                    Ok((value, _)) => Ok(Role::Fixed(value)),
                    Err(_) => Err(format!("argument role {other:?} is not data, length, out, state or an integer")),
                },
            },
            Value::Number(number) => number
                .as_u64()
                .or_else(|| number.as_i64().map(|value| value as u64))
                .map(Role::Fixed)
                .ok_or_else(|| format!("argument {number} is not an integer")),
            other => Err(format!("argument role {other} is not data, length, out, state or an integer")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let count = |role: &Role| roles.iter().filter(|candidate| *candidate == role).count();
    if count(&Role::Data) != 1 || count(&Role::Length) > 1 || count(&Role::Out) > 1 || count(&Role::State) > 1 {
        return Err("args names data once, and length, out and state at most once each".to_owned());
    }
    let block = shape == Shape::Block;
    if matches!(shape, Shape::Digest(_)) && count(&Role::Out) == 0 {
        return Err("a digest is read from an out buffer: add \"out\"".into());
    }
    if block && (count(&Role::State) == 0 || count(&Role::Length) == 1) {
        return Err("sha256_block takes a state and one 64-byte block (data), no length".into());
    }
    if !block && count(&Role::State) == 1 {
        return Err("only sha256_block takes a state".into());
    }
    Ok(roles)
}

/// One generated input of an algorithm claim.
struct Sample {
    data: Vec<u8>,
    state: [u32; 8],
}

fn algorithm_sample(index: usize, rng: &mut Rng, shape: Shape, nul_terminated: bool) -> Sample {
    let state = std::array::from_fn(|_| rng.next() as u32);
    if shape == Shape::Block {
        return Sample { data: rng.bytes(64), state };
    }
    let length = LENGTHS.get(index).copied().unwrap_or_else(|| (rng.next() % RANDOM_LENGTH_LIMIT as u64) as usize);
    let mut data = if length == 9 && index == 2 {
        b"123456789".to_vec()
    } else {
        match index % 4 {
            0 => rng.bytes(length),
            1 => vec![0; length],
            2 => vec![0xff; length],
            _ => (0..length).map(|offset| (offset + index) as u8).collect(),
        }
    };
    if nul_terminated {
        // A C string has no NUL inside.
        for byte in &mut data {
            if *byte == 0 {
                *byte = 1;
            }
        }
    }
    Sample { data, state }
}

fn buffer(hex_text: String, size: usize) -> EvaluateArgument {
    serde_json::from_value(json!({"buffer": {"hex": hex_text, "size": size.max(1)}})).expect("buffer argument")
}

fn fixed(value: u64, bits: Option<u32>) -> EvaluateArgument {
    match bits {
        Some(bits) => serde_json::from_value(json!({"value": value, "bits": bits})).expect("integer argument"),
        None => EvaluateArgument::Integer(IntegerText::Unsigned(value)),
    }
}

pub(crate) fn computes(project: &Project, claim: &ComputesClaim, budget: Budget) -> Outcome {
    let samples = claim.samples.unwrap_or(DEFAULT_SAMPLES);
    if !(1..=MAX_SAMPLES).contains(&samples) {
        return Outcome::invalid(format!("samples must be 1..={MAX_SAMPLES}"));
    }
    let runner = |budget| {
        Runner::new(
            project,
            &claim.function,
            &claim.setup,
            &claim.memory,
            &claim.mmio,
            claim.convention,
            claim.max_steps,
            budget,
        )
    };
    match (&claim.algorithm, &claim.expression) {
        (Some(algorithm), None) => {
            let reference = match Reference::parse(algorithm) {
                Ok(reference) => reference,
                Err(error) => return Outcome::invalid(error),
            };
            if claim.bits.is_some() {
                return Outcome::invalid("bits is for an expression; an algorithm has its own width");
            }
            let roles = match roles(claim.args.as_ref(), reference.shape()) {
                Ok(roles) => roles,
                Err(error) => return Outcome::invalid(error),
            };
            match runner(budget) {
                Ok(runner) => computes_algorithm(project, &runner, &reference, &roles, samples, claim.seed),
                Err(outcome) => outcome,
            }
        }
        (None, Some(text)) => {
            let expression = match Expression::parse(text) {
                Ok(expression) => expression,
                Err(error) => return Outcome::invalid(error),
            };
            let bits = claim.bits.unwrap_or(32);
            if ![8, 16, 32, 64].contains(&bits) {
                return Outcome::invalid("bits must be 8, 16, 32 or 64");
            }
            match runner(budget) {
                Ok(runner) => computes_expression(&runner, &expression, claim.args.as_ref(), bits, samples, claim.seed),
                Err(outcome) => outcome,
            }
        }
        _ => Outcome::invalid("a computes claim states an algorithm or an expression"),
    }
}

fn computes_algorithm(
    project: &Project,
    runner: &Runner<'_>,
    reference: &Reference,
    roles: &[Role],
    samples: usize,
    seed: Option<u64>,
) -> Outcome {
    let shape = reference.shape();
    let big_endian = project.binary.big_endian;
    let pointer_bits = u32::from(project.binary.arch.pointer_size().unwrap_or(4)) * 8;
    let seed = seed.unwrap_or(DEFAULT_SEED);
    let mut rng = Rng::new(seed);
    let nul_terminated = !roles.contains(&Role::Length) && shape != Shape::Block;
    let to_return = matches!(shape, Shape::Checksum(_)) && !roles.contains(&Role::Out);
    let output = match shape {
        Shape::Checksum(_) if to_return => "the return value",
        Shape::Transform if !roles.contains(&Role::Out) => "the data buffer after the call",
        Shape::Block => "the state buffer after the call",
        _ => "the out buffer",
    };
    let method = format!(
        "evaluate_function on {samples} generated inputs (seed {seed:#x}) compared with {}, reading {output}",
        reference.describe()
    );
    let mut shown = Vec::new();
    let mut lengths = std::collections::BTreeSet::new();
    let mut initial_reads = DataReads::default();
    for index in 0..samples {
        let sample = algorithm_sample(index, &mut rng, shape, nul_terminated);
        let data = &sample.data;
        let state_bytes: Vec<u8> = sample
            .state
            .iter()
            .flat_map(|word| if big_endian { word.to_be_bytes() } else { word.to_le_bytes() })
            .collect();
        // What the reference computes, as the bytes or value the function's output is compared with.
        let (expected_value, expected_bytes): (Option<(u64, u32)>, Vec<u8>) = match shape {
            Shape::Checksum(bits) => {
                let value = reference.checksum(data, big_endian);
                let bytes = value.to_le_bytes()[..(bits / 8) as usize].to_vec();
                let bytes = if big_endian { bytes.into_iter().rev().collect() } else { bytes };
                (Some((value, bits)), bytes)
            }
            Shape::Digest(_) => (None, reference.digest(data)),
            Shape::Transform => (None, reference.transform(data)),
            Shape::Block => {
                let block: &[u8; 64] = data.as_slice().try_into().expect("a 64-byte block");
                let state = sha256_block(sample.state, block);
                let bytes =
                    state.iter().flat_map(|word| if big_endian { word.to_be_bytes() } else { word.to_le_bytes() });
                (None, bytes.collect())
            }
        };
        let mut data_argument = None;
        let mut out_argument = None;
        let mut state_argument = None;
        let mut args = Vec::new();
        for (position, role) in roles.iter().enumerate() {
            args.push(match role {
                Role::Data => {
                    data_argument = Some(position);
                    let mut bytes = data.clone();
                    if nul_terminated {
                        bytes.push(0);
                    }
                    let size = bytes.len();
                    buffer(hex(&bytes), size)
                }
                Role::Length => fixed(data.len() as u64, None),
                Role::Out => {
                    out_argument = Some(position);
                    buffer(String::new(), expected_bytes.len().max(1))
                }
                Role::State => {
                    state_argument = Some(position);
                    buffer(hex(&state_bytes), state_bytes.len())
                }
                Role::Fixed(value) => fixed(*value, None),
            });
        }
        let return_bits = match expected_value {
            Some((_, bits)) if to_return && bits > pointer_bits => Some(bits),
            _ => None,
        };
        let (report, reads) = match runner.run(args, return_bits, None) {
            Ok(ran) => ran,
            Err(outcome) => return outcome,
        };
        let input = json!({"length": data.len(), "data": hex_prefix(data, SHOWN_INPUT)});
        if report.stop != StopReason::Returned {
            return stopped(&report, json!({"input": input, "matched_before": index}));
        }
        initial_reads.initial_count += reads.initial_count;
        for address in &reads.initial {
            if initial_reads.initial.len() < 8 && !initial_reads.initial.contains(address) {
                initial_reads.initial.push(*address);
            }
        }
        let (actual, expected) = if to_return {
            let Some((value, bits)) = expected_value else { unreachable!("a checksum has a value") };
            let Some((register, _)) = result_bits(&report) else {
                return Outcome::unknown(&method, input, "the run returned no value");
            };
            let width = mask(bits);
            (json!(format!("{:#x}", register & width)), json!(format!("{value:#x}")))
        } else {
            let position = match shape {
                Shape::Block => state_argument,
                Shape::Transform if out_argument.is_none() => data_argument,
                _ => out_argument,
            }
            .expect("the output argument");
            let Some(buffer) = report.buffers.iter().find(|buffer| buffer.argument == position) else {
                return Outcome::unknown(&method, input, "the output buffer was not read back");
            };
            let got = super::decode_hex(&buffer.hex).unwrap_or_default();
            if got.len() < expected_bytes.len() {
                return Outcome::unknown(&method, input, "the output buffer was not read back whole")
                    .needs("smaller inputs: fewer samples reach the long lengths");
            }
            let got = &got[..expected_bytes.len()];
            (json!(hex_prefix(got, SHOWN_INPUT)), json!(hex_prefix(&expected_bytes, SHOWN_INPUT)))
        };
        if actual != expected || (to_return && actual.is_null()) {
            let counterexample = json!({
                "counterexample": {"input": input, "expected": expected, "actual": actual},
                "matched_before": index,
            });
            return mismatch(method, counterexample, &reads, Confidence::Exact);
        }
        lengths.insert(data.len());
        if shown.len() < SHOWN_SAMPLES || data.as_slice() == b"123456789" {
            shown.push(json!({"length": data.len(), "data": hex_prefix(data, 16), "output": actual}));
        }
    }
    let mut evidence = json!({
        "samples": samples,
        "lengths": lengths.into_iter().collect::<Vec<_>>(),
        "seed": format!("{seed:#x}"),
        "shown": shown,
    });
    if !runner.setup.is_empty() {
        evidence["setup"] = json!(runner.setup);
    }
    if initial_reads.initial_count > 0 {
        evidence["assumes_initial_data"] = reads_evidence(&initial_reads)["initial"].clone();
    }
    Outcome::verified(
        Confidence::Sampled,
        format!("{method}: equal on every input; another input could still differ"),
        evidence,
    )
}

/// Generated values of one variable: edge cases first, then seeded values, alternating full-width and small.
fn variable_value(sample: usize, variable: usize, bits: u32, rng: &mut Rng) -> u64 {
    let all = if bits == 64 { u64::MAX } else { (1 << bits) - 1 };
    let sign = 1u64 << (bits - 1);
    let edges = [0, 1, all, 2, sign, sign - 1, 3, 0xff & all, 7, 0x100 & all, sign + 1, all - 1];
    let value = if sample < edges.len() {
        edges[(sample + variable * 5) % edges.len()]
    } else if sample.is_multiple_of(2) {
        rng.next()
    } else {
        rng.next() % u64::from(bits + 1)
    };
    value & all
}

fn computes_expression(
    runner: &Runner<'_>,
    expression: &Expression,
    args: Option<&Vec<Value>>,
    bits: u32,
    samples: usize,
    seed: Option<u64>,
) -> Outcome {
    // Arguments: each a variable (by its index in the expression, or a free one it does not use) or a fixed value.
    enum Slot {
        Variable(Option<usize>),
        Fixed(u64),
    }
    let order: Vec<Value> = match args {
        Some(args) => args.clone(),
        None => expression.default_order().into_iter().map(Value::String).collect(),
    };
    let mut slots = Vec::new();
    for arg in &order {
        slots.push(match arg {
            Value::String(name)
                if name.starts_with(|character: char| character.is_ascii_alphabetic() || character == '_') =>
            {
                Slot::Variable(expression.names.iter().position(|known| known == name))
            }
            Value::String(text) => match parse_integer(&IntegerText::Text(text.clone())) {
                Ok((value, _)) => Slot::Fixed(value),
                Err(error) => return Outcome::invalid(error),
            },
            Value::Number(number) => match number.as_u64().or_else(|| number.as_i64().map(|value| value as u64)) {
                Some(value) => Slot::Fixed(value),
                None => return Outcome::invalid(format!("argument {number} is not an integer")),
            },
            other => return Outcome::invalid(format!("argument {other} is not a variable name or an integer")),
        });
    }
    for (index, name) in expression.names.iter().enumerate() {
        if !slots.iter().any(|slot| matches!(slot, Slot::Variable(Some(known)) if *known == index)) {
            return Outcome::invalid(format!("the expression's variable {name} is not an argument: list it in args"));
        }
    }
    let width_mask = if bits == 64 { u64::MAX } else { (1 << bits) - 1 };
    let seed = seed.unwrap_or(DEFAULT_SEED);
    let mut rng = Rng::new(seed);
    let names: Vec<Value> = order.clone();
    let method = format!(
        "evaluate_function on {samples} generated inputs (seed {seed:#x}) at {bits} bits, arguments {}, compared with \
         the expression",
        serde_json::to_string(&names).unwrap_or_default()
    );
    let mut shown = Vec::new();
    let mut checked = 0;
    let mut undefined = 0;
    let mut attempt = 0;
    let mut initial_reads = DataReads::default();
    while checked < samples {
        if attempt >= samples * 4 {
            return Outcome::unknown(
                &method,
                json!({"checked": checked, "undefined": undefined}),
                "most generated inputs make the expression undefined (division by zero or an oversized shift)",
            )
            .needs("fixed arguments in args for the divisor or shift count");
        }
        let values: Vec<u64> =
            (0..slots.len()).map(|variable| variable_value(attempt, variable, bits, &mut rng)).collect();
        attempt += 1;
        let mut bound = vec![0u64; expression.names.len()];
        let mut call = Vec::new();
        for (slot, &value) in slots.iter().zip(&values) {
            let value = match slot {
                Slot::Variable(index) => {
                    if let Some(index) = index {
                        bound[*index] = value;
                    }
                    value
                }
                Slot::Fixed(value) => *value & width_mask,
            };
            call.push(value);
        }
        let Ok(expected) = expression.evaluate(&bound, bits) else {
            undefined += 1;
            continue;
        };
        let arguments = call.iter().map(|&value| fixed(value, Some(bits))).collect();
        let (report, reads) = match runner.run(arguments, Some(bits), None) {
            Ok(ran) => ran,
            Err(outcome) => return outcome,
        };
        let input: Vec<String> = call.iter().map(|value| format!("{value:#x}")).collect();
        if report.stop != StopReason::Returned {
            return stopped(&report, json!({"input": input, "matched_before": checked}));
        }
        initial_reads.initial_count += reads.initial_count;
        let Some((actual, _)) = result_bits(&report) else {
            return Outcome::unknown(&method, json!({"input": input}), "the run returned no value");
        };
        let actual = actual as u64 & width_mask;
        if actual != expected {
            let counterexample = json!({
                "counterexample": {"args": input, "expected": format!("{expected:#x}"), "actual": format!("{actual:#x}")},
                "matched_before": checked,
            });
            return mismatch(method, counterexample, &reads, Confidence::Exact);
        }
        checked += 1;
        if shown.len() < SHOWN_SAMPLES {
            shown.push(json!({"args": input, "result": format!("{actual:#x}")}));
        }
    }
    let mut evidence = json!({"samples": samples, "seed": format!("{seed:#x}"), "bits": bits, "shown": shown});
    if undefined > 0 {
        evidence["undefined_skipped"] = json!(undefined);
    }
    if !runner.setup.is_empty() {
        evidence["setup"] = json!(runner.setup);
    }
    if initial_reads.initial_count > 0 {
        evidence["reads_initial_data"] = json!(initial_reads.initial_count);
    }
    Outcome::verified(
        Confidence::Sampled,
        format!(
            "{method}: equal on every input, edge cases (0, 1, all ones, signed minimum and maximum) included; \
             another input could still differ"
        ),
        evidence,
    )
}
