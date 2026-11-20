//! Claims checked by running the function: `returns` (one call's result) and `computes` (a known algorithm or an
//! integer expression, on generated inputs).

use serde::Deserialize;
use serde_json::{Value, json};

use super::expr::Expression;
use super::reference::{AlgorithmSpec, Reference, Shape, sha256_block};
use super::{Address, Budget, Confidence, Outcome, Verdict, hex, hex_prefix};
use crate::Project;
use crate::evaluate::{
    Convention, DataReads, EvaluateArgument, EvaluateReport, EvaluateRequest, FloatText, ImageState, IntegerText,
    MemoryWrite, MmioValue, StopReason,
};

pub const DEFAULT_SAMPLES: usize = 16;
/// An expression argument's width unless the claim gives one: a C int on every supported target.
const DEFAULT_ARGUMENT_BITS: u32 = 32;
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
    /// The whole buffer's final bytes (or its first bytes with `prefix`).
    hex: Option<String>,
    /// A C string: these bytes and a NUL.
    text: Option<String>,
    #[serde(default)]
    prefix: bool,
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
    if reads.initial_count > 0 {
        let addresses: Vec<String> = reads.initial.iter().map(|address| format!("{address:#x}")).collect();
        counterexample["assumes"] = json!(format!(
            "the writable data the run read ({}) held its initial values from the file; the program may change them \
             before the call",
            addresses.join(", ")
        ));
    }
    Outcome::refuted(confidence, method, counterexample)
}

/// Whether a claimed integer fits `bits`: unsigned up to all ones, negative down to the signed minimum.
fn fits(value: u64, negative: bool, bits: u32) -> bool {
    if bits >= 64 {
        return true;
    }
    if negative { (value as i64) >= -(1i64 << (bits - 1)) } else { value < (1u64 << bits) }
}

/// The unset data a verified run read, as evidence: the result holds for that state.
fn note_unset(evidence: &mut Value, reads: &DataReads) {
    if reads.unset_count > 0 {
        evidence["reads_unset_data"] = reads_evidence(reads)["unset"].clone();
    }
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
            if !fits(value, negative, bits) {
                if claim.bits.is_some() {
                    return Outcome::invalid(format!("value {expected:?} does not fit in {bits} bits"));
                }
                // Never compare a wider claim with a masked register.
                return Outcome::unknown(
                    method,
                    evidence,
                    format!("the claimed value does not fit the {bits}-bit result register"),
                )
                .needs(format!("bits {} to read a register pair (EDX:EAX, r1:r0)", 2 * bits.min(64)));
            }
            let value = u128::from(value);
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
            (None, Some(text)) => text.bytes().chain([0]).collect(),
            _ => return Outcome::invalid("an expected buffer takes hex or text"),
        };
        let Some(buffer) = report.buffers.iter().find(|buffer| buffer.argument == expected.argument) else {
            return Outcome::invalid(format!("argument {} is not a buffer", expected.argument));
        };
        let got = super::decode_hex(&buffer.hex).unwrap_or_default();
        if expected.hex.is_some() && !expected.prefix && want.len() != buffer.size {
            return Outcome::invalid(format!(
                "hex states the whole buffer ({} bytes, {} given); pass prefix: true to compare its first bytes",
                buffer.size,
                want.len()
            ));
        }
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
    note_unset(&mut evidence, &reads);
    Outcome::verified(Confidence::Exact, method, evidence)
}

/// Whether a `register_bits` register holds more than a `bits`-wide value: its upper bits are neither zero nor the
/// value's sign extension.
fn wider_than(register: u128, register_bits: u32, bits: u32) -> bool {
    if bits >= register_bits {
        return false;
    }
    let upper = register >> bits;
    let extended = upper == mask(register_bits - bits) && (register >> (bits - 1)) & 1 == 1;
    upper != 0 && !extended
}

/// Adds one run's data reads to a claim's.
fn merge_reads(total: &mut DataReads, reads: &DataReads) {
    total.initial_count += reads.initial_count;
    total.unset_count += reads.unset_count;
    for (list, from) in [(&mut total.initial, &reads.initial), (&mut total.unset, &reads.unset)] {
        for address in from {
            if list.len() < 8 && !list.contains(address) {
                list.push(*address);
            }
        }
    }
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
                Ok(runner) if claim.args.is_none() => {
                    computes_default_layouts(project, &runner, &reference, &roles, samples, claim.seed)
                }
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

fn layout_text(roles: &[Role]) -> String {
    let names: Vec<String> = roles
        .iter()
        .map(|role| match role {
            Role::Data => "data".to_owned(),
            Role::Length => "length".to_owned(),
            Role::Out => "out".to_owned(),
            Role::State => "state".to_owned(),
            Role::Fixed(value) => format!("{value:#x}"),
        })
        .collect();
    format!("[{}]", names.join(", "))
}

/// A checksum claim without `args`: the default `(data, length)`, then the running-value layouts checksum APIs
/// commonly take, `(seed, data, length)` as zlib's `crc32` and `adler32` do and `(data, length, seed)`, the seed
/// being the checksum of no bytes (0 for CRC-32, 1 for Adler-32). The first layout that verifies is reported.
/// Otherwise a layout whose run returned decides: a mismatch left unknown (unset data) before a refutation; a run
/// that faulted or did not return says only that its layout is not the function's.
fn computes_default_layouts(
    project: &Project,
    runner: &Runner<'_>,
    reference: &Reference,
    roles: &[Role],
    samples: usize,
    seed: Option<u64>,
) -> Outcome {
    let first = computes_algorithm(project, runner, reference, roles, samples, seed);
    if first.verdict == Verdict::Verified || !matches!(reference.shape(), Shape::Checksum(_)) {
        return first;
    }
    let initial = reference.checksum(&[], project.binary.big_endian);
    let layouts =
        [vec![Role::Fixed(initial), Role::Data, Role::Length], vec![Role::Data, Role::Length, Role::Fixed(initial)]];
    let mut tried = vec![json!({"args": layout_text(roles), "verdict": first.verdict})];
    let mut outcomes = vec![first];
    for layout in layouts {
        let outcome = computes_algorithm(project, runner, reference, &layout, samples, seed);
        if outcome.verdict == Verdict::Verified {
            let mut outcome = outcome;
            outcome.method = format!(
                "no args were given and {} did not match; with args {}: {}",
                layout_text(roles),
                layout_text(&layout),
                outcome.method
            );
            outcome.evidence["args"] = json!(layout_text(&layout));
            outcome.evidence["tried"] = json!(tried);
            return outcome;
        }
        tried.push(json!({"args": layout_text(&layout), "verdict": outcome.verdict}));
        outcomes.push(outcome);
    }
    let compared = |outcome: &Outcome| outcome.evidence.get("counterexample").is_some();
    let pick = outcomes
        .iter()
        .position(|outcome| outcome.verdict == Verdict::Unknown && compared(outcome))
        .or_else(|| outcomes.iter().position(|outcome| outcome.verdict == Verdict::Refuted))
        .unwrap_or(0);
    let mut chosen = outcomes.swap_remove(pick);
    chosen.method = format!(
        "{}; no args were given, and none of the argument layouts tried ({}) matched; this outcome is for {}. A \
         function taking other arguments needs args",
        chosen.method,
        tried.iter().filter_map(|row| row["args"].as_str()).collect::<Vec<_>>().join(", "),
        tried[pick]["args"].as_str().unwrap_or_default()
    );
    if chosen.evidence.is_object() {
        chosen.evidence["tried"] = json!(tried);
    }
    chosen
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
                let bytes = value.to_le_bytes()[..bits.div_ceil(8) as usize].to_vec();
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
            Some((_, bits)) if to_return && bits > pointer_bits => Some(bits.next_multiple_of(8)),
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
        merge_reads(&mut initial_reads, &reads);
        let (actual, expected) = if to_return {
            let Some((value, bits)) = expected_value else { unreachable!("a checksum has a value") };
            let Some((register, register_bits)) = result_bits(&report) else {
                return Outcome::unknown(&method, input, "the run returned no value");
            };
            let low = register & mask(bits);
            // Bits above the algorithm's width must be zero or a sign extension: otherwise the function computes
            // something wider (sum32 is not sum8 because their low bytes agree).
            if low == u128::from(value) && wider_than(register, register_bits, bits) {
                return Outcome::unknown(
                    &method,
                    json!({"input": input, "result": format!("{register:#x}"), "matched_before": index}),
                    format!(
                        "the low {bits} bits equal the reference, but the register's upper bits are set: the function \
                         may compute a wider value"
                    ),
                )
                .needs("a wider algorithm, or a returns claim on this input with bits");
            }
            (json!(format!("{low:#x}")), json!(format!("{value:#x}")))
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
    note_unset(&mut evidence, &initial_reads);
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
    // Arguments: each a variable (by its index in the expression, or a free one it does not use) or a fixed value,
    // with its own width: a C int (32 bits) unless the claim says otherwise.
    enum Slot {
        Variable { index: Option<usize>, bits: u32, signed: bool },
        Fixed { value: u64, bits: u32 },
    }
    let order: Vec<Value> = match args {
        Some(args) => args.clone(),
        None => expression.default_order().into_iter().map(Value::String).collect(),
    };
    let width = |value: Option<&Value>| -> Result<u32, String> {
        match value {
            None => Ok(DEFAULT_ARGUMENT_BITS),
            Some(bits) => match bits.as_u64() {
                Some(bits @ (8 | 16 | 32 | 64)) => Ok(bits as u32),
                _ => Err(format!("argument bits {bits} is not 8, 16, 32 or 64")),
            },
        }
    };
    let integer = |value: &Value| -> Result<u64, String> {
        match value {
            Value::Number(number) => number
                .as_u64()
                .or_else(|| number.as_i64().map(|value| value as u64))
                .ok_or_else(|| format!("argument {number} is not an integer")),
            Value::String(text) => parse_integer(&IntegerText::Text(text.clone())).map(|(value, _)| value),
            other => Err(format!("argument {other} is not an integer")),
        }
    };
    let variable = |name: &str| expression.names.iter().position(|known| known == name);
    let mut slots = Vec::new();
    for arg in &order {
        let slot = match arg {
            Value::String(name)
                if name.starts_with(|character: char| character.is_ascii_alphabetic() || character == '_') =>
            {
                Ok(Slot::Variable { index: variable(name), bits: DEFAULT_ARGUMENT_BITS, signed: false })
            }
            Value::Object(fields) => {
                let unknown = fields.keys().find(|key| !["name", "value", "bits", "signed"].contains(&key.as_str()));
                match (unknown, fields.get("name").and_then(Value::as_str), fields.get("value")) {
                    (Some(key), ..) => {
                        Err(format!("an argument object takes name or value, bits and signed, not {key}"))
                    }
                    (None, Some(name), None) => width(fields.get("bits")).map(|bits| Slot::Variable {
                        index: variable(name),
                        bits,
                        signed: fields.get("signed").and_then(Value::as_bool).unwrap_or(false),
                    }),
                    (None, None, Some(value)) => integer(value)
                        .and_then(|value| width(fields.get("bits")).map(|bits| Slot::Fixed { value, bits })),
                    _ => Err("an argument object takes a name or a value".to_owned()),
                }
            }
            other => integer(other).map(|value| Slot::Fixed { value, bits: DEFAULT_ARGUMENT_BITS }),
        };
        match slot {
            Ok(Slot::Fixed { value, bits }) if bits < 64 && value >> bits != 0 && (value as i64) >= 0 => {
                return Outcome::invalid(format!("argument {value:#x} does not fit in {bits} bits"));
            }
            Ok(slot) => slots.push(slot),
            Err(error) => return Outcome::invalid(error),
        }
    }
    for (index, name) in expression.names.iter().enumerate() {
        if !slots.iter().any(|slot| matches!(slot, Slot::Variable { index: Some(known), .. } if *known == index)) {
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
        let mut bound = vec![0u64; expression.names.len()];
        let mut call = Vec::new();
        for (position, slot) in slots.iter().enumerate() {
            let (value, arg_bits) = match slot {
                Slot::Variable { index, bits: arg_bits, signed } => {
                    let value = variable_value(attempt, position, *arg_bits, &mut rng);
                    if let Some(index) = index {
                        // The expression sees the argument at its own width, extended to the result's.
                        let shift = 64 - arg_bits;
                        let extended = if *signed { (((value << shift) as i64) >> shift) as u64 } else { value };
                        bound[*index] = extended & width_mask;
                    }
                    (value, *arg_bits)
                }
                Slot::Fixed { value, bits: arg_bits } => {
                    let mask = if *arg_bits == 64 { u64::MAX } else { (1 << arg_bits) - 1 };
                    (*value & mask, *arg_bits)
                }
            };
            call.push((value, arg_bits));
        }
        attempt += 1;
        let Ok(expected) = expression.evaluate(&bound, bits) else {
            undefined += 1;
            continue;
        };
        let arguments = call.iter().map(|&(value, arg_bits)| fixed(value, Some(arg_bits))).collect();
        let (report, reads) = match runner.run(arguments, Some(bits), None) {
            Ok(ran) => ran,
            Err(outcome) => return outcome,
        };
        let input: Vec<String> = call.iter().map(|(value, _)| format!("{value:#x}")).collect();
        if report.stop != StopReason::Returned {
            return stopped(&report, json!({"input": input, "matched_before": checked}));
        }
        merge_reads(&mut initial_reads, &reads);
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
        evidence["assumes_initial_data"] = reads_evidence(&initial_reads)["initial"].clone();
    }
    note_unset(&mut evidence, &initial_reads);
    Outcome::verified(
        Confidence::Sampled,
        format!(
            "{method}: equal on every input, edge cases (0, 1, all ones, signed minimum and maximum) included; \
             another input could still differ"
        ),
        evidence,
    )
}

#[cfg(test)]
mod tests {
    use super::wider_than;

    /// A sum32 routine is not a sum8 one although their low bytes agree: set upper register bits say so, while zero
    /// or sign-extended upper bits are what a narrower C result leaves.
    #[test]
    fn upper_register_bits_tell_a_wider_result() {
        assert!(wider_than(0x1_2345, 32, 8));
        assert!(wider_than(0x1_2345, 32, 16));
        assert!(!wider_than(0x45, 32, 8));
        assert!(!wider_than(0xffff_ff85, 32, 8), "a sign-extended byte");
        assert!(wider_than(0xffff_ff05, 32, 8), "all ones above a byte without its sign bit");
        assert!(!wider_than(0xdead_beef, 32, 32));
    }
}
