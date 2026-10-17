//! Function-signature recovery (the embedded decompiler's inferred prototypes) scored against DWARF.
//!
//! A `-g` build's DWARF is the truth ([`TypeTruth`]) for its stripped twin. Each function's signature is reduced
//! to [`TypeClass`]es, the distinctions a stripped binary can support (integer width, pointer, struct pointer,
//! float width, struct by value), and scored by one [`TypeMetric`] at a time: parameter count, void versus a
//! returned value, and each parameter's class.

use std::collections::BTreeMap;

use gimli::{AttributeValue, Dwarf, EndianSlice, RunTimeEndian, UnitOffset};
use object::{Object, ObjectSection};
use rampage_loaders::Binary;
use serde::{Deserialize, Serialize};

use crate::{Disagreement, Outcome, Report, parse_address_key, ratio};

const MAX_DIES: usize = 1_000_000;
const MAX_TYPE_DEPTH: usize = 32;

/// What a type is, as far as signature recovery is scored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeClass {
    Void,
    Int8,
    Int16,
    Int32,
    Int64,
    Int128,
    Pointer,
    /// A pointer to a struct, class or union.
    StructPointer,
    Float32,
    Float64,
    /// Wider than a double: x87 extended or binary128 `long double`.
    FloatWide,
    /// A struct, class or union passed or returned by value.
    Struct,
    /// Anything else: arrays, complex numbers, odd widths, unresolvable references.
    Other,
}

impl TypeClass {
    pub fn tag(self) -> &'static str {
        match self {
            TypeClass::Void => "void",
            TypeClass::Int8 => "int8",
            TypeClass::Int16 => "int16",
            TypeClass::Int32 => "int32",
            TypeClass::Int64 => "int64",
            TypeClass::Int128 => "int128",
            TypeClass::Pointer => "pointer",
            TypeClass::StructPointer => "struct_pointer",
            TypeClass::Float32 => "float32",
            TypeClass::Float64 => "float64",
            TypeClass::FloatWide => "float_wide",
            TypeClass::Struct => "struct",
            TypeClass::Other => "other",
        }
    }

    fn integer(bytes: u64) -> TypeClass {
        match bytes {
            1 => TypeClass::Int8,
            2 => TypeClass::Int16,
            4 => TypeClass::Int32,
            8 => TypeClass::Int64,
            16 => TypeClass::Int128,
            _ => TypeClass::Other,
        }
    }

    fn float(bytes: u64) -> TypeClass {
        match bytes {
            4 => TypeClass::Float32,
            8 => TypeClass::Float64,
            9.. => TypeClass::FloatWide,
            _ => TypeClass::Other,
        }
    }
}

/// One function's source signature, reduced to classes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureTruth {
    pub name: String,
    #[serde(rename = "return")]
    pub returns: TypeClass,
    pub params: Vec<TypeClass>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub variadic: bool,
}

impl SignatureTruth {
    fn render(&self) -> String {
        render(self.params.iter().map(|class| class.tag()), self.variadic)
    }
}

fn render<'a>(params: impl Iterator<Item = &'a str>, variadic: bool) -> String {
    let mut parts: Vec<&str> = params.collect();
    if variadic {
        parts.push("...");
    }
    format!("({})", parts.join(", "))
}

/// Source signatures by function address, from DWARF.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TypeTruth(pub BTreeMap<u64, SignatureTruth>);

impl TypeTruth {
    /// Every DWARF subprogram with code (a `DW_AT_low_pc`), from an executable's embedded DWARF. Out-of-line
    /// instances of inline functions and other entries that take their prototype from another DIE
    /// (`DW_AT_abstract_origin`, `DW_AT_specification`) are left out and named in the returned notes, as are
    /// functions that share an address with an earlier one.
    pub fn from_dwarf(data: &[u8]) -> Result<(TypeTruth, Vec<String>), String> {
        let object = object::File::parse(data).map_err(|error| error.to_string())?;
        let endian = if object.is_little_endian() { RunTimeEndian::Little } else { RunTimeEndian::Big };
        let dwarf = Dwarf::load(|id| -> Result<EndianSlice<'_, RunTimeEndian>, String> {
            let data = match object.section_by_name(id.name()) {
                Some(section) => section.data().map_err(|error| format!("{}: {error}", id.name()))?,
                None => &[],
            };
            Ok(EndianSlice::new(data, endian))
        })?;
        let mut truth = TypeTruth::default();
        let mut notes = Vec::new();
        let mut units = dwarf.units();
        let mut dies = 0;
        while let Some(header) = units.next().map_err(|error| error.to_string())? {
            let unit = dwarf.unit(header).map_err(|error| error.to_string())?;
            let mut entries = unit.entries();
            // The subprogram being collected: its depth and address.
            let mut open: Option<(isize, u64)> = None;
            while let Some(entry) = entries.next_dfs().map_err(|error| error.to_string())? {
                dies += 1;
                if dies > MAX_DIES {
                    return Err(format!("more than {MAX_DIES} DWARF entries"));
                }
                let depth = entry.depth();
                if open.is_some_and(|(at, _)| depth <= at) {
                    open = None;
                }
                if let Some((at, address)) = open {
                    if depth == at + 1 {
                        let signature = truth.0.get_mut(&address).expect("opened with an entry");
                        match entry.tag() {
                            gimli::DW_TAG_formal_parameter => {
                                signature.params.push(class_of(&unit, entry.attr_value(gimli::DW_AT_type))?)
                            }
                            gimli::DW_TAG_unspecified_parameters => signature.variadic = true,
                            _ => {}
                        }
                    }
                    continue;
                }
                if entry.tag() != gimli::DW_TAG_subprogram {
                    continue;
                }
                let Some(low_pc) = entry.attr_value(gimli::DW_AT_low_pc) else { continue };
                let Some(address) = dwarf.attr_address(&unit, low_pc).map_err(|error| error.to_string())? else {
                    continue;
                };
                let name = match entry.attr_value(gimli::DW_AT_name) {
                    Some(value) => {
                        dwarf.attr_string(&unit, value).map_err(|error| error.to_string())?.to_string_lossy()
                    }
                    None => format!("{address:#x}").into(),
                };
                let name = name.into_owned();
                if entry.has_attr(gimli::DW_AT_abstract_origin) || entry.has_attr(gimli::DW_AT_specification) {
                    notes.push(format!("{name} at {address:#x}: its prototype is on another DIE; left out"));
                    continue;
                }
                if truth.0.contains_key(&address) {
                    notes.push(format!("{name} at {address:#x}: shares an address with another function; left out"));
                    continue;
                }
                let returns = class_of(&unit, entry.attr_value(gimli::DW_AT_type))?;
                truth.0.insert(address, SignatureTruth { name, returns, params: Vec::new(), variadic: false });
                open = Some((depth, address));
            }
        }
        Ok((truth, notes))
    }

    /// Parses `{ "0x<address>": {"name": .., "return": .., "params": [..], "variadic": true} }`.
    pub fn from_json(text: &str) -> Result<TypeTruth, serde_json::Error> {
        let raw: BTreeMap<String, SignatureTruth> = serde_json::from_str(text)?;
        let mut entries = BTreeMap::new();
        for (key, signature) in raw {
            entries.insert(parse_address_key(&key)?, signature);
        }
        Ok(TypeTruth(entries))
    }

    /// One function per line, in numeric address order, like [`crate::Truth::to_json`].
    pub fn to_json(&self) -> String {
        let lines: Vec<String> = self
            .0
            .iter()
            .map(|(address, signature)| {
                let value = serde_json::to_string(signature).expect("a signature serializes");
                format!("  \"{address:#x}\": {value}")
            })
            .collect();
        if lines.is_empty() { "{}\n".to_owned() } else { format!("{{\n{}\n}}\n", lines.join(",\n")) }
    }
}

type Unit<'a> = gimli::Unit<EndianSlice<'a, RunTimeEndian>>;

/// The class of the type a `DW_AT_type` names; no attribute is `void`.
fn class_of(
    unit: &Unit<'_>,
    reference: Option<AttributeValue<EndianSlice<'_, RunTimeEndian>>>,
) -> Result<TypeClass, String> {
    let mut reference = reference;
    for _ in 0..MAX_TYPE_DEPTH {
        let Some(value) = reference else { return Ok(TypeClass::Void) };
        let AttributeValue::UnitRef(offset) = value else { return Ok(TypeClass::Other) };
        let entry = entry(unit, offset)?;
        let size = entry.attr_value(gimli::DW_AT_byte_size).and_then(|value| value.udata_value());
        match entry.tag() {
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type => reference = entry.attr_value(gimli::DW_AT_type),
            gimli::DW_TAG_base_type => {
                let Some(size) = size else { return Ok(TypeClass::Other) };
                return Ok(match entry.attr_value(gimli::DW_AT_encoding) {
                    Some(AttributeValue::Encoding(gimli::DW_ATE_float)) => TypeClass::float(size),
                    Some(AttributeValue::Encoding(
                        gimli::DW_ATE_boolean
                        | gimli::DW_ATE_signed
                        | gimli::DW_ATE_unsigned
                        | gimli::DW_ATE_signed_char
                        | gimli::DW_ATE_unsigned_char
                        | gimli::DW_ATE_UTF,
                    )) => TypeClass::integer(size),
                    _ => TypeClass::Other,
                });
            }
            gimli::DW_TAG_enumeration_type => match size {
                Some(size) => return Ok(TypeClass::integer(size)),
                None => reference = entry.attr_value(gimli::DW_AT_type),
            },
            gimli::DW_TAG_pointer_type | gimli::DW_TAG_reference_type | gimli::DW_TAG_rvalue_reference_type => {
                let aggregate = pointee_is_aggregate(unit, entry.attr_value(gimli::DW_AT_type))?;
                return Ok(if aggregate { TypeClass::StructPointer } else { TypeClass::Pointer });
            }
            gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type => {
                return Ok(TypeClass::Struct);
            }
            _ => return Ok(TypeClass::Other),
        }
    }
    Ok(TypeClass::Other)
}

fn pointee_is_aggregate(
    unit: &Unit<'_>,
    reference: Option<AttributeValue<EndianSlice<'_, RunTimeEndian>>>,
) -> Result<bool, String> {
    let mut reference = reference;
    for _ in 0..MAX_TYPE_DEPTH {
        let Some(AttributeValue::UnitRef(offset)) = reference else { return Ok(false) };
        let entry = entry(unit, offset)?;
        match entry.tag() {
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type => reference = entry.attr_value(gimli::DW_AT_type),
            tag => {
                return Ok(matches!(
                    tag,
                    gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type
                ));
            }
        }
    }
    Ok(false)
}

fn entry<'a>(
    unit: &Unit<'a>,
    offset: UnitOffset,
) -> Result<gimli::DebuggingInformationEntry<EndianSlice<'a, RunTimeEndian>>, String> {
    unit.entry(offset).map_err(|error| format!("DWARF type at unit offset {:#x}: {error}", offset.0))
}

/// One recovered type: its class and the decompiler's own spelling, which the disagreements keep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedType {
    pub class: TypeClass,
    pub raw: String,
}

impl ProposedType {
    /// Classifies a decompiler type by its name and size. The structured result spells types the decompiler
    /// core's way (`int4`, `uint1`, `float8`, `xunknown8` for an unknown 8-byte value, `code()` for a function),
    /// with sizes in bytes, so any built-in name that is neither a pointer, a float nor `void` is an integer of
    /// its size. A name no built-in type has can only be a recovered struct; an array (`xunknown1 [16]`) is
    /// [`TypeClass::Other`].
    pub fn from_decompiler(name: &str, size: u32) -> ProposedType {
        let trimmed = name.trim();
        let class = if let Some(pointee) = trimmed.strip_suffix('*') {
            let pointee = pointee.trim().trim_end_matches('*').trim();
            let function = pointee.ends_with(')');
            let plain = pointee.is_empty() || function || builtin(pointee);
            if plain { TypeClass::Pointer } else { TypeClass::StructPointer }
        } else if trimmed.ends_with(']') {
            TypeClass::Other
        } else if trimmed == "void" || size == 0 {
            TypeClass::Void
        } else if matches!(trimmed, "float" | "double" | "longdouble") || numbered(trimmed, "float") {
            TypeClass::float(u64::from(size))
        } else if builtin(trimmed) {
            TypeClass::integer(u64::from(size))
        } else {
            TypeClass::Struct
        };
        ProposedType { class, raw: trimmed.to_owned() }
    }
}

/// A name of one of the decompiler's built-in types.
fn builtin(name: &str) -> bool {
    let name = name.strip_prefix("const ").unwrap_or(name);
    matches!(
        name,
        "void"
            | "undefined"
            | "bool"
            | "char"
            | "uchar"
            | "schar"
            | "sbyte"
            | "byte"
            | "short"
            | "ushort"
            | "word"
            | "sword"
            | "int"
            | "uint"
            | "dword"
            | "sdword"
            | "long"
            | "ulong"
            | "longlong"
            | "ulonglong"
            | "qword"
            | "sqword"
            | "float"
            | "double"
            | "longdouble"
            | "code"
            | "wchar_t"
            | "char16_t"
            | "char32_t"
    ) || ["undefined", "xunknown", "int", "uint", "float", "unkbyte", "unkint", "unkuint", "wchar"]
        .iter()
        .any(|prefix| numbered(name, prefix))
}

fn numbered(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// A function's recovered signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedSignature {
    pub returns: ProposedType,
    pub params: Vec<ProposedType>,
    pub variadic: bool,
}

impl ProposedSignature {
    fn render(&self) -> String {
        render(self.params.iter().map(|param| param.class.tag()), self.variadic)
    }
}

/// Decompiles each of `addresses` in the stripped `target` and keeps its recovered signature, or why there is
/// none. A decompilation that starts elsewhere (the address is inside a function discovery bounded differently)
/// describes another function, so it is an error rather than an answer.
pub fn decompiled_signatures(
    target: Binary,
    addresses: impl IntoIterator<Item = u64>,
) -> BTreeMap<u64, Result<ProposedSignature, String>> {
    decompiled_signature_batch(target, addresses).signatures
}

#[derive(Debug, Serialize)]
pub struct DecompileObservation {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub requested_address: u64,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub returned_address: Option<u64>,
    pub status: &'static str,
    pub elapsed_us: u64,
    pub c_bytes: usize,
    pub recovery_status: Option<rampage_decompiler::results::RecoveryStatus>,
    pub warning_count: Option<usize>,
    pub bad_data: Option<bool>,
    pub unimplemented: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct SignatureRecoveryBatch {
    pub signatures: BTreeMap<u64, Result<ProposedSignature, String>>,
    pub observations: Vec<DecompileObservation>,
    pub timing_boundary: &'static str,
}

pub fn decompiled_signature_batch(target: Binary, addresses: impl IntoIterator<Item = u64>) -> SignatureRecoveryBatch {
    let project = rampage_api::Project::new(target);
    let mut observations = Vec::new();
    let mut signatures = BTreeMap::new();
    for address in addresses {
        let started = std::time::Instant::now();
        let result = project.decompile(address);
        let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let mut observation = DecompileObservation {
            requested_address: address,
            returned_address: None,
            status: "error",
            elapsed_us,
            c_bytes: 0,
            recovery_status: None,
            warning_count: None,
            bad_data: None,
            unimplemented: None,
        };
        let signature = match result {
            Ok(result) => {
                observation.returned_address = Some(result.address);
                observation.c_bytes = result.code.len();
                observation.recovery_status = Some(result.recovery_status);
                if let Some(diagnostics) = &result.structure.diagnostics {
                    observation.warning_count = Some(diagnostics.warnings.len());
                    observation.bad_data = Some(diagnostics.bad_data);
                    observation.unimplemented = Some(diagnostics.unimplemented);
                }
                if result.address != address {
                    observation.status = "address_mismatch";
                    Err(format!("decompiled the function at {:#x} instead", result.address))
                } else {
                    observation.status = "returned";
                    let signature = &result.structure.signature;
                    let ty = |info: &rampage_decompiler::results::TypeInfo| {
                        ProposedType::from_decompiler(&info.name, info.size)
                    };
                    Ok(ProposedSignature {
                        returns: ty(&signature.return_type),
                        params: signature.parameters.iter().map(|param| ty(&param.data_type)).collect(),
                        variadic: signature.variadic,
                    })
                }
            }
            Err(error) => Err(error.to_string()),
        };
        observations.push(observation);
        signatures.insert(address, signature);
    }
    SignatureRecoveryBatch {
        signatures,
        observations,
        timing_boundary: "Around each Project::decompile call; Project construction excluded. \
            First call may include discovery/native initialization; subsequent calls share target caches. \
            In-process calls are not forcibly interruptible.",
    }
}

/// Which part of a signature a slice scores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeMetric {
    /// Per function: the recovered parameter count equals the declared one (varargs not counted).
    #[default]
    Params,
    /// Per function, value-returning as the positive class: a recovered value where the source returns void
    /// is spurious, a recovered void where it returns a value is missed.
    Return,
    /// Per declared parameter position: the recovered class at that position. A position past the recovered
    /// count is missed; a recovered position past the declared count is spurious.
    Classes,
}

impl TypeMetric {
    pub fn tag(self) -> &'static str {
        match self {
            TypeMetric::Params => "params",
            TypeMetric::Return => "return",
            TypeMetric::Classes => "classes",
        }
    }
}

/// Scores `proposals` against `truth` on one metric. A truth function with no proposal, or whose decompilation
/// failed, has every scored item missed. Proposals for addresses the truth lacks are ignored: the eval only
/// decompiles truth functions.
///
/// Unlike name identification, a type answer can be wrong without being useless, so the rates count a wrong
/// answer against both sides: precision is correct over everything answered (correct, wrong, spurious) and
/// recall correct over everything the truth holds (correct, wrong, missed). `disagreement_classes` counts each
/// kind of disagreement (`struct_pointer->pointer`, `fewer`, `value->void`), the flywheel's candidate list.
pub fn score_types(
    metric: TypeMetric,
    proposals: &BTreeMap<u64, Result<ProposedSignature, String>>,
    truth: &TypeTruth,
) -> Report {
    let mut tally = Tally::default();
    for (&address, declared) in &truth.0 {
        let proposed = proposals.get(&address).and_then(|proposal| proposal.as_ref().ok());
        match metric {
            TypeMetric::Params => {
                let truth = Some(format!("{}{}", declared.name, declared.render()));
                match proposed {
                    None => tally.add(address, None, truth, Outcome::Missed, "not_decompiled".to_owned()),
                    Some(proposed) if proposed.params.len() == declared.params.len() => tally.correct += 1,
                    Some(proposed) => {
                        let class = if proposed.params.len() < declared.params.len() { "fewer" } else { "more" };
                        let class = if declared.variadic { format!("variadic_{class}") } else { class.to_owned() };
                        tally.add(address, Some(proposed.render()), truth, Outcome::Wrong, class);
                    }
                }
            }
            TypeMetric::Return => {
                let returns = declared.returns != TypeClass::Void;
                let truth = Some(format!("{} returns {}", declared.name, declared.returns.tag()));
                let answer = proposed.map(|proposed| &proposed.returns);
                let label = |answer: &ProposedType| Some(format!("returns {} ({})", answer.class.tag(), answer.raw));
                match (returns, answer) {
                    (true, None) => tally.add(address, None, truth, Outcome::Missed, "not_decompiled".to_owned()),
                    (true, Some(answer)) if answer.class == TypeClass::Void => {
                        tally.add(address, label(answer), truth, Outcome::Missed, "value->void".to_owned())
                    }
                    (true, Some(_)) => tally.correct += 1,
                    (false, Some(answer)) if answer.class != TypeClass::Void => {
                        tally.add(address, label(answer), truth, Outcome::Spurious, "void->value".to_owned())
                    }
                    (false, _) => {}
                }
            }
            TypeMetric::Classes => {
                let positions = declared.params.len().max(proposed.map_or(0, |proposed| proposed.params.len()));
                for index in 0..positions {
                    let expected = declared.params.get(index);
                    let answer = proposed.and_then(|proposed| proposed.params.get(index));
                    let truth = expected.map(|class| format!("{} #{index} {}", declared.name, class.tag()));
                    let label = answer.map(|answer| format!("#{index} {} ({})", answer.class.tag(), answer.raw));
                    let class = |answer: &str| format!("{}->{answer}", expected.map_or("none", |class| class.tag()));
                    match (expected, answer) {
                        (Some(expected), Some(answer)) if *expected == answer.class => tally.correct += 1,
                        (Some(_), Some(answer)) => {
                            tally.add(address, label, truth, Outcome::Wrong, class(answer.class.tag()))
                        }
                        (Some(_), None) => {
                            let why = if proposed.is_some() { "none" } else { "not_decompiled" };
                            tally.add(address, label, truth, Outcome::Missed, class(why));
                        }
                        (None, Some(answer)) => {
                            tally.add(address, label, truth, Outcome::Spurious, class(answer.class.tag()))
                        }
                        (None, None) => {}
                    }
                }
            }
        }
    }
    tally.report()
}

#[derive(Default)]
struct Tally {
    correct: usize,
    wrong: usize,
    missed: usize,
    spurious: usize,
    disagreements: Vec<Disagreement>,
    classes: BTreeMap<String, usize>,
}

impl Tally {
    fn add(&mut self, address: u64, proposed: Option<String>, truth: Option<String>, outcome: Outcome, class: String) {
        match outcome {
            Outcome::Correct => unreachable!("only disagreements are added"),
            Outcome::Wrong => self.wrong += 1,
            Outcome::Missed => self.missed += 1,
            Outcome::Spurious => self.spurious += 1,
        }
        *self.classes.entry(class).or_default() += 1;
        self.disagreements.push(Disagreement { address, proposed, truth, outcome });
    }

    fn report(self) -> Report {
        Report {
            precision: ratio(self.correct, self.correct + self.wrong + self.spurious),
            recall: ratio(self.correct, self.correct + self.wrong + self.missed),
            correct: self.correct,
            wrong: self.wrong,
            missed: self.missed,
            spurious: self.spurious,
            disagreements: self.disagreements,
            tool_disagreements: Vec::new(),
            disagreement_classes: self.classes,
            omitted: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use TypeClass::*;

    fn declared(name: &str, returns: TypeClass, params: &[TypeClass], variadic: bool) -> SignatureTruth {
        SignatureTruth { name: name.to_owned(), returns, params: params.to_vec(), variadic }
    }

    fn proposed(returns: TypeClass, params: &[TypeClass]) -> Result<ProposedSignature, String> {
        let ty = |class: TypeClass| ProposedType { class, raw: class.tag().to_owned() };
        Ok(ProposedSignature { returns: ty(returns), params: params.iter().map(|&c| ty(c)).collect(), variadic: false })
    }

    fn truth() -> TypeTruth {
        TypeTruth(BTreeMap::from([
            (0x10, declared("add", Int32, &[Int32, Int32], false)),
            (0x20, declared("reset", Void, &[StructPointer], false)),
            (0x30, declared("sum", Int64, &[Int32], true)),
            (0x40, declared("lost", Float64, &[Float64], false)),
        ]))
    }

    fn proposals() -> BTreeMap<u64, Result<ProposedSignature, String>> {
        BTreeMap::from([
            (0x10, proposed(Int32, &[Int32, Int32])),
            (0x20, proposed(Int64, &[Pointer])),
            (0x30, proposed(Void, &[Int32, Int64, Int64])),
            (0x40, Err("decompiler failed".to_owned())),
            (0x50, proposed(Int32, &[Int32])),
        ])
    }

    fn outcomes(report: &Report) -> Vec<(u64, Outcome)> {
        report.disagreements.iter().map(|entry| (entry.address, entry.outcome)).collect()
    }

    #[test]
    fn parameter_counts_are_scored_per_function() {
        let report = score_types(TypeMetric::Params, &proposals(), &truth());
        assert_eq!((report.correct, report.wrong, report.missed, report.spurious), (2, 1, 1, 0));
        assert_eq!(outcomes(&report), [(0x30, Outcome::Wrong), (0x40, Outcome::Missed)]);
        assert_eq!(report.disagreements[0].truth.as_deref(), Some("sum(int32, ...)"));
        assert_eq!(report.disagreements[0].proposed.as_deref(), Some("(int32, int64, int64)"));
        assert_eq!(
            report.disagreement_classes,
            BTreeMap::from([("not_decompiled".into(), 1), ("variadic_more".into(), 1)])
        );
        assert!((report.precision - 2.0 / 3.0).abs() < 1e-12);
        assert!((report.recall - 0.5).abs() < 1e-12);
    }

    #[test]
    fn return_values_are_the_positive_class() {
        let report = score_types(TypeMetric::Return, &proposals(), &truth());
        assert_eq!((report.correct, report.wrong, report.missed, report.spurious), (1, 0, 2, 1));
        assert_eq!(outcomes(&report), [(0x20, Outcome::Spurious), (0x30, Outcome::Missed), (0x40, Outcome::Missed)]);
        assert_eq!(report.disagreements[0].truth.as_deref(), Some("reset returns void"));
        let classes =
            BTreeMap::from([("not_decompiled".into(), 1), ("value->void".into(), 1), ("void->value".into(), 1)]);
        assert_eq!(report.disagreement_classes, classes);
        assert!((report.precision - 0.5).abs() < 1e-12);
        assert!((report.recall - 1.0 / 3.0).abs() < 1e-12);
    }

    #[test]
    fn parameter_classes_are_scored_per_position() {
        let report = score_types(TypeMetric::Classes, &proposals(), &truth());
        assert_eq!((report.correct, report.wrong, report.missed, report.spurious), (3, 1, 1, 2));
        assert_eq!(
            outcomes(&report),
            [(0x20, Outcome::Wrong), (0x30, Outcome::Spurious), (0x30, Outcome::Spurious), (0x40, Outcome::Missed)]
        );
        assert_eq!(report.disagreements[0].truth.as_deref(), Some("reset #0 struct_pointer"));
        assert_eq!(report.disagreements[0].proposed.as_deref(), Some("#0 pointer (pointer)"));
        let classes = BTreeMap::from([
            ("float64->not_decompiled".into(), 1),
            ("none->int64".into(), 2),
            ("struct_pointer->pointer".into(), 1),
        ]);
        assert_eq!(report.disagreement_classes, classes);
        assert!((report.precision - 3.0 / 6.0).abs() < 1e-12);
        assert!((report.recall - 3.0 / 5.0).abs() < 1e-12);
    }

    #[test]
    fn a_shorter_recovery_misses_the_trailing_positions() {
        let truth = TypeTruth(BTreeMap::from([(0x10, declared("f", Void, &[Int32, Pointer], false))]));
        let report = score_types(TypeMetric::Classes, &BTreeMap::from([(0x10, proposed(Void, &[Int32]))]), &truth);
        assert_eq!((report.correct, report.missed), (1, 1));
        assert_eq!(report.disagreement_classes, BTreeMap::from([("pointer->none".into(), 1)]));
        assert!(score_types(TypeMetric::Return, &BTreeMap::new(), &truth).disagreements.is_empty());
    }

    #[test]
    fn decompiler_types_classify_by_spelling_and_size() {
        let class = |name: &str, size: u32| ProposedType::from_decompiler(name, size).class;
        assert_eq!(class("void", 0), Void);
        assert_eq!(class("undefined8", 8), Int64);
        assert_eq!(class("undefined", 1), Int8);
        assert_eq!(class("bool", 1), Int8);
        assert_eq!(class("ushort", 2), Int16);
        assert_eq!(class("int", 4), Int32);
        assert_eq!(class("float", 4), Float32);
        assert_eq!(class("double", 8), Float64);
        assert_eq!(class("float10", 10), FloatWide);
        assert_eq!(class("char *", 8), Pointer);
        assert_eq!(class("undefined8 **", 8), Pointer);
        assert_eq!(class("code *", 8), Pointer);
        assert_eq!(class("code() *", 8), Pointer);
        assert_eq!(class("int8", 8), Int64);
        assert_eq!(class("uint1", 1), Int8);
        assert_eq!(class("float8", 8), Float64);
        assert_eq!(class("xunknown8", 8), Int64);
        assert_eq!(class("xunknown4 *", 8), Pointer);
        assert_eq!(class("xunknown1 [16]", 16), Other);
        assert_eq!(class("point *", 8), StructPointer);
        assert_eq!(class("point", 8), Struct);
        assert_eq!(class("undefined3", 3), Other);
    }

    #[test]
    fn truth_round_trips_through_hex_keyed_json() {
        let original = truth();
        let json = original.to_json();
        assert!(
            json.contains("\"0x30\": {\"name\":\"sum\",\"return\":\"int64\",\"params\":[\"int32\"],\"variadic\":true}")
        );
        assert!(json.contains("\"0x10\": {\"name\":\"add\",\"return\":\"int32\",\"params\":[\"int32\",\"int32\"]}"));
        assert_eq!(TypeTruth::from_json(&json).unwrap(), original);
        assert!(TypeTruth::from_json("{\"16\": {\"name\":\"f\",\"return\":\"void\",\"params\":[]}}").is_err());
        assert!(TypeTruth::from_json("{\"0x10\": {\"name\":\"f\",\"return\":\"word\",\"params\":[]}}").is_err());
    }

    #[test]
    fn malformed_objects_are_errors_not_panics() {
        assert!(TypeTruth::from_dwarf(b"").is_err());
        assert!(TypeTruth::from_dwarf(b"\x7fELF\x02\x01\x01").is_err());
    }
}
