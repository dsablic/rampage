//! `string_decoding`: candidate string-decoding routines found statically -- functions with a short loop that
//! loads a byte, transforms it (XOR, rotate, or byte ADD/SUB) and stores a byte, ranked by how many call sites
//! pass them pointers to non-printable or high-entropy data blobs. Nothing is emulated or executed: a candidate is
//! a loop shape plus its call sites, not a decoded string.

use std::collections::BTreeMap;

use rampage_analysis::discover::{DiscoveredFunction, XrefKind};
use rampage_arch::{Arch, Disassembler, Flow, Insn};
use rampage_loaders::shannon_entropy;
use serde_json::{Value, json};

use super::registry::{Workflow, WorkflowOptions, report_options, report_schema};
use super::{Confidence, Finding, ReportLimits, Section, Tracer, WorkflowReport};
use crate::tools::Group;
use crate::{ApiError, Project, XrefQuery};

/// Instructions in a loop body (from a backward branch's target to the branch) for it to count as a byte loop.
/// Decoding loops are tight; larger loops are left out rather than guessed about.
const MAX_LOOP_INSTRUCTIONS: usize = 64;
/// Functions with more instructions are not scanned for loops.
const MAX_FUNCTION_INSTRUCTIONS: usize = 4_000;
/// Instructions decoded over the whole scan before it stops.
const MAX_SCANNED_INSTRUCTIONS: usize = 2_000_000;
/// Direct call sites read per candidate.
const MAX_CALL_SITES: usize = 200;
/// Candidates whose call sites are traced, XOR and rotate loops first.
const MAX_TRACED_CANDIDATES: usize = 64;
/// Instructions decoded over all call-site tracing before it stops.
const MAX_TRACED_INSTRUCTIONS: usize = 500_000;
/// Instructions before a call searched for data pointers passed as arguments.
const ARGUMENT_WINDOW: usize = 8;
/// Blobs kept per candidate.
const MAX_BLOBS: usize = 32;
/// Bytes read from a blob for its length estimate and entropy.
const MAX_BLOB_BYTES: usize = 256;
/// Blobs shorter than this are too short to judge.
const MIN_BLOB_BYTES: usize = 4;
/// Share of non-printable bytes above which a blob does not read as text.
const NON_PRINTABLE_SHARE: f64 = 0.25;
/// Entropy (bits per byte) and length from which a printable blob still reads as encoded (base64-like).
const HIGH_ENTROPY: f64 = 5.5;
const HIGH_ENTROPY_MIN_BYTES: usize = 48;
/// Loop instructions quoted per candidate.
const QUOTED_INSTRUCTIONS: usize = 4;
/// Functions suggested for decompilation in next steps.
const SUGGESTED_FUNCTIONS: usize = 3;

const X86_BYTE_REGISTERS: [&str; 20] = [
    "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil", "bpl", "spl", "r8b", "r9b", "r10b", "r11b", "r12b",
    "r13b", "r14b", "r15b",
];
/// Byte loads, byte stores, XORs and rotates on AArch64, ARM, MIPS, PowerPC, RISC-V, SPARC and s390x, by
/// mnemonic (x86 and m68k carry operand sizes instead).
const BYTE_LOADS: [&str; 19] = [
    "ldrb", "ldrsb", "ldurb", "ldursb", "lb", "lbu", "lbz", "lbzx", "lbzu", "lbzux", "ldub", "ldsb", "lduba", "ldsba",
    "llc", "llgc", "lgb", "ic", "icy",
];
const BYTE_STORES: [&str; 10] = ["strb", "sturb", "sb", "stb", "stbx", "stbu", "stbux", "stba", "stc", "stcy"];
const XORS: [&str; 17] = [
    "eor", "eors", "xor", "xori", "xoris", "xorcc", "xnor", "xnorcc", "x", "xr", "xg", "xgr", "xrk", "xgrk", "xy",
    "xilf", "xihf",
];
const ROTATES: [&str; 8] = ["ror", "rors", "rol", "rori", "rotlwi", "rotrwi", "rll", "rllg"];
/// s390x XORs of an immediate into a byte of memory, which load, transform and store at once.
const BYTE_XORS_IN_MEMORY: [&str; 2] = ["xi", "xiy"];
/// ARM condition codes, which A32 and T32 (in IT blocks) append to a mnemonic.
const ARM_CONDITIONS: [&str; 16] =
    ["eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le"];
/// The architectures whose byte operations are recognized, for the report's limitations.
const RECOGNIZED_ARCHITECTURES: &str = "x86, AArch64, 32-bit ARM, MIPS, PowerPC, RISC-V, SPARC, s390x and m68k";

/// What one loop instruction does to bytes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ByteOps {
    load: bool,
    store: bool,
    xor: bool,
    rotate: bool,
    add_sub: bool,
}

impl ByteOps {
    fn merge(&mut self, other: Self) {
        self.load |= other.load;
        self.store |= other.store;
        self.xor |= other.xor;
        self.rotate |= other.rotate;
        self.add_sub |= other.add_sub;
    }

    fn transforms(self) -> bool {
        self.xor || self.rotate || self.add_sub
    }

    /// The transforms seen, as words for a report.
    fn transform_names(self) -> Vec<&'static str> {
        [(self.xor, "XOR"), (self.rotate, "rotate"), (self.add_sub, "byte ADD/SUB")]
            .into_iter()
            .filter_map(|(seen, name)| seen.then_some(name))
            .collect()
    }
}

/// Splits assembly text into its mnemonic and operands, keeping commas inside brackets and braces.
fn parse(text: &str) -> (String, Vec<String>) {
    let text = text.trim();
    let (mnemonic, rest) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    let mut operands = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for c in rest.chars() {
        match c {
            '[' | '{' | '(' => depth += 1,
            ']' | '}' | ')' => depth -= 1,
            ',' if depth == 0 => {
                operands.push(current.trim().to_owned());
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    if !current.trim().is_empty() {
        operands.push(current.trim().to_owned());
    }
    (mnemonic.to_ascii_lowercase(), operands)
}

/// What `text`, one instruction on `arch`, does to bytes.
fn classify(arch: Arch, text: &str) -> ByteOps {
    let (mnemonic, operands) = parse(text);
    match arch {
        Arch::X86 | Arch::X86_64 => return classify_x86(&mnemonic, &operands),
        Arch::M68k => return classify_m68k(&mnemonic, &operands),
        _ => {}
    }
    let base = mnemonic.split('.').next().unwrap_or(&mnemonic);
    // A conditional ARM form (`ldrbne`, `eorsne`) is its base mnemonic plus a condition; the suffix is only taken
    // off when what remains is a known mnemonic, so `bls` or `teq` never read as one.
    let unconditional =
        (arch == Arch::Arm).then(|| ARM_CONDITIONS.iter().find_map(|condition| base.strip_suffix(condition))).flatten();
    let is = |table: &[&str]| table.contains(&base) || unconditional.is_some_and(|stripped| table.contains(&stripped));
    if is(&BYTE_XORS_IN_MEMORY) && arch == Arch::S390x {
        return ByteOps { load: true, store: true, xor: true, ..ByteOps::default() };
    }
    ByteOps {
        load: is(&BYTE_LOADS),
        store: is(&BYTE_STORES),
        xor: is(&XORS) && !same_operands(&operands),
        rotate: is(&ROTATES),
        add_sub: false,
    }
}

/// m68k gives the operand size as a mnemonic suffix (`move.b`), and its operands run source first.
fn classify_m68k(mnemonic: &str, operands: &[String]) -> ByteOps {
    let (base, size) = mnemonic.split_once('.').unwrap_or((mnemonic, ""));
    let byte = size == "b";
    let memory = |operand: Option<&String>| operand.is_some_and(|operand| operand.contains('('));
    let (source_memory, destination_memory) = (memory(operands.first()), memory(operands.last()));
    let mut ops = ByteOps::default();
    match base {
        "move" => {
            ops.load = byte && source_memory;
            ops.store = byte && destination_memory;
        }
        "eor" | "eori" | "add" | "addi" | "addq" | "sub" | "subi" | "subq" => {
            // A memory destination is read, transformed and written back.
            ops.load = byte && (source_memory || destination_memory);
            ops.store = byte && destination_memory;
            ops.xor = base.starts_with("eor") && !same_operands(operands);
            ops.add_sub = byte && !base.starts_with("eor");
        }
        "rol" | "ror" | "roxl" | "roxr" => ops.rotate = true,
        _ => {}
    }
    ops
}

/// x86 has no byte-specific mnemonics: an operand's size comes from a `byte ptr` or an 8-bit register.
fn classify_x86(mnemonic: &str, operands: &[String]) -> ByteOps {
    let memory = |operand: &String| operand.contains('[');
    let byte_register = |operand: &String| X86_BYTE_REGISTERS.contains(&operand.as_str());
    let sized = operands.iter().any(|operand| operand.starts_with("byte ptr") || byte_register(operand));
    let first_memory = operands.first().is_some_and(memory);
    let later_memory = operands.iter().skip(1).any(memory);
    let mut ops = ByteOps::default();
    match mnemonic {
        "mov" => {
            ops.store = sized && first_memory;
            ops.load = sized && later_memory;
        }
        "movzx" | "movsx" => ops.load = operands.iter().skip(1).any(|operand| operand.starts_with("byte ptr")),
        "xor" | "add" | "sub" | "adc" | "sbb" | "rol" | "ror" => {
            // A memory destination is read, transformed and written back.
            ops.load = sized && (first_memory || later_memory);
            ops.store = sized && first_memory;
            ops.xor = mnemonic == "xor" && !same_operands(operands);
            ops.rotate = matches!(mnemonic, "rol" | "ror");
            ops.add_sub = sized && matches!(mnemonic, "add" | "sub" | "adc" | "sbb");
        }
        _ => {}
    }
    ops
}

/// Whether an instruction names one register twice (`xor eax, eax`, `eor w0, w0, w0`), which zeroes or copies
/// rather than mixes data.
fn same_operands(operands: &[String]) -> bool {
    (operands.len() >= 2 && operands.iter().all(|operand| *operand == operands[0]))
        || (operands.len() == 3 && operands[1] == operands[2])
}

/// A function holding a byte loop.
struct Candidate {
    address: u64,
    name: String,
    loop_start: u64,
    ops: ByteOps,
    /// `address: text` of the loop's byte-moving and transforming instructions.
    quoted: Vec<String>,
    /// Whether its call sites were looked up at all.
    traced: bool,
    call_sites: Vec<CallSite>,
    /// Whether some call sites were left unread.
    call_sites_cut: bool,
    blobs: BTreeMap<u64, Blob>,
}

impl Candidate {
    /// XOR or rotate in the loop plus at least one encoded-looking argument is the shape worth a Medium; anything
    /// less (byte ADD/SUB alone, or no such argument) is common in ordinary string handling.
    fn confidence(&self) -> Confidence {
        if (self.ops.xor || self.ops.rotate) && !self.blobs.is_empty() { Confidence::Medium } else { Confidence::Low }
    }
}

struct CallSite {
    at: u64,
    caller: Option<(u64, String)>,
    blobs: Vec<u64>,
    /// Why the arguments were not read, when they were not.
    unread: Option<&'static str>,
}

/// What call-site tracing left out, for the report's limitations.
#[derive(Default)]
struct Tracing {
    decoded: usize,
    untraced_candidates: usize,
    unread_sites: usize,
}

#[derive(Clone)]
struct Blob {
    length: usize,
    /// Whether the length ran into `MAX_BLOB_BYTES` rather than a NUL, the segment end or the next referenced
    /// address.
    capped: bool,
    entropy: f64,
    non_printable: f64,
    preview: String,
    /// Call sites passing it.
    passed_from: Vec<u64>,
}

impl Blob {
    fn reads_as_encoded(&self) -> bool {
        self.non_printable > NON_PRINTABLE_SHARE
            || self.length >= HIGH_ENTROPY_MIN_BYTES && self.entropy >= HIGH_ENTROPY
    }
}

/// Decodes the instructions of `function`'s blocks, in address order, with each one's bytes.
fn function_instructions<'b>(
    project: &'b Project,
    decoder: &mut dyn Disassembler,
    function: &DiscoveredFunction,
) -> Vec<(Insn, &'b [u8])> {
    let mut instructions = Vec::with_capacity(function.instruction_count);
    for block in &function.blocks {
        instructions.extend(block_instructions(project, decoder, block.start, block.end));
    }
    instructions.sort_by_key(|(insn, _)| insn.address);
    instructions.dedup_by_key(|(insn, _)| insn.address);
    instructions
}

/// Decodes from `start` up to (not including) `end`.
fn block_instructions<'b>(
    project: &'b Project,
    decoder: &mut dyn Disassembler,
    start: u64,
    end: u64,
) -> Vec<(Insn, &'b [u8])> {
    let binary = &project.binary;
    let Some(code) = binary.read_to_segment_end(start) else { return Vec::new() };
    let limit = usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX).min(code.len());
    decoder.reset();
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < limit {
        let address = start + offset as u64;
        let insn = decoder.decode_with_memory(&code[offset..], address, &|at, size| binary.read_pointer(at, size));
        let length = usize::from(insn.len.max(1));
        instructions.push((insn, &code[offset..(offset + length).min(code.len())]));
        offset += length;
    }
    instructions
}

pub struct StringDecoding;

impl Workflow for StringDecoding {
    fn name(&self) -> &'static str {
        "string_decoding"
    }

    fn summary(&self) -> &'static str {
        "Candidate string-decoding loops, their call sites and the encoded-looking data passed to them"
    }

    fn description(&self) -> &'static str {
        "Find candidate string-decoding routines statically: functions with a short loop that loads, transforms \
         (XOR, rotate, byte ADD/SUB) and stores bytes, their direct call sites, and the non-printable or \
         high-entropy data blobs passed to them (address, length estimate, entropy). Nothing is emulated or \
         executed; candidates are loop shapes with medium or low confidence."
    }

    fn group(&self) -> Group {
        Group::Core
    }

    fn input_schema(&self) -> Value {
        report_schema()
    }

    fn options(&self, input: Value) -> Result<WorkflowOptions, String> {
        report_options(input)
    }

    fn run(&self, project: &Project, options: &WorkflowOptions) -> Result<WorkflowReport, ApiError> {
        project.string_decoding(options.limits)
    }
}

impl Project {
    /// Candidate string-decoding routines: byte loops that load, transform and store bytes, with the call sites
    /// and encoded-looking data blobs that reach them. Static and bounded: nothing is emulated or executed.
    pub fn string_decoding(&self, limits: ReportLimits) -> Result<WorkflowReport, ApiError> {
        if self.binary.is_sleigh_raw() {
            let _decoder = crate::decoder::project_decoder(self)?;
            return Err(ApiError::Unavailable(
                "string-decoding loop classification is not supported by the selected Sleigh Project profile".into(),
            ));
        }
        let mut report = WorkflowReport::new("string_decoding", self);
        let mut tracer = Tracer::new(self, &mut report);
        let mut candidates = Vec::new();
        let mut scan_stopped = false;
        let mut skipped_large = 0;
        let mut tracing = Tracing::default();
        let decoder = self.binary.decoder();
        if let Err(error) = &decoder {
            report.limitation(format!("Instructions cannot be decoded ({error}); no loops were looked for."));
        }
        if let (Ok(analysis), Ok(mut decoder)) = (self.analysis(), decoder) {
            if self.binary.arch == Arch::Arm {
                decoder.set_code_modes(&analysis.program.code_modes);
            }
            let mut scanned = 0;
            for function in &analysis.program.functions {
                if function.instruction_count > MAX_FUNCTION_INSTRUCTIONS {
                    skipped_large += 1;
                    continue;
                }
                if scanned >= MAX_SCANNED_INSTRUCTIONS {
                    scan_stopped = true;
                    break;
                }
                let instructions = function_instructions(self, decoder.as_mut(), function);
                scanned += instructions.len();
                if let Some(candidate) = self.byte_loop(decoder.as_mut(), function, &instructions) {
                    candidates.push(candidate);
                }
            }
            candidates.sort_by_key(|candidate| (!(candidate.ops.xor || candidate.ops.rotate), candidate.address));
            tracing = self.trace_call_sites(decoder.as_mut(), &mut candidates, &analysis.program.xrefs);
        }
        candidates.sort_by(|a, b| {
            b.confidence()
                .cmp(&a.confidence())
                .then(b.blobs.len().cmp(&a.blobs.len()))
                .then(b.call_sites.len().cmp(&a.call_sites.len()))
                .then(a.address.cmp(&b.address))
        });

        let mut routines = Section::new("Candidate decoding routines", limits);
        let mut sites = Section::new("Call sites", limits);
        let mut blobs = Section::new("Referenced data blobs", limits);
        for candidate in &candidates {
            let transforms = candidate.ops.transform_names().join(", ");
            let mut evidence = vec![format!(
                "loop at {:#x} loads a byte, applies {transforms} and stores a byte",
                candidate.loop_start
            )];
            evidence.extend(candidate.quoted.iter().cloned());
            let site_count = if !candidate.traced {
                "call sites not traced".to_owned()
            } else if candidate.call_sites_cut {
                format!("at least {} direct call sites (read up to {MAX_CALL_SITES})", candidate.call_sites.len())
            } else {
                format!("{} direct call sites", candidate.call_sites.len())
            };
            evidence.push(site_count.clone());
            routines.push(
                Finding::new(
                    "disassemble",
                    candidate.confidence(),
                    format!(
                        "`{}` has a byte loop applying {transforms}; {site_count}, {} passing non-printable or \
                         high-entropy data",
                        candidate.name,
                        candidate.call_sites.iter().filter(|site| !site.blobs.is_empty()).count()
                    ),
                )
                .at(candidate.address)
                .evidence(evidence),
            );

            let callers = tracer.users(&[candidate.address]);
            tracer.record(&callers, &format!("calls candidate decoding routine `{}`", candidate.name));
            for site in &candidate.call_sites {
                let caller = site.caller.as_ref().map_or_else(
                    || "code outside any function".to_owned(),
                    |(address, name)| format!("`{name}` ({address:#x})"),
                );
                let mut evidence = vec![format!("direct call at {:#x} from {caller}", site.at)];
                evidence.extend(site.blobs.iter().map(|blob| format!("passes the data blob at {blob:#x}")));
                if let Some(unread) = site.unread {
                    evidence.push(unread.to_owned());
                } else if site.blobs.is_empty() {
                    evidence.push(format!(
                        "no data pointer to a non-printable or high-entropy blob in the {ARGUMENT_WINDOW} \
                         instructions before the call"
                    ));
                }
                sites.push(
                    Finding::new("xrefs", Confidence::High, format!("call to `{}` at {:#x}", candidate.name, site.at))
                        .at(site.at)
                        .evidence(evidence),
                );
            }
            for (&address, blob) in &candidate.blobs {
                let referenced = tracer.users(&[address]);
                let size = if blob.capped {
                    format!("at least {} bytes (read up to {MAX_BLOB_BYTES})", blob.length)
                } else {
                    format!("about {} bytes", blob.length)
                };
                let mut evidence = vec![
                    format!("{size}, to the first NUL, the next referenced address or the segment end"),
                    format!("entropy {:.2} bits/byte, {:.0}% non-printable", blob.entropy, blob.non_printable * 100.0),
                    format!("leading bytes {}", blob.preview),
                ];
                evidence.extend(blob.passed_from.iter().map(|at| format!("passed to `{}` at {at:#x}", candidate.name)));
                evidence.extend(referenced.evidence());
                blobs.push(
                    Finding::new(
                        "xrefs",
                        candidate.confidence(),
                        format!("possibly encoded data at {address:#x} passed to `{}`", candidate.name),
                    )
                    .at(address)
                    .evidence(evidence),
                );
                tracer.record(&referenced, &format!("references the data blob at {address:#x}"));
            }
        }
        let (functions, ranked) = tracer.finish(
            &mut report,
            "Functions calling candidates or referencing their blobs",
            "string-decoding evidence",
            limits,
        );

        report.summary.push(if candidates.is_empty() {
            "No byte loop that loads, transforms and stores bytes was found.".to_owned()
        } else {
            let medium = candidates.iter().filter(|candidate| candidate.confidence() == Confidence::Medium).count();
            format!(
                "{} candidate decoding routines ({medium} with XOR or rotate and an encoded-looking argument), {} \
                 direct call sites and {} referenced data blobs; candidates are loop shapes, not confirmed decoders.",
                routines.total, sites.total, blobs.total
            )
        });
        for candidate in candidates.iter().take(SUGGESTED_FUNCTIONS) {
            report.step(
                "decompile",
                json!({ "at": format!("{:#x}", candidate.address) }),
                format!("`{}` is a candidate decoding routine; read what its loop does to each byte.", candidate.name),
            );
        }
        if let Some(candidate) = candidates.first() {
            report.step(
                "xrefs",
                json!({ "to": format!("{:#x}", candidate.address) }),
                format!("List every reference to `{}`, including indirect ones the call sites miss.", candidate.name),
            );
        }
        for (address, name) in ranked.iter().take(SUGGESTED_FUNCTIONS) {
            report.step(
                "decompile",
                json!({ "at": format!("{address:#x}") }),
                format!("`{name}` calls a candidate or references its data; read how the result is used."),
            );
        }
        report.sections.extend([routines, sites, blobs, functions]);

        if scan_stopped {
            report.limitation(format!(
                "The loop scan stopped after {MAX_SCANNED_INSTRUCTIONS} instructions; later functions were not \
                 looked at."
            ));
        }
        if skipped_large > 0 {
            report.limitation(format!(
                "{skipped_large} functions over {MAX_FUNCTION_INSTRUCTIONS} instructions were not scanned for loops."
            ));
        }
        if tracing.untraced_candidates > 0 {
            report.limitation(format!(
                "Call sites were traced for the first {MAX_TRACED_CANDIDATES} candidates only (XOR and rotate loops \
                 first); {} candidates were not traced and stay at low confidence.",
                tracing.untraced_candidates
            ));
        }
        if tracing.unread_sites > 0 {
            report.limitation(format!(
                "Call-site tracing stopped after decoding {MAX_TRACED_INSTRUCTIONS} instructions; the arguments of {} \
                 call sites were not read.",
                tracing.unread_sites
            ));
        }
        report.limitation(format!(
            "Loops are found from backward branches within one function, at most {MAX_LOOP_INSTRUCTIONS} \
             instructions long, and read by mnemonic: vectorized, table-driven, multi-byte or unrolled-without-branch \
             decoders, decoders split across functions, and inlined decoders without a call site are missed. Byte \
             operations are recognized on {RECOGNIZED_ARCHITECTURES}; byte ADD/SUB only on x86 and m68k, where \
             operand sizes are visible."
        ));
        report.limitation(format!(
            "Arguments are data pointers in the {ARGUMENT_WINDOW} instructions before a direct call; pointers built \
             at run time, passed through the stack or through other functions, and indirect calls are not followed. \
             Blob lengths are estimates."
        ));
        report.limitation(
            "Nothing is emulated or executed: a candidate is a loop shape that byte-wise copying, case conversion, \
             checksums and ciphers also have, and no string is decoded. Absence of evidence is not evidence of \
             absence.",
        );
        Ok(report)
    }

    /// The first loop in `function` that loads, transforms and stores bytes.
    fn byte_loop(
        &self,
        decoder: &mut dyn Disassembler,
        function: &DiscoveredFunction,
        instructions: &[(Insn, &[u8])],
    ) -> Option<Candidate> {
        // Each instruction is formatted at most once, however many loops it lies in, so formatting costs no more
        // than the decoding already counted against MAX_SCANNED_INSTRUCTIONS. The text is kept for quoting only
        // when the instruction does something to bytes.
        let mut classified: Vec<Option<(ByteOps, Option<String>)>> = vec![None; instructions.len()];
        for (insn, _) in instructions {
            let (Flow::ConditionalJump(target) | Flow::Jump(target)) = insn.flow else { continue };
            if target > insn.address || !function.contains(target) {
                continue;
            }
            let first = instructions.partition_point(|(other, _)| other.address < target);
            let last = instructions.partition_point(|(other, _)| other.address <= insn.address);
            if last - first > MAX_LOOP_INSTRUCTIONS {
                continue;
            }
            let mut ops = ByteOps::default();
            let mut quoted = Vec::new();
            for index in first..last {
                let (other, bytes) = &instructions[index];
                let (found, text) = classified[index].get_or_insert_with(|| {
                    let text = decoder.format(bytes, other.address);
                    let found = classify(self.binary.arch, &text);
                    (found, (found != ByteOps::default()).then_some(text))
                });
                if let Some(text) = text
                    && quoted.len() < QUOTED_INSTRUCTIONS
                {
                    quoted.push(format!("{:#x}: {text}", other.address));
                }
                ops.merge(*found);
            }
            if ops.load && ops.store && ops.transforms() {
                return Some(Candidate {
                    address: function.address,
                    name: self.function_name(function.address),
                    loop_start: target,
                    ops,
                    quoted,
                    traced: false,
                    call_sites: Vec::new(),
                    call_sites_cut: false,
                    blobs: BTreeMap::new(),
                });
            }
        }
        None
    }

    /// Fills the direct call sites of the first `MAX_TRACED_CANDIDATES` candidates and the encoded-looking data
    /// blobs their arguments point at. Each caller block is decoded once, up to its last traced call, and at most
    /// `MAX_TRACED_INSTRUCTIONS` instructions are decoded in all.
    fn trace_call_sites(
        &self,
        decoder: &mut dyn Disassembler,
        candidates: &mut [Candidate],
        xrefs: &[rampage_analysis::discover::Xref],
    ) -> Tracing {
        let mut tracing = Tracing::default();
        // (candidate index, call address, caller, start of the caller's block holding the call)
        let mut sites = Vec::new();
        // Checked once for every call site below, not once per lookup.
        let analysis = self.analysis().ok();
        for (index, candidate) in candidates.iter_mut().enumerate() {
            if index >= MAX_TRACED_CANDIDATES {
                tracing.untraced_candidates += 1;
                continue;
            }
            let Ok(page) = self.xrefs(XrefQuery::To(candidate.address), None, Some(MAX_CALL_SITES)) else { continue };
            candidate.traced = true;
            candidate.call_sites_cut = page.total > page.items.len();
            for row in page.items.iter().filter(|row| row.kind == XrefKind::Call) {
                let caller = analysis.and_then(|analysis| analysis.function_containing(row.from));
                let block = caller.and_then(|caller| block_start(analysis?, caller, row.from));
                sites.push((index, row.from, caller, block));
            }
        }

        let mut by_block: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for (site, &(.., block)) in sites.iter().enumerate() {
            if let Some(block) = block {
                by_block.entry(block).or_default().push(site);
            }
        }
        // In an image based at zero, small constants (lengths, keys) would read as addresses.
        let immediates_are_addresses = self.binary.segments.iter().all(|segment| segment.address > 0);
        let mut arguments: Vec<Option<Vec<u64>>> = vec![None; sites.len()];
        for (&start, members) in &by_block {
            if tracing.decoded >= MAX_TRACED_INSTRUCTIONS {
                tracing.unread_sites += members.len();
                continue;
            }
            let end = members.iter().map(|&site| sites[site].1).max().unwrap_or(start);
            let instructions = block_instructions(self, decoder, start, end);
            tracing.decoded += instructions.len();
            for &site in members {
                let before = instructions.partition_point(|(insn, _)| insn.address < sites[site].1);
                let window = &instructions[before.saturating_sub(ARGUMENT_WINDOW)..before];
                let pointers = window
                    .iter()
                    .filter_map(|(insn, _)| insn.data_ref.or(insn.immediate.filter(|_| immediates_are_addresses)));
                arguments[site] = Some(pointers.collect());
            }
        }

        for ((index, at, caller, block), pointers) in sites.into_iter().zip(arguments) {
            let candidate = &mut candidates[index];
            let unread = match (block, &pointers) {
                (None, _) => {
                    Some("the call lies outside the caller's discovered blocks, so its arguments were not read")
                }
                (Some(_), None) => Some("its arguments were not read: call-site tracing ran out of its decode budget"),
                (Some(_), Some(_)) => None,
            };
            let mut site =
                CallSite { at, caller: caller.map(|at| (at, self.function_name(at))), blobs: vec![], unread };
            for address in pointers.unwrap_or_default() {
                if let Some(blob) = candidate.blobs.get_mut(&address) {
                    site.blobs.push(address);
                    blob.passed_from.push(at);
                    continue;
                }
                if candidate.blobs.len() >= MAX_BLOBS || site.blobs.contains(&address) {
                    continue;
                }
                if let Some(mut blob) = self.blob_at(address, xrefs).filter(Blob::reads_as_encoded) {
                    blob.passed_from.push(at);
                    candidate.blobs.insert(address, blob);
                    site.blobs.push(address);
                }
            }
            candidate.call_sites.push(site);
        }
        tracing
    }

    /// The data at `address` if it is file-backed and not code, measured to the first NUL, the next referenced
    /// address (`xrefs` is sorted by target) or `MAX_BLOB_BYTES`.
    fn blob_at(&self, address: u64, xrefs: &[rampage_analysis::discover::Xref]) -> Option<Blob> {
        if self.binary.is_code(address) {
            return None;
        }
        let bytes = self.binary.read_to_segment_end(address)?;
        let next = xrefs.partition_point(|xref| xref.to <= address);
        let to_next =
            xrefs.get(next).map_or(usize::MAX, |xref| usize::try_from(xref.to - address).unwrap_or(usize::MAX));
        let read = bytes.len().min(MAX_BLOB_BYTES).min(to_next);
        let length = bytes[..read].iter().position(|&byte| byte == 0).unwrap_or(read);
        if length < MIN_BLOB_BYTES {
            return None;
        }
        let data = &bytes[..length];
        let printable = |byte: &&u8| byte.is_ascii_graphic() || **byte == b' ';
        let non_printable = 1.0 - data.iter().filter(printable).count() as f64 / length as f64;
        Some(Blob {
            length,
            capped: length == MAX_BLOB_BYTES,
            entropy: shannon_entropy(data),
            non_printable,
            preview: rampage_arch::hex::bytes(&data[..length.min(16)]),
            passed_from: Vec::new(),
        })
    }
}

/// The start of the block of `function` that holds `address`.
fn block_start(analysis: &crate::project::Analysis, function: u64, address: u64) -> Option<u64> {
    let function = analysis.program.function_at(function)?;
    function.blocks.iter().find(|block| (block.start..block.end).contains(&address)).map(|block| block.start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_byte_operations_need_a_byte_operand() {
        let ops = |text: &str| classify(Arch::X86_64, text);
        assert!(ops("movzx r8d, byte ptr [rsi+rdx]").load);
        assert!(ops("mov [rdi+rdx], r8b").store);
        assert!(ops("mov byte ptr [rdi+rax], 0").store);
        assert!(!ops("mov [rdi+rdx], r8").store);
        assert!(ops("xor r8b, cl").xor);
        assert!(!ops("xor eax, eax").xor);
        let rmw = ops("xor byte ptr [rax], 0x5a");
        assert!(rmw.load && rmw.store && rmw.xor);
        assert!(ops("rol cl, 1").rotate);
        assert!(ops("add cl, 0x3d").add_sub);
        assert!(!ops("add rdx, 2").add_sub);
        assert!(ops("xor cl, [rsi+rdx]").load);
    }

    #[test]
    fn fixed_width_byte_operations_are_read_by_mnemonic() {
        let ops = |text: &str| classify(Arch::Aarch64, text);
        assert!(ops("ldrb w13, [x1], #1").load);
        assert!(ops("strb w11, [x10], #1").store);
        assert!(ops("eor w11, w13, w11").xor);
        assert!(!ops("eor w0, w1, w1").xor);
        assert!(!ops("add w11, w12, #61").add_sub);
        assert!(classify(Arch::Mips, "lbu $v0, 0($a1)").load);
        assert!(classify(Arch::Riscv64, "sb a5, 0(a0)").store);
    }

    #[test]
    fn operands_keep_bracketed_commas() {
        assert_eq!(parse("strb wzr, [x0, x8]"), ("strb".to_owned(), vec!["wzr".to_owned(), "[x0, x8]".to_owned()]));
        assert_eq!(parse("ret"), ("ret".to_owned(), vec![]));
    }

    /// Decoded instructions, as each architecture's disassembler formats them, and what they do to bytes.
    #[test]
    fn byte_operations_are_read_from_decoded_instructions() {
        let none = ByteOps::default();
        let load = ByteOps { load: true, ..none };
        let store = ByteOps { store: true, ..none };
        let xor = ByteOps { xor: true, ..none };
        let rotate = ByteOps { rotate: true, ..none };
        let cases: &[(Arch, &[u8], &str, ByteOps)] = &[
            (Arch::Arm, &[0x01, 0x30, 0xd1, 0xd4], "ldrble r3, [r1], #1", load),
            (Arch::Arm, &[0x01, 0x30, 0xc0, 0x14], "strbne r3, [r0], #1", store),
            (Arch::Arm, &[0x02, 0x30, 0x23, 0x10], "eorne r3, r3, r2", xor),
            (Arch::Arm, &[0x02, 0x30, 0x33, 0x10], "eorsne r3, r3, r2", xor),
            (Arch::Sparc, &[0xc2, 0x0a, 0x40, 0x00], "ldub [%o1], %g1", load),
            (Arch::Sparc, &[0xc2, 0x4a, 0x40, 0x00], "ldsb [%o1], %g1", load),
            (Arch::Sparc, &[0xc2, 0x2a, 0x00, 0x00], "stb %g1, [%o0]", store),
            (Arch::Sparc, &[0x82, 0x18, 0x40, 0x02], "xor %g1, %g2, %g1", xor),
            (Arch::S390x, &[0xe3, 0x10, 0x20, 0x00, 0x00, 0x94], "llc %r1, 0(%r2)", load),
            (Arch::S390x, &[0x43, 0x10, 0x30, 0x00], "ic %r1, 0(%r3)", load),
            (Arch::S390x, &[0x42, 0x10, 0x30, 0x00], "stc %r1, 0(%r3)", store),
            (Arch::S390x, &[0x17, 0x12], "xr %r1, %r2", xor),
            (Arch::S390x, &[0x97, 0x5a, 0x10, 0x00], "xi 0(%r1), 0x5a", ByteOps { load: true, store: true, ..xor }),
            (Arch::S390x, &[0xeb, 0x12, 0x00, 0x03, 0x00, 0x1d], "rll %r1, %r2, 3", rotate),
            (Arch::M68k, &[0x10, 0x18], "move.b (a0)+, d0", load),
            (Arch::M68k, &[0x12, 0xc0], "move.b d0, (a1)+", store),
            (Arch::M68k, &[0xb3, 0x00], "eor.b d1, d0", xor),
            (Arch::M68k, &[0x0a, 0x00, 0x00, 0x5a], "eori.b #$5a, d0", xor),
            (Arch::M68k, &[0xe3, 0x18], "rol.b #$1, d0", rotate),
            (Arch::M68k, &[0xd0, 0x01], "add.b d1, d0", ByteOps { add_sub: true, ..none }),
        ];
        for &(arch, bytes, text, expected) in cases {
            let formatted = rampage_arch::decoder_for(arch).unwrap().format(bytes, 0x1000);
            assert_eq!(formatted, text, "{arch:?} {bytes:02x?}");
            assert_eq!(classify(arch, &formatted), expected, "{arch:?} {formatted}");
        }
    }

    /// A decoder counting the instructions it decodes and formats.
    struct Counting {
        inner: Box<dyn Disassembler>,
        decoded: usize,
        formatted: usize,
    }

    impl Disassembler for Counting {
        fn decode(&mut self, bytes: &[u8], address: u64) -> Insn {
            self.decoded += 1;
            self.inner.decode(bytes, address)
        }
        fn decode_with_memory(&mut self, bytes: &[u8], address: u64, read: &dyn Fn(u64, u8) -> Option<u64>) -> Insn {
            self.decoded += 1;
            self.inner.decode_with_memory(bytes, address, read)
        }
        fn reset(&mut self) {
            self.inner.reset();
        }
        fn format(&mut self, bytes: &[u8], address: u64) -> String {
            self.formatted += 1;
            self.inner.format(bytes, address)
        }
    }

    fn project(path: &str) -> Project {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
        Project::new(rampage_loaders::Binary::open(path).unwrap())
    }

    #[test]
    fn loops_format_each_instruction_at_most_once() {
        let project = project("../../tests/fixtures/bin/hello-go-x64.elf");
        let mut decoder = Counting { inner: project.binary.decoder().unwrap(), decoded: 0, formatted: 0 };
        let analysis = project.analysis().unwrap();
        for function in analysis.program.functions.iter().filter(|f| f.instruction_count <= MAX_FUNCTION_INSTRUCTIONS) {
            let instructions = function_instructions(&project, &mut decoder, function);
            decoder.formatted = 0;
            project.byte_loop(&mut decoder, function, &instructions);
            assert!(decoder.formatted <= instructions.len(), "{:#x}", function.address);
        }
    }

    #[test]
    fn call_sites_decode_each_caller_block_once_for_a_bounded_set_of_candidates() {
        let project = project("tests/fixtures/decode-x64.elf");
        let analysis = project.analysis().unwrap();
        let decode = project.resolve("decode").unwrap();
        let main = analysis.program.function_at(project.resolve("main").unwrap()).unwrap();
        let function = analysis.program.function_at(decode).unwrap();
        let mut decoder = Counting { inner: project.binary.decoder().unwrap(), decoded: 0, formatted: 0 };
        let instructions = function_instructions(&project, &mut decoder, function);
        let found = project.byte_loop(&mut decoder, function, &instructions).unwrap();
        // The same routine many times over: every copy's three call sites sit in `main`'s one block.
        let mut candidates: Vec<Candidate> = (0..MAX_TRACED_CANDIDATES + 6)
            .map(|_| Candidate {
                name: found.name.clone(),
                quoted: found.quoted.clone(),
                call_sites: Vec::new(),
                blobs: BTreeMap::new(),
                ..found
            })
            .collect();
        decoder.decoded = 0;
        let tracing = project.trace_call_sites(&mut decoder, &mut candidates, &analysis.program.xrefs);
        assert!(decoder.decoded <= main.instruction_count, "{} > {}", decoder.decoded, main.instruction_count);
        assert_eq!((tracing.decoded, tracing.untraced_candidates, tracing.unread_sites), (decoder.decoded, 6, 0));
        assert!(candidates[..MAX_TRACED_CANDIDATES].iter().all(|candidate| candidate.blobs.len() == 3));
        assert!(candidates[MAX_TRACED_CANDIDATES..].iter().all(|candidate| !candidate.traced));
    }

    #[test]
    fn arm_conditions_come_off_only_known_mnemonics() {
        for text in ["bls #0x40", "teq r0, r1", "blo #0x40", "movne r0, r1", "lsls r0, r0, #1"] {
            assert_eq!(classify(Arch::Arm, text), ByteOps::default(), "{text}");
        }
        assert!(classify(Arch::Arm, "ldrbeq.w r3, [r1]").load);
        assert!(!classify(Arch::Aarch64, "strbne w0, [x1]").store, "conditions are stripped only on ARM");
        assert!(!classify(Arch::M68k, "move.l (a0)+, d0").load, "a long move is not a byte load");
        assert!(!classify(Arch::S390x, "xr %r1, %r1").xor);
    }
}
