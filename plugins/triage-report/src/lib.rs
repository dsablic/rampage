//! Import-free triage composition over complete immutable primitive facts.
//! Native calls to `compose` are for algorithm oracles only; production execution uses the component export.
//!
//! One private component instance is exclusively owned from `run` through the last `output` chunk. Production
//! creates a fresh instance per invocation, with no imports or reentry. A new `run` replaces the entire output
//! transaction; no generation field is needed under that ownership rule.

use std::collections::BTreeMap;
use std::io::{self, Write};

#[cfg(target_arch = "wasm32")]
use std::sync::Mutex;

use rampage_plugin_contract::*;

#[cfg(target_arch = "wasm32")]
wit_bindgen::generate!({
    path: "../../wit",
    world: "triage-plugin",
});

#[cfg(target_arch = "wasm32")]
struct Component;

#[cfg(target_arch = "wasm32")]
static OUTPUT: Mutex<OutputState> = Mutex::new(OutputState(Vec::new()));

#[cfg(target_arch = "wasm32")]
impl exports::rampage::workflow::triage::Guest for Component {
    fn run(input: Vec<u8>) -> u32 {
        OUTPUT.lock().expect("guest output state").run(&input)
    }

    fn output(offset: u32) -> (u64, u64, u64, u64) {
        OUTPUT.lock().expect("guest output state").output(offset)
    }
}

#[cfg(target_arch = "wasm32")]
export!(Component);

/// Allocation-free admission precedes guest serde allocation. The host checks returned length before allocation,
/// collects fixed-size chunks, then performs the same shared response admission before typed deserialization.
pub fn run_json(input: &[u8]) -> Vec<u8> {
    let outcome = match decode_facts(input) {
        Ok(facts) => {
            let body = compose(&facts);
            match validate_report(&facts, &body) {
                Ok(()) => GuestOutcome::Report { body },
                Err(code) => GuestOutcome::Failure { code },
            }
        }
        Err(code) => GuestOutcome::Failure { code },
    };
    let response = GuestResponse { schema_version: SCHEMA_VERSION, outcome };
    let mut output = BoundedOutput(Vec::new());
    match serde_json::to_writer(&mut output, &response) {
        Ok(()) => output.0,
        Err(_) => br#"{"schemaVersion":1,"outcome":{"status":"failure","code":"output_limit"}}"#.to_vec(),
    }
}

#[cfg(any(target_arch = "wasm32", test))]
struct OutputState(Vec<u8>);

#[cfg(any(target_arch = "wasm32", test))]
impl OutputState {
    fn run(&mut self, input: &[u8]) -> u32 {
        self.0 = run_json(input);
        self.0.len() as u32
    }

    fn output(&self, offset: u32) -> (u64, u64, u64, u64) {
        output_chunk(&self.0, offset)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn output_chunk(bytes: &[u8], offset: u32) -> (u64, u64, u64, u64) {
    let mut words = [0u64; 4];
    let start = offset as usize;
    if start < bytes.len() {
        for (index, byte) in bytes[start..].iter().take(32).enumerate() {
            words[index / 8] |= u64::from(*byte) << ((index % 8) * 8);
        }
    }
    (words[0], words[1], words[2], words[3])
}

struct BoundedOutput(Vec<u8>);

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_OUTPUT_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("output limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Composes an already validated fact set. No Project, host callback, native analysis or ambient authority exists.
pub fn compose(facts: &TriageFacts) -> ReportBody {
    let limit = facts.per_section as usize;
    let binary = &facts.binary;
    let triage = &facts.triage;
    let mut report = ReportBody {
        summary: Vec::new(),
        limitations: Vec::new(),
        next_steps: Vec::new(),
        next_steps_omitted: 0,
        sections: Vec::new(),
    };

    let mut overview = section("Binary");
    let entry = binary.entry.map_or_else(|| "no entry point".to_owned(), |entry| format!("entry {entry:#x}"));
    push(
        &mut overview,
        finding(
            Source::BinaryInfo,
            Confidence::Observed,
            format!("{} {} binary, {entry}", binary.format, binary.arch),
            [binary.id],
            [format!("{} sections, {} segments", binary.section_count, binary.segment_count)],
        ),
        limit,
    );
    push(
        &mut overview,
        finding(
            Source::Triage,
            Confidence::Observed,
            format!("image of {} bytes, overall entropy {:.2} bits/byte", triage.image_size, triage.entropy),
            [triage.id],
            [format!("sha256 {}", triage.sha256), format!("md5 {}", triage.md5)],
        ),
        limit,
    );
    for hint in &triage.hints {
        push(
            &mut overview,
            finding(Source::Triage, Confidence::Medium, format!("triage hint: {}", hint.text), [hint.id], []),
            limit,
        );
    }
    report.sections.push(overview);

    let mut toolchain = section("Toolchain");
    for detection in &facts.detections {
        let confidence = match detection.confidence {
            DetectionConfidence::Strong => Confidence::High,
            DetectionConfidence::Tentative => Confidence::Low,
        };
        push(
            &mut toolchain,
            finding(
                Source::DetectTools,
                confidence,
                format!("{} signature matched: {}", detection.kind.label(), detection.name),
                [detection.id],
                detection.evidence.iter().cloned(),
            ),
            limit,
        );
    }
    if let Some(managed) = &facts.managed {
        let identity = managed.assembly.as_ref().map_or_else(
            || "an unnamed module".to_owned(),
            |assembly| format!("{} {}", assembly.name, assembly.version),
        );
        let counts = format!(
            "{} types, {} methods ({} IL, {} native)",
            managed.type_count, managed.method_count, managed.il_method_count, managed.native_method_count,
        );
        let references = managed.assembly_refs.iter().map(|row| format!("references {} {}", row.name, row.version));
        push(
            &mut toolchain,
            finding(
                Source::DotnetMetadata,
                Confidence::Observed,
                format!(".NET assembly {identity}, metadata version {}", managed.runtime_version),
                std::iter::once(managed.id).chain(managed.assembly_refs.iter().map(|row| row.id)),
                std::iter::once(counts).chain(references),
            ),
            limit,
        );
    }
    report.sections.push(toolchain);

    let mut capabilities = section("Capabilities");
    for capability in &facts.capabilities {
        push(
            &mut capabilities,
            finding(
                Source::Capabilities,
                Confidence::Low,
                format!(
                    "building blocks of '{}' ({}) are present; this does not show the behavior executes",
                    capability.name, capability.category,
                ),
                [capability.id],
                capability.evidence.iter().cloned(),
            ),
            limit,
        );
    }
    report.sections.push(capabilities);

    let mut by_library: BTreeMap<&str, Vec<&ImportFact>> = BTreeMap::new();
    for import in &facts.imports {
        by_library.entry(import.library.as_deref().unwrap_or("(library not recorded)")).or_default().push(import);
    }
    let mut libraries: Vec<_> = by_library.into_iter().collect();
    libraries.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
    let mut imports = section("Imports by library");
    for (library, names) in &libraries {
        let listed = names.iter().take(12).map(|import| import.name.as_str()).collect::<Vec<_>>().join(", ");
        let more = names.len().saturating_sub(12);
        let suffix = if more > 0 { format!(", ... and {more} more") } else { String::new() };
        push(
            &mut imports,
            finding(
                Source::ListImports,
                Confidence::Observed,
                format!("{library}: {} imports", names.len()),
                names.iter().map(|row| row.id),
                [format!("{listed}{suffix}")],
            ),
            limit,
        );
    }
    report.sections.push(imports);
    if facts.imports.is_empty() {
        report.limitations.push(
            "No dynamic imports: the binary is statically linked, or resolves its imports at run time. Library \
             code then appears as functions, which only symbols or signature matches can name."
                .to_owned(),
        );
    }

    let mut strings = section("Notable strings");
    let mut notable: Vec<_> =
        facts.strings.iter().filter_map(|found| classify(&found.text).map(|indicator| (indicator, found))).collect();
    notable.sort_by_key(|(indicator, found)| (indicator.kind, found.address));
    let network_refs: Vec<_> = facts
        .capabilities
        .iter()
        .filter(|row| row.category == "networking")
        .map(|row| row.id)
        .chain(notable.iter().filter(|(indicator, _)| indicator.kind.is_network()).map(|(_, row)| row.id))
        .collect();
    let first_string = notable.first().map(|(_, found)| *found);
    for (indicator, found) in &notable {
        let mut item = finding(
            Source::ListStrings,
            indicator.kind.confidence(),
            format!("{}: {}", indicator.kind.label(), quote(&indicator.value)),
            [found.id],
            [format!("string {} at {:#x}", quote(&found.text), found.address)],
        );
        item.address = Some(found.address);
        push(&mut strings, item, limit);
    }
    let notable_strings = strings.total;
    report.sections.push(strings);

    let mut functions = section("Functions");
    let mut unique_unnamed = Vec::new();
    match &facts.functions {
        FunctionFacts::Available { rows } => {
            let named = rows.iter().filter(|row| row.name != format!("sub_{:x}", row.address)).count();
            push(
                &mut functions,
                finding(
                    Source::ListFunctions,
                    Confidence::High,
                    format!(
                        "{} functions discovered: {named} named by symbols, exports or the user, {} with default \
                         sub_ names",
                        rows.len(),
                        rows.len() - named,
                    ),
                    rows.iter().map(|row| row.id),
                    ["recursive descent from the entry point, symbols, exports and unwind metadata".to_owned()],
                ),
                limit,
            );
            let mut by_name: BTreeMap<&str, Vec<&SignatureFact>> = BTreeMap::new();
            for candidate in &facts.signature_matches {
                by_name.entry(&candidate.name).or_default().push(candidate);
            }
            for (name, matches) in by_name {
                let shared = matches.len() > 1;
                if !shared && matches[0].unnamed {
                    unique_unnamed.push(matches[0].id);
                }
                let (confidence, observation) = if shared {
                    (
                        Confidence::Low,
                        format!(
                            "{} functions share the masked hash of library function `{name}`; a hash shared this \
                             way is likely a generic stub, not `{name}` itself",
                            matches.len(),
                        ),
                    )
                } else {
                    let origin = signature_origin(&matches[0].source);
                    (Confidence::Medium, format!("matches the signature of library function `{name}` in {origin}"))
                };
                let mut item = finding(
                    Source::IdentifyFunctions,
                    confidence,
                    observation,
                    matches.iter().map(|row| row.id),
                    matches.iter().map(|row| format!("{:#x}", row.address)),
                );
                item.address = Some(matches[0].address);
                push(&mut functions, item, limit);
            }
        }
        FunctionFacts::Unavailable { reason } => {
            report.limitations.push(format!("Function discovery is unavailable for this binary: {reason}"));
        }
    }
    report.sections.push(functions);

    let packing_refs: Vec<_> = triage
        .hints
        .iter()
        .filter(|hint| hint.text.contains("packed") || hint.text.contains("typical of"))
        .map(|hint| hint.id)
        .chain(
            facts
                .detections
                .iter()
                .filter(|row| matches!(row.kind, DetectionKind::Packer | DetectionKind::Protector))
                .map(|row| row.id),
        )
        .collect();
    let packing_signal = !packing_refs.is_empty();
    let packing = if packing_signal {
        "Packing or protection signals were seen"
    } else {
        "No packing or protection signal matched"
    };
    let tools = facts.detections.iter().map(|row| row.name.as_str()).collect::<Vec<_>>();
    report.summary = vec![
        format!("{} {} binary of {} bytes.", binary.format, binary.arch, triage.image_size),
        if tools.is_empty() {
            "No toolchain signature matched.".to_owned()
        } else {
            format!("Toolchain signatures matched: {}.", tools.join(", "))
        },
        format!(
            "{} imports from {} libraries; {} capability tags; {} notable strings.",
            facts.imports.len(),
            libraries.len(),
            facts.capabilities.len(),
            notable_strings,
        ),
        format!("{packing} (heuristic signals, not a determination)."),
    ];

    if let Some(managed) = &facts.managed {
        step(
            &mut report,
            Action::DotnetMetadata,
            "This is a managed assembly: list its types and methods (CIL bodies) from the .NET metadata.",
            vec![managed.id],
        );
        if let Some(token) = managed.entry_method {
            step(
                &mut report,
                Action::DotnetIl { method: token },
                "List the CIL of the managed entry point, where the program's own logic starts.",
                vec![managed.id],
            );
        } else if let Some(method) = managed.first_page_methods.iter().find(|row| row.has_il) {
            step(
                &mut report,
                Action::DotnetIl { method: method.token },
                "No managed entry point (a library): list the CIL of its first method with an IL body.",
                vec![method.id],
            );
        }
        report.limitations.push(
            "This is a .NET assembly: its methods are CIL bytecode, so native function discovery, disassembly and \
             decompilation do not describe its logic; the .NET metadata does."
                .to_owned(),
        );
    } else {
        step(
            &mut report,
            Action::FindMain,
            "Locate the program's own entry logic past the runtime startup code.",
            vec![binary.id],
        );
    }
    if !network_refs.is_empty() {
        step(
            &mut report,
            Action::NetworkSurface,
            "Networking capability tags or network-like strings were seen; map them to the functions using them.",
            network_refs,
        );
    }
    if packing_signal {
        step(
            &mut report,
            Action::AnalysisDiagnostics { include_discovery: true },
            "Packing or protection signals were seen; check how much of the code decodes reliably.",
            packing_refs,
        );
    }
    if !unique_unnamed.is_empty() {
        let reason = format!(
            "{} unnamed functions match a unique library signature. Review the shared-hash matches first: apply \
             also names one function of each shared hash.",
            unique_unnamed.len(),
        );
        step(&mut report, Action::IdentifyFunctions { apply: true }, &reason, unique_unnamed);
    }
    if let Some(found) = first_string {
        step(
            &mut report,
            Action::Xrefs { to: found.address },
            "Find the code that references the first notable string.",
            vec![found.id],
        );
    }
    report.limitations.extend([
        "Capability tags and toolchain signatures are heuristics over imports, strings and byte patterns; they \
         show building blocks are present, not that any behavior runs."
            .to_owned(),
        "Notable strings are classified lexically from a static scan; encoded, encrypted or runtime-built \
         strings are not seen, and a string's presence does not show it is used."
            .to_owned(),
        "Signature identification compares masked byte hashes of whole functions: it can miss inlined or \
         differently compiled library code, and small stubs can share a hash."
            .to_owned(),
    ]);
    report
}

fn section(title: &str) -> Section {
    Section { title: title.to_owned(), findings: Vec::new(), total: 0, truncated: false }
}

fn push(section: &mut Section, finding: Finding, limit: usize) {
    section.total += 1;
    if section.findings.len() < limit {
        section.findings.push(finding);
    } else {
        section.truncated = true;
    }
}

fn finding(
    source: Source,
    confidence: Confidence,
    observation: String,
    references: impl IntoIterator<Item = FactId>,
    evidence: impl IntoIterator<Item = String>,
) -> Finding {
    let mut retained = Vec::new();
    let mut omitted = 0;
    for text in evidence {
        if retained.len() < MAX_EVIDENCE {
            retained.push(text);
        } else {
            omitted += 1;
        }
    }
    if omitted > 0 {
        retained.push(format!("... and {omitted} more"));
    }
    Finding {
        observation,
        evidence: retained,
        source,
        confidence,
        address: None,
        fact_refs: references.into_iter().collect(),
    }
}

fn step(report: &mut ReportBody, action: Action, reason: &str, fact_refs: Vec<FactId>) {
    if report.next_steps.iter().any(|step| step.action == action) {
        return;
    }
    if report.next_steps.len() < MAX_NEXT_STEPS {
        report.next_steps.push(NextStep { action, reason: reason.to_owned(), fact_refs });
    } else {
        report.next_steps_omitted += 1;
    }
}

fn signature_origin(source: &SignatureSource) -> String {
    match source {
        SignatureSource::Bundled => "the bundled starter database".to_owned(),
        SignatureSource::User => "the user-supplied database".to_owned(),
        SignatureSource::Pack { name } => format!("data pack `{name}`"),
    }
}

fn quote(text: &str) -> String {
    if text.chars().count() <= MAX_QUOTE_CHARS {
        return format!("{text:?}");
    }
    let cut: String = text.chars().take(MAX_QUOTE_CHARS).collect();
    format!("{cut:?}...")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum IndicatorKind {
    Url,
    Ipv4,
    Domain,
    RegistryKey,
    FilePath,
}

impl IndicatorKind {
    fn label(self) -> &'static str {
        match self {
            Self::Url => "URL",
            Self::Ipv4 => "IPv4-like address",
            Self::Domain => "domain-like name",
            Self::RegistryKey => "registry key",
            Self::FilePath => "file path",
        }
    }

    fn is_network(self) -> bool {
        matches!(self, Self::Url | Self::Ipv4 | Self::Domain)
    }

    fn confidence(self) -> Confidence {
        match self {
            Self::Url | Self::RegistryKey | Self::FilePath => Confidence::High,
            Self::Ipv4 => Confidence::Medium,
            Self::Domain => Confidence::Low,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Indicator {
    kind: IndicatorKind,
    value: String,
}

const URL_SCHEMES: [&str; 5] = ["http://", "https://", "ftp://", "ws://", "wss://"];
const TLDS: [&str; 22] = [
    "com", "net", "org", "biz", "xyz", "top", "onion", "ru", "cn", "su", "tk", "de", "uk", "fr", "jp", "kr", "br",
    "nl", "ir", "us", "eu", "gov",
];
const UNIX_ROOTS: [&str; 19] = [
    "/etc/",
    "/tmp/",
    "/var/",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/dev/",
    "/proc/",
    "/sys/",
    "/home/",
    "/root/",
    "/opt/",
    "/lib/",
    "/lib64/",
    "/Library/",
    "/System/",
    "/Users/",
    "/Applications/",
    "/private/",
];
const WINDOWS_VARIABLES: [&str; 7] =
    ["%appdata%", "%temp%", "%systemroot%", "%userprofile%", "%programdata%", "%localappdata%", "%windir%"];
const REGISTRY_PREFIXES: [&str; 8] =
    ["hkey_", "hklm\\", "hkcu\\", "hkcr\\", "hku\\", "software\\", "system\\currentcontrolset", "\\registry\\"];

fn classify(text: &str) -> Option<Indicator> {
    let indicator = |kind, value: &str| Some(Indicator { kind, value: value.to_owned() });
    if let Some(url) = url(text) {
        return indicator(IndicatorKind::Url, url);
    }
    let lower = text.to_ascii_lowercase();
    if REGISTRY_PREFIXES.iter().any(|prefix| lower.starts_with(prefix)) || lower.contains("\\software\\") {
        return indicator(IndicatorKind::RegistryKey, text);
    }
    let tokens = || text.split(|c: char| !(c.is_ascii_alphanumeric() || "._-:".contains(c)));
    if let Some(address) = tokens().find(|token| is_ipv4(token)) {
        return indicator(IndicatorKind::Ipv4, address);
    }
    if let Some(domain) = tokens().find(|token| is_domain(token) && !in_path(text, token)) {
        return indicator(IndicatorKind::Domain, domain);
    }
    if is_path(text, &lower) {
        return indicator(IndicatorKind::FilePath, text);
    }
    None
}

fn url(text: &str) -> Option<&str> {
    let lower = text.to_ascii_lowercase();
    let start = URL_SCHEMES.iter().filter_map(|scheme| lower.find(scheme).map(|at| (at, scheme.len()))).min()?;
    let rest = &text[start.0..];
    let end = rest.find(|c: char| c.is_whitespace() || "\"'<>`".contains(c)).unwrap_or(rest.len());
    let url = &rest[..end];
    let host = &url[start.1..];
    host.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '[').then_some(url)
}

fn is_ipv4(token: &str) -> bool {
    let (address, port) = match token.split_once(':') {
        Some((address, port)) => (address, Some(port)),
        None => (token, None),
    };
    let octets: Vec<_> = address.split('.').collect();
    let octets_valid =
        octets.len() == 4 && octets.iter().all(|octet| (1..=3).contains(&octet.len()) && octet.parse::<u8>().is_ok());
    let port_valid = port.is_none_or(|port| port.parse::<u16>().is_ok_and(|port| port > 0));
    octets_valid && port_valid
}

fn is_domain(token: &str) -> bool {
    let host = token.split(':').next().unwrap_or(token).trim_end_matches('.');
    let labels: Vec<_> = host.split('.').collect();
    let Some(tld) = labels.last() else { return false };
    labels.len() >= 2
        && host.len() <= 253
        && TLDS.contains(&tld.to_ascii_lowercase().as_str())
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && labels[..labels.len() - 1].iter().any(|label| label.chars().any(|c| c.is_ascii_alphabetic()))
}

fn in_path(text: &str, token: &str) -> bool {
    let start = token.as_ptr() as usize - text.as_ptr() as usize;
    text[..start].ends_with(['/', '\\'])
}

fn is_path(text: &str, lower: &str) -> bool {
    let bytes = text.as_bytes();
    let drive = bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    let unc = text.starts_with("\\\\") && text.len() > 3;
    let unix = UNIX_ROOTS.iter().any(|root| text.starts_with(root)) && !text.contains(char::is_whitespace);
    text.len() <= 260 && (drive || unc || unix || WINDOWS_VARIABLES.iter().any(|variable| lower.contains(variable)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> TriageFacts {
        TriageFacts {
            schema_version: SCHEMA_VERSION,
            exhaustive: true,
            record_total: 2,
            per_section: 25,
            binary: BinaryFact {
                id: 1,
                format: "Elf".to_owned(),
                arch: "x86_64".to_owned(),
                entry: Some(0x1000),
                section_count: 3,
                segment_count: 2,
            },
            triage: TriageFact {
                id: 2,
                image_size: 256,
                entropy: 3.5,
                sha256: "a".repeat(64),
                md5: "b".repeat(32),
                hints: Vec::new(),
            },
            detections: Vec::new(),
            managed: None,
            capabilities: Vec::new(),
            imports: Vec::new(),
            strings: Vec::new(),
            functions: FunctionFacts::Available { rows: Vec::new() },
            signature_matches: Vec::new(),
        }
    }

    fn seal(facts: &mut TriageFacts) {
        let methods = facts.managed.as_ref().map_or(0, |m| 1 + m.assembly_refs.len() + m.first_page_methods.len());
        let functions = match &facts.functions {
            FunctionFacts::Available { rows } => rows.len(),
            FunctionFacts::Unavailable { .. } => 0,
        };
        facts.record_total = (2
            + facts.triage.hints.len()
            + facts.detections.len()
            + methods
            + facts.capabilities.len()
            + facts.imports.len()
            + facts.strings.len()
            + functions
            + facts.signature_matches.len()) as u32;
    }

    fn run(facts: &mut TriageFacts) -> ReportBody {
        seal(facts);
        validate_facts(facts).unwrap();
        let bytes = serde_json::to_vec(facts).unwrap();
        let response: GuestResponse = serde_json::from_slice(&run_json(&bytes)).unwrap();
        assert_eq!(response.schema_version, SCHEMA_VERSION);
        match response.outcome {
            GuestOutcome::Report { body } => {
                validate_report(facts, &body).unwrap();
                body
            }
            GuestOutcome::Failure { code } => panic!("unexpected failure: {code:?}"),
        }
    }

    fn import(id: FactId, library: &str, name: &str) -> ImportFact {
        ImportFact { id, library: Some(library.to_owned()), name: name.to_owned() }
    }

    fn string(id: FactId, address: u64, text: &str) -> StringFact {
        StringFact { id, address, text: text.to_owned() }
    }

    #[test]
    fn import_count_ranks_before_name_and_only_twelve_names_are_listed() {
        let mut input = facts();
        input.imports = (0..13).map(|i| import(10 + i, "b", &format!("fn_{i:02}"))).collect();
        input.imports.extend([import(30, "z", "last"), import(31, "a", "first")]);
        let report = run(&mut input);
        let imports = &report.sections[3];
        let observations: Vec<_> = imports.findings.iter().map(|row| row.observation.as_str()).collect();
        assert_eq!(observations, ["b: 13 imports", "a: 1 imports", "z: 1 imports"]);
        assert!(imports.findings[0].evidence[0].ends_with("fn_11, ... and 1 more"));
        assert!(!imports.findings[0].evidence[0].contains("fn_12"));
        assert_eq!(imports.findings[0].fact_refs.len(), 13);
    }

    #[test]
    fn network_indicator_ranking_and_recommendations_survive_a_one_finding_cap() {
        let mut input = facts();
        input.per_section = 1;
        input.strings = vec![
            string(10, 0x100, "/Users/builder/source.cc"),
            string(11, 0x200, "HKEY_LOCAL_MACHINE\\Software\\Run"),
            string(12, 0x300, "198.51.100.23"),
            string(13, 0x500, "GET http://updates.example.com/check HTTP/1.1"),
            string(14, 0x400, "https://earlier.example.com/"),
        ];
        let report = run(&mut input);
        let strings = &report.sections[4];
        assert_eq!(strings.total, 5);
        assert!(strings.truncated);
        assert_eq!(strings.findings.len(), 1);
        assert_eq!(strings.findings[0].observation, "URL: \"https://earlier.example.com/\"");
        assert_eq!(strings.findings[0].confidence, Confidence::High);
        let actions: Vec<_> = report.next_steps.iter().map(|step| &step.action).collect();
        assert_eq!(actions, [&Action::FindMain, &Action::NetworkSurface, &Action::Xrefs { to: 0x400 }]);
        assert!(report.summary[2].ends_with("5 notable strings."));
    }

    #[test]
    fn lexical_lookalikes_are_not_classified_as_networking() {
        let cases = [
            "1.2.3.4.5",
            "256.1.1.1",
            "libc.so.6",
            "GLIBC_2.2.5",
            "http://",
            "src/foo.cc",
            "absl/strings/str_cat.cc",
            "Assertion failed at third_party/net/session.com",
            "src\\net\\client.de",
            "std.io",
            "config.info",
            "my_host.example.com",
        ];
        let mut input = facts();
        input.strings = cases.iter().enumerate().map(|(i, text)| string(10 + i as u32, i as u64, text)).collect();
        let report = run(&mut input);
        assert_eq!(report.sections[4].total, 0);
        assert!(!report.next_steps.iter().any(|step| step.action == Action::NetworkSurface));
        for (text, kind) in [
            ("evil.ru/gate.php", IndicatorKind::Domain),
            ("connect to evil.de:443", IndicatorKind::Domain),
            ("https://tunnel.ngrok.io/x", IndicatorKind::Url),
            ("C:\\Windows\\System32\\cmd.exe", IndicatorKind::FilePath),
            ("%APPDATA%\\tool.dat", IndicatorKind::FilePath),
        ] {
            assert_eq!(classify(text).unwrap().kind, kind);
        }
    }

    #[test]
    fn shared_signatures_are_low_confidence_and_never_count_as_unique_unnamed() {
        let mut input = facts();
        let address = u64::MAX - 2;
        input.functions = FunctionFacts::Available {
            rows: (0..3)
                .map(|i| FunctionFact {
                    id: 10 + i,
                    address: address + u64::from(i),
                    name: format!("sub_{:x}", address + u64::from(i)),
                })
                .collect(),
        };
        input.signature_matches = (0..3)
            .map(|i| SignatureFact {
                id: 20 + i,
                address: address + u64::from(i),
                name: if i == 2 { "exit" } else { "__lctrans" }.to_owned(),
                unnamed: true,
                source: SignatureSource::Bundled,
            })
            .collect();
        let report = run(&mut input);
        let functions = &report.sections[5];
        assert_eq!(functions.findings[1].confidence, Confidence::Low);
        assert!(functions.findings[1].observation.contains("2 functions share"));
        assert_eq!(functions.findings[1].address, Some(address));
        assert_eq!(functions.findings[2].confidence, Confidence::Medium);
        let step = report.next_steps.iter().find(|step| step.action == Action::IdentifyFunctions { apply: true });
        assert!(step.unwrap().reason.starts_with("1 unnamed functions"));
        assert_eq!(step.unwrap().fact_refs, [22]);
        input.signature_matches.pop();
        let shared_only = run(&mut input);
        assert!(!shared_only.next_steps.iter().any(|step| matches!(step.action, Action::IdentifyFunctions { .. })));
    }

    #[test]
    fn unavailable_discovery_preserves_static_sections_and_limitations() {
        let mut input = facts();
        input.functions = FunctionFacts::Unavailable { reason: "no decoder".to_owned() };
        input.strings.push(string(10, 0x1000, "https://example.com"));
        let report = run(&mut input);
        assert!(report.sections[5].findings.is_empty());
        assert_eq!(report.sections[4].total, 1);
        assert!(report.limitations.iter().any(|line| line.contains("Function discovery is unavailable")));
        assert!(report.limitations.iter().any(|line| line.contains("No dynamic imports")));
    }

    #[test]
    fn managed_entry_wins_over_first_page_and_library_falls_back_to_first_il_method() {
        let mut input = facts();
        input.managed = Some(ManagedFact {
            id: 10,
            assembly: Some(AssemblyIdentity { name: "Example".to_owned(), version: "1.0.0.0".to_owned() }),
            runtime_version: "v4.0.30319".to_owned(),
            type_count: 1,
            method_count: 3,
            il_method_count: 2,
            native_method_count: 1,
            assembly_refs: Vec::new(),
            entry_method: Some(0x0600_0003),
            first_page_methods: vec![
                MethodFact { id: 11, token: 0x0600_0001, has_il: false },
                MethodFact { id: 12, token: 0x0600_0002, has_il: true },
            ],
        });
        let report = run(&mut input);
        assert_eq!(report.next_steps[0].action, Action::DotnetMetadata);
        assert_eq!(report.next_steps[1].action, Action::DotnetIl { method: 0x0600_0003 });
        assert!(!report.next_steps.iter().any(|step| step.action == Action::FindMain));
        input.managed.as_mut().unwrap().entry_method = None;
        let library = run(&mut input);
        assert_eq!(library.next_steps[1].action, Action::DotnetIl { method: 0x0600_0002 });
        assert_eq!(library.next_steps[1].fact_refs, [12]);
    }

    #[test]
    fn forged_managed_tokens_and_retained_method_counts_fail_closed() {
        let mut input = facts();
        let managed = ManagedFact {
            id: 10,
            assembly: None,
            runtime_version: "v4".to_owned(),
            type_count: 1,
            method_count: 2,
            il_method_count: 1,
            native_method_count: 1,
            assembly_refs: Vec::new(),
            entry_method: Some(0x0600_0002),
            first_page_methods: vec![
                MethodFact { id: 11, token: 0x0600_0001, has_il: false },
                MethodFact { id: 12, token: 0x0600_0002, has_il: true },
            ],
        };
        input.managed = Some(managed.clone());
        run(&mut input);
        for bad_token in [0x0600_0000, 0x0600_0003, 0x0600_ffff, 0x0200_0001] {
            input.managed = Some(ManagedFact { entry_method: Some(bad_token), ..managed.clone() });
            assert_eq!(failure(&serde_json::to_vec(&input).unwrap()), FailureCode::InvalidInput);
            let mut forged_row = managed.clone();
            forged_row.first_page_methods[0].token = bad_token;
            input.managed = Some(forged_row);
            assert_eq!(failure(&serde_json::to_vec(&input).unwrap()), FailureCode::InvalidInput);
        }
        let mut too_many_rows = managed.clone();
        too_many_rows.method_count = 1;
        too_many_rows.native_method_count = 0;
        too_many_rows.entry_method = None;
        too_many_rows.first_page_methods[1].token = 0x0600_0001;
        input.managed = Some(too_many_rows);
        assert_eq!(failure(&serde_json::to_vec(&input).unwrap()), FailureCode::InvalidInput);
        let mut too_many_il = managed;
        too_many_il.first_page_methods[0].has_il = true;
        input.managed = Some(too_many_il);
        assert_eq!(failure(&serde_json::to_vec(&input).unwrap()), FailureCode::InvalidInput);
    }

    #[test]
    fn preflight_blocks_evidence_amplification_and_accepts_escaped_text_at_the_limit() {
        let mut input = facts();
        input.detections.push(DetectionFact {
            id: 10,
            name: "Boundary".to_owned(),
            kind: DetectionKind::Unknown,
            confidence: DetectionConfidence::Tentative,
            evidence: vec![String::new(); 300_000],
        });
        seal(&mut input);
        let json = serde_json::to_vec(&input).unwrap();
        assert!(json.len() < MAX_INPUT_BYTES);
        assert_eq!(decode_facts(&json), Err(FailureCode::InputLimit));
        assert_eq!(failure(&json), FailureCode::InputLimit);
        input.detections.clear();
        input.binary.arch = "x".repeat(MAX_TEXT_BYTES);
        seal(&mut input);
        let json = serde_json::to_string(&input).unwrap();
        let escaped = json.replace(&"x".repeat(MAX_TEXT_BYTES), &"\\u0078".repeat(MAX_TEXT_BYTES));
        assert!(decode_facts(escaped.as_bytes()).is_ok());
        let response: GuestResponse = serde_json::from_slice(&run_json(escaped.as_bytes())).unwrap();
        assert!(matches!(response.outcome, GuestOutcome::Report { .. }));
    }

    #[test]
    fn evidence_omission_and_packing_advice_do_not_depend_on_section_retention() {
        let mut input = facts();
        input.per_section = 1;
        input.detections = vec![DetectionFact {
            id: 10,
            name: "Example packer".to_owned(),
            kind: DetectionKind::Packer,
            confidence: DetectionConfidence::Strong,
            evidence: (0..12).map(|i| format!("evidence {i}")).collect(),
        }];
        let report = run(&mut input);
        assert_eq!(report.sections[1].findings[0].evidence.last().unwrap(), "... and 4 more");
        assert!(
            report
                .next_steps
                .iter()
                .any(|step| { step.action == Action::AnalysisDiagnostics { include_discovery: true } })
        );
        input.detections.clear();
        input.triage.hints.push(HintFact { id: 11, text: "entropy typical of packing".to_owned() });
        let report = run(&mut input);
        assert!(report.sections[0].truncated);
        assert!(report.summary[3].starts_with("Packing or protection signals were seen"));
    }

    fn failure(input: &[u8]) -> FailureCode {
        let response: GuestResponse = serde_json::from_slice(&run_json(input)).unwrap();
        match response.outcome {
            GuestOutcome::Failure { code } => code,
            GuestOutcome::Report { .. } => panic!("expected failure"),
        }
    }

    #[test]
    fn schema_unknown_fields_and_incomplete_or_oversized_facts_fail_closed() {
        let mut input = facts();
        input.schema_version += 1;
        assert_eq!(failure(&serde_json::to_vec(&input).unwrap()), FailureCode::UnsupportedSchema);
        input.schema_version = SCHEMA_VERSION;
        let json = serde_json::to_string(&input).unwrap();
        let unknown = format!("{{\"unexpected\":true,{}", &json[1..]);
        assert_eq!(failure(unknown.as_bytes()), FailureCode::InvalidInput);
        input.exhaustive = false;
        assert_eq!(failure(&serde_json::to_vec(&input).unwrap()), FailureCode::InvalidInput);
        input.exhaustive = true;
        input.binary.arch = "x".repeat(MAX_TEXT_BYTES + 1);
        assert_eq!(failure(&serde_json::to_vec(&input).unwrap()), FailureCode::InputLimit);
        assert_eq!(failure(&vec![b' '; MAX_INPUT_BYTES + 1]), FailureCode::InputLimit);
    }

    #[test]
    fn duplicate_ids_forged_counts_and_mismatched_source_references_are_rejected() {
        let mut input = facts();
        input.imports.push(import(1, "libc", "connect"));
        seal(&mut input);
        assert_eq!(validate_facts(&input), Err(FailureCode::InvalidInput));
        input.imports[0].id = 10;
        let mut report = run(&mut input);
        report.sections[3].findings[0].fact_refs = vec![input.binary.id];
        assert_eq!(validate_report(&input, &report), Err(FailureCode::InvalidReport));
        input.record_total += 1;
        assert_eq!(validate_facts(&input), Err(FailureCode::InvalidInput));
    }

    #[test]
    fn composed_output_limits_return_a_small_typed_failure() {
        let mut input = facts();
        input.detections = (0..60)
            .map(|i| DetectionFact {
                id: 10 + i,
                name: "x".repeat(MAX_TEXT_BYTES),
                kind: DetectionKind::Unknown,
                confidence: DetectionConfidence::Tentative,
                evidence: Vec::new(),
            })
            .collect();
        seal(&mut input);
        validate_facts(&input).unwrap();
        assert_eq!(failure(&serde_json::to_vec(&input).unwrap()), FailureCode::OutputLimit);
        let mut writer = BoundedOutput(Vec::new());
        assert!(writer.write_all(&vec![0; MAX_OUTPUT_BYTES + 1]).is_err());
        assert!(writer.0.is_empty());
    }

    #[test]
    fn output_chunks_are_little_endian_stable_and_zero_padded() {
        let bytes: Vec<_> = (0u8..35).collect();
        let first = output_chunk(&bytes, 0);
        assert_eq!(first.0.to_le_bytes(), [0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(first.3.to_le_bytes(), [24, 25, 26, 27, 28, 29, 30, 31]);
        assert_eq!(output_chunk(&bytes, 32), (0x22_21_20, 0, 0, 0));
        assert_eq!(output_chunk(&bytes, 0), first);
        assert_eq!(output_chunk(&bytes, u32::MAX), (0, 0, 0, 0));
    }

    fn collect_transaction(state: &OutputState, length: u32) -> Vec<u8> {
        assert!(length as usize <= MAX_OUTPUT_BYTES);
        let mut bytes = Vec::with_capacity(length as usize);
        for offset in (0..length).step_by(32) {
            let (a, b, c, d) = state.output(offset);
            for word in [a, b, c, d] {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
        }
        bytes.truncate(length as usize);
        bytes
    }

    #[test]
    fn successive_runs_replace_the_whole_export_state_without_shared_test_globals() {
        let mut state = OutputState(Vec::new());
        let input = facts();
        let first_len = state.run(&serde_json::to_vec(&input).unwrap());
        let first = collect_transaction(&state, first_len);
        assert_eq!(collect_transaction(&state, first_len), first);
        assert!(matches!(decode_response(&first, &input).unwrap().outcome, GuestOutcome::Report { .. }));
        let second_len = state.run(b"{}");
        let second = collect_transaction(&state, second_len);
        assert!(second_len < first_len);
        assert_ne!(second, first);
        let response = decode_response(&second, &input).unwrap();
        assert_eq!(response.outcome, GuestOutcome::Failure { code: FailureCode::InvalidInput });
        assert_eq!(state.output(second_len), (0, 0, 0, 0));
        assert_eq!(state.output(first_len), (0, 0, 0, 0));
    }
}
