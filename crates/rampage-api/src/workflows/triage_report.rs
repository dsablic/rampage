//! `triage_report`: a one-shot overview chaining binary_info, triage, detect_tools, capabilities, imports,
//! strings, function discovery and bundled-signature identification.

use std::collections::BTreeMap;

use rampage_detect::{Confidence as DetectConfidence, Kind};
use serde_json::json;

use super::{Confidence, Finding, ReportLimits, Section, WorkflowReport, classify, is_default_name, quote};
use crate::{ApiError, FunctionsQuery, Project};

/// Import names listed per library before the rest are counted.
const NAMES_PER_LIBRARY: usize = 12;

impl Project {
    /// A bounded first look at the binary: what it is, what built it, what it imports and contains, and where to
    /// look next. Analysis failures (an architecture without a decoder) shrink the report instead of failing it.
    pub fn triage_report(&self, limits: ReportLimits) -> Result<WorkflowReport, ApiError> {
        let mut report = WorkflowReport::new("triage_report", self);
        let triage = self.triage();
        let binary = &self.binary;

        let mut overview = Section::new("Binary", limits);
        let entry = binary.entry.map_or_else(|| "no entry point".to_owned(), |entry| format!("entry {entry:#x}"));
        overview.push(
            Finding::new(
                "binary_info",
                Confidence::Observed,
                format!("{:?} {} binary, {entry}", binary.format, binary.arch),
            )
            .evidence([format!("{} sections, {} segments", binary.sections.len(), binary.segments.len())]),
        );
        overview.push(
            Finding::new(
                "triage",
                Confidence::Observed,
                format!("image of {} bytes, overall entropy {:.2} bits/byte", triage.image_size, triage.entropy),
            )
            .evidence([format!("sha256 {}", triage.image_hashes.sha256), format!("md5 {}", triage.image_hashes.md5)]),
        );
        for hint in &triage.hints {
            overview.push(Finding::new("triage", Confidence::Medium, format!("triage hint: {hint}")));
        }
        report.sections.push(overview);

        let detections = self.detect_tools(None)?;
        let mut toolchain = Section::new("Toolchain", limits);
        for detection in &detections {
            let confidence = match detection.confidence {
                DetectConfidence::Strong => Confidence::High,
                DetectConfidence::Tentative => Confidence::Low,
            };
            let kind = format!("{:?}", detection.kind).to_lowercase();
            toolchain.push(
                Finding::new("detect_tools", confidence, format!("{kind} signature matched: {}", detection.name))
                    .evidence(detection.evidence.iter().cloned()),
            );
        }
        report.sections.push(toolchain);

        let capabilities = self.capabilities();
        let mut tags = Section::new("Capabilities", limits);
        for capability in &capabilities {
            tags.push(
                Finding::new(
                    "capabilities",
                    Confidence::Low,
                    format!(
                        "building blocks of '{}' ({}) are present; this does not show the behavior executes",
                        capability.name, capability.category
                    ),
                )
                .evidence(capability.evidence.iter().cloned()),
            );
        }
        report.sections.push(tags);

        let mut by_library: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for import in &binary.imports {
            by_library
                .entry(import.library.as_deref().unwrap_or("(library not recorded)"))
                .or_default()
                .push(&import.name);
        }
        let mut libraries: Vec<(&str, Vec<&str>)> = by_library.into_iter().collect();
        libraries.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
        let mut imports = Section::new("Imports by library", limits);
        for (library, names) in &libraries {
            let listed = names.iter().take(NAMES_PER_LIBRARY).copied().collect::<Vec<_>>().join(", ");
            let more = names.len().saturating_sub(NAMES_PER_LIBRARY);
            let suffix = if more > 0 { format!(", ... and {more} more") } else { String::new() };
            imports.push(
                Finding::new("list_imports", Confidence::Observed, format!("{library}: {} imports", names.len()))
                    .evidence([format!("{listed}{suffix}")]),
            );
        }
        report.sections.push(imports);
        if binary.imports.is_empty() {
            report.limitation(
                "No dynamic imports: the binary is statically linked, or resolves its imports at run time. Library \
                 code then appears as functions, which only symbols or signature matches can name.",
            );
        }

        let mut strings = Section::new("Notable strings", limits);
        let mut first_string = None;
        let mut network_strings = false;
        for found in self.scanned_strings() {
            let Some(indicator) = classify(&found.text) else { continue };
            first_string.get_or_insert(found.address);
            network_strings |= indicator.kind.is_network();
            strings.push(
                Finding::new(
                    "list_strings",
                    indicator.kind.confidence(),
                    format!("{}: {}", indicator.kind.label(), quote(&indicator.value)),
                )
                .at(found.address)
                .evidence([format!("string {} at {:#x}", quote(&found.text), found.address)]),
            );
        }
        let notable_strings = strings.total;
        report.sections.push(strings);

        let mut functions = Section::new("Functions", limits);
        let mut unnamed_matches = 0;
        match self.functions(&FunctionsQuery::default()) {
            Ok(page) => {
                let named = page.items.iter().filter(|row| !is_default_name(&row.name)).count();
                functions.push(
                    Finding::new(
                        "list_functions",
                        Confidence::Observed,
                        format!(
                            "{} functions discovered: {named} named by symbols, exports or the user, {} with default \
                             sub_ names",
                            page.total,
                            page.total - named
                        ),
                    )
                    .evidence(["recursive descent from the entry point, symbols, exports and unwind metadata"]),
                );
                let identified = self.apply_signatures_default(None, false)?;
                let mut by_name: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
                for candidate in &identified.matches {
                    by_name.entry(&candidate.name).or_default().push(candidate.address);
                }
                for (name, addresses) in by_name {
                    let shared = addresses.len() > 1;
                    if !shared && identified.matches.iter().any(|m| m.address == addresses[0] && m.unnamed) {
                        unnamed_matches += 1;
                    }
                    let (confidence, observation) = if shared {
                        (
                            Confidence::Low,
                            format!(
                                "{} functions share the masked hash of library function `{name}`; a hash shared this \
                                 way is likely a generic stub, not `{name}` itself",
                                addresses.len()
                            ),
                        )
                    } else {
                        (Confidence::Medium, format!("matches the bundled signature of library function `{name}`"))
                    };
                    functions.push(
                        Finding::new("identify_functions", confidence, observation)
                            .at(addresses[0])
                            .evidence(addresses.iter().map(|address| format!("{address:#x}"))),
                    );
                }
            }
            Err(error) => {
                report.limitation(format!("Function discovery is unavailable for this binary: {error}"));
            }
        }
        report.sections.push(functions);

        let detected = |kind: Kind| detections.iter().any(|detection| detection.kind == kind);
        let packed_hint = triage.hints.iter().any(|hint| hint.contains("packed") || hint.contains("typical of"));
        let networking = capabilities.iter().any(|capability| capability.category == "networking");

        let packing = if packed_hint || detected(Kind::Packer) || detected(Kind::Protector) {
            "Packing or protection signals were seen"
        } else {
            "No packing or protection signal matched"
        };
        let toolchain = detections.iter().map(|detection| detection.name.as_str()).collect::<Vec<_>>();
        report.summary = vec![
            format!("{:?} {} binary of {} bytes.", binary.format, binary.arch, triage.image_size),
            if toolchain.is_empty() {
                "No toolchain signature matched.".to_owned()
            } else {
                format!("Toolchain signatures matched: {}.", toolchain.join(", "))
            },
            format!(
                "{} imports from {} libraries; {} capability tags; {} notable strings.",
                binary.imports.len(),
                libraries.len(),
                capabilities.len(),
                notable_strings
            ),
            format!("{packing} (heuristic signals, not a determination)."),
        ];

        report.step("find_main", json!({}), "Locate the program's own entry logic past the runtime startup code.");
        if networking || network_strings {
            report.step(
                "network_surface",
                json!({}),
                "Networking capability tags or network-like strings were seen; map them to the functions using them.",
            );
        }
        if packed_hint || detected(Kind::Packer) || detected(Kind::Protector) {
            report.step(
                "analysis_diagnostics",
                json!({ "include_discovery": true }),
                "Packing or protection signals were seen; check how much of the code decodes reliably.",
            );
        }
        if unnamed_matches > 0 {
            report.step(
                "identify_functions",
                json!({ "apply": true }),
                format!(
                    "{unnamed_matches} unnamed functions match a unique bundled signature. Review the shared-hash \
                     matches first: apply also names one function of each shared hash."
                ),
            );
        }
        if let Some(address) = first_string {
            report.step(
                "xrefs",
                json!({ "to": format!("{address:#x}") }),
                "Find the code that references the first notable string.",
            );
        }

        report.limitation(
            "Capability tags and toolchain signatures are heuristics over imports, strings and byte patterns; they \
             show building blocks are present, not that any behavior runs.",
        );
        report.limitation(
            "Notable strings are classified lexically from a static scan; encoded, encrypted or runtime-built \
             strings are not seen, and a string's presence does not show it is used.",
        );
        report.limitation(
            "Signature identification compares masked byte hashes of whole functions: it can miss inlined or \
             differently compiled library code, and small stubs can share a hash.",
        );
        Ok(report)
    }
}
