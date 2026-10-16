use std::collections::{BTreeMap, BTreeSet};

use crate::*;

struct Budget {
    ids: BTreeMap<FactId, Source>,
    text_bytes: usize,
    text_items: usize,
}

impl Budget {
    fn new() -> Self {
        Self { ids: BTreeMap::new(), text_bytes: 0, text_items: 0 }
    }

    fn record(&mut self, id: FactId, source: Source) -> Result<(), FailureCode> {
        if id == 0 || self.ids.contains_key(&id) {
            return Err(FailureCode::InvalidInput);
        }
        if self.ids.len() >= MAX_RECORDS {
            return Err(FailureCode::InputLimit);
        }
        self.ids.insert(id, source);
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<(), FailureCode> {
        self.text_items = self.text_items.checked_add(1).ok_or(FailureCode::InputLimit)?;
        self.text_bytes = self.text_bytes.checked_add(text.len()).ok_or(FailureCode::InputLimit)?;
        if text.len() > MAX_TEXT_BYTES || self.text_bytes > MAX_INPUT_BYTES || self.text_items > MAX_RECORDS {
            return Err(FailureCode::InputLimit);
        }
        Ok(())
    }

    fn evidence(&mut self, evidence: &[String]) -> Result<(), FailureCode> {
        if evidence.len() > MAX_RECORDS {
            return Err(FailureCode::InputLimit);
        }
        for text in evidence {
            self.text(text)?;
        }
        Ok(())
    }
}

/// Semantic validation after bounded raw JSON ingestion; not a replacement for host raw preflight.
/// ID-bearing records and all scalar/evidence text items have separate 16,384-item budgets.
pub fn validate_facts(facts: &TriageFacts) -> Result<(), FailureCode> {
    fact_index(facts).map(|_| ())
}

fn fact_index(facts: &TriageFacts) -> Result<BTreeMap<FactId, Source>, FailureCode> {
    if facts.schema_version != SCHEMA_VERSION {
        return Err(FailureCode::UnsupportedSchema);
    }
    if !facts.exhaustive || !(1..=MAX_FINDINGS_PER_SECTION as u32).contains(&facts.per_section) {
        return Err(FailureCode::InvalidInput);
    }
    if facts.record_total as usize > MAX_RECORDS {
        return Err(FailureCode::InputLimit);
    }
    let mut budget = Budget::new();
    budget.record(facts.binary.id, Source::BinaryInfo)?;
    budget.text(&facts.binary.format)?;
    budget.text(&facts.binary.arch)?;
    budget.record(facts.triage.id, Source::Triage)?;
    if !facts.triage.entropy.is_finite() || !(0.0..=8.0).contains(&facts.triage.entropy) {
        return Err(FailureCode::InvalidInput);
    }
    for (digest, length) in [(&facts.triage.sha256, 64), (&facts.triage.md5, 32)] {
        if digest.len() != length || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(FailureCode::InvalidInput);
        }
        budget.text(digest)?;
    }
    for hint in &facts.triage.hints {
        budget.record(hint.id, Source::Triage)?;
        budget.text(&hint.text)?;
    }
    for detection in &facts.detections {
        budget.record(detection.id, Source::DetectTools)?;
        budget.text(&detection.name)?;
        budget.evidence(&detection.evidence)?;
    }
    if let Some(managed) = &facts.managed {
        budget.record(managed.id, Source::DotnetMetadata)?;
        budget.text(&managed.runtime_version)?;
        if let Some(assembly) = &managed.assembly {
            budget.text(&assembly.name)?;
            budget.text(&assembly.version)?;
        }
        if managed.il_method_count.checked_add(managed.native_method_count).is_none_or(|n| n > managed.method_count) {
            return Err(FailureCode::InvalidInput);
        }
        if managed.entry_method.is_some_and(|token| !method_token(token, managed.method_count)) {
            return Err(FailureCode::InvalidInput);
        }
        if managed.first_page_methods.len() as u64 > managed.method_count
            || managed.first_page_methods.iter().filter(|row| row.has_il).count() as u64 > managed.il_method_count
        {
            return Err(FailureCode::InvalidInput);
        }
        for reference in &managed.assembly_refs {
            budget.record(reference.id, Source::DotnetMetadata)?;
            budget.text(&reference.name)?;
            budget.text(&reference.version)?;
        }
        let mut tokens = BTreeSet::new();
        for method in &managed.first_page_methods {
            budget.record(method.id, Source::DotnetMetadata)?;
            if !method_token(method.token, managed.method_count) || !tokens.insert(method.token) {
                return Err(FailureCode::InvalidInput);
            }
        }
    }
    for capability in &facts.capabilities {
        budget.record(capability.id, Source::Capabilities)?;
        budget.text(&capability.name)?;
        budget.text(&capability.category)?;
        budget.evidence(&capability.evidence)?;
    }
    for import in &facts.imports {
        budget.record(import.id, Source::ListImports)?;
        if let Some(library) = &import.library {
            budget.text(library)?;
        }
        budget.text(&import.name)?;
    }
    for string in &facts.strings {
        budget.record(string.id, Source::ListStrings)?;
        budget.text(&string.text)?;
    }
    let mut functions = BTreeMap::new();
    match &facts.functions {
        FunctionFacts::Available { rows } => {
            for function in rows {
                budget.record(function.id, Source::ListFunctions)?;
                budget.text(&function.name)?;
                if functions.insert(function.address, function).is_some() {
                    return Err(FailureCode::InvalidInput);
                }
            }
        }
        FunctionFacts::Unavailable { reason } => {
            budget.text(reason)?;
            if !facts.signature_matches.is_empty() {
                return Err(FailureCode::InvalidInput);
            }
        }
    }
    let mut matched = BTreeSet::new();
    for signature in &facts.signature_matches {
        budget.record(signature.id, Source::IdentifyFunctions)?;
        budget.text(&signature.name)?;
        if let SignatureSource::Pack { name } = &signature.source {
            budget.text(name)?;
        }
        let function = functions.get(&signature.address).ok_or(FailureCode::InvalidInput)?;
        let default_name = format!("sub_{:x}", function.address);
        let unnamed = function.name == default_name;
        if signature.unnamed != unnamed || !matched.insert(signature.address) {
            return Err(FailureCode::InvalidInput);
        }
    }
    if budget.ids.len() != facts.record_total as usize {
        return Err(FailureCode::InvalidInput);
    }
    Ok(budget.ids)
}

fn method_token(token: u32, method_count: u64) -> bool {
    let row = token & 0x00ff_ffff;
    token & 0xff00_0000 == 0x0600_0000 && row != 0 && u64::from(row) <= method_count
}

/// Validates shape and references only. Passing this does not authenticate a plugin claim or its confidence.
/// Hosts must separately cap raw bytes before copying/lifting and bound strict JSON parsing allocations.
pub fn validate_report(facts: &TriageFacts, report: &ReportBody) -> Result<(), FailureCode> {
    let ids = fact_index(facts)?;
    if report.sections.len() != MAX_SECTIONS
        || report.summary.is_empty()
        || report.summary.len() > 8
        || report.limitations.is_empty()
        || report.limitations.len() > 16
        || report.next_steps.len() > MAX_NEXT_STEPS
        || report.next_steps_omitted > MAX_RECORDS as u32
    {
        return Err(FailureCode::InvalidReport);
    }
    let mut text_bytes = 0usize;
    for text in report.summary.iter().chain(&report.limitations) {
        output_text(text, &mut text_bytes)?;
    }
    let titles = ["Binary", "Toolchain", "Capabilities", "Imports by library", "Notable strings", "Functions"];
    for (section, title) in report.sections.iter().zip(titles) {
        if section.title != title
            || section.findings.len() > facts.per_section as usize
            || section.total < section.findings.len() as u32
            || section.total as usize > MAX_RECORDS + 1
            || section.truncated != (section.total > section.findings.len() as u32)
        {
            return Err(FailureCode::InvalidReport);
        }
        output_text(&section.title, &mut text_bytes)?;
        for finding in &section.findings {
            output_text(&finding.observation, &mut text_bytes)?;
            if finding.evidence.len() > MAX_EVIDENCE + 1 {
                return Err(FailureCode::InvalidReport);
            }
            if finding.evidence.len() == MAX_EVIDENCE + 1 {
                let last = &finding.evidence[MAX_EVIDENCE];
                let omitted = last.strip_prefix("... and ").and_then(|text| text.strip_suffix(" more"));
                if omitted.and_then(|text| text.parse::<u32>().ok()).is_none_or(|count| count == 0) {
                    return Err(FailureCode::InvalidReport);
                }
            }
            for evidence in &finding.evidence {
                output_text(evidence, &mut text_bytes)?;
            }
            references(&finding.fact_refs, &ids, Some(finding.source))?;
            if finding.fact_refs.is_empty() && finding.source != Source::ListFunctions {
                return Err(FailureCode::InvalidReport);
            }
            if let Some(address) = finding.address {
                let present = match finding.source {
                    Source::ListStrings => {
                        facts.strings.iter().any(|row| row.address == address && finding.fact_refs.contains(&row.id))
                    }
                    Source::IdentifyFunctions => facts
                        .signature_matches
                        .iter()
                        .any(|row| row.address == address && finding.fact_refs.contains(&row.id)),
                    Source::ListFunctions => match &facts.functions {
                        FunctionFacts::Available { rows } => {
                            rows.iter().any(|row| row.address == address && finding.fact_refs.contains(&row.id))
                        }
                        FunctionFacts::Unavailable { .. } => false,
                    },
                    _ => false,
                };
                if !present {
                    return Err(FailureCode::InvalidReport);
                }
            }
        }
    }
    let mut actions = Vec::new();
    for step in &report.next_steps {
        output_text(&step.reason, &mut text_bytes)?;
        references(&step.fact_refs, &ids, None)?;
        if step.fact_refs.is_empty() || actions.contains(&&step.action) {
            return Err(FailureCode::InvalidReport);
        }
        actions.push(&step.action);
        let matches = match &step.action {
            Action::DotnetMetadata => facts.managed.as_ref().is_some_and(|m| step.fact_refs.contains(&m.id)),
            Action::DotnetIl { method } => facts.managed.as_ref().is_some_and(|m| {
                (m.entry_method == Some(*method) && step.fact_refs.contains(&m.id))
                    || m.first_page_methods
                        .iter()
                        .any(|row| row.token == *method && row.has_il && step.fact_refs.contains(&row.id))
            }),
            Action::Xrefs { to } => {
                facts.strings.iter().any(|row| row.address == *to && step.fact_refs.contains(&row.id))
            }
            Action::IdentifyFunctions { .. } => {
                step.fact_refs.iter().any(|id| ids.get(id) == Some(&Source::IdentifyFunctions))
            }
            Action::FindMain => facts.managed.is_none() && step.fact_refs.contains(&facts.binary.id),
            Action::NetworkSurface | Action::AnalysisDiagnostics { .. } => true,
        };
        if !matches {
            return Err(FailureCode::InvalidReport);
        }
    }
    Ok(())
}

fn references(
    references: &[FactId],
    ids: &BTreeMap<FactId, Source>,
    source: Option<Source>,
) -> Result<(), FailureCode> {
    if references.len() > MAX_RECORDS {
        return Err(FailureCode::InvalidReport);
    }
    let mut seen = BTreeSet::new();
    for id in references {
        let actual = ids.get(id).ok_or(FailureCode::InvalidReport)?;
        if source.is_some_and(|expected| expected != *actual) || !seen.insert(*id) {
            return Err(FailureCode::InvalidReport);
        }
    }
    Ok(())
}

fn output_text(text: &str, total: &mut usize) -> Result<(), FailureCode> {
    *total = total.checked_add(text.len()).ok_or(FailureCode::OutputLimit)?;
    if text.len() > MAX_OUTPUT_TEXT_BYTES || *total > MAX_OUTPUT_BYTES {
        return Err(FailureCode::OutputLimit);
    }
    Ok(())
}
