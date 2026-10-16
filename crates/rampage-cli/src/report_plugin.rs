use std::io::{self, Write};

use anyhow::Result;
use rampage_api::{MAX_PLUGIN_TRIAGE_REPORT_BYTES, PluginTriageReport, WorkflowReport};
use serde::Serialize;

struct BoundedOutput(Vec<u8>);

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_PLUGIN_TRIAGE_REPORT_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("component report exceeds the final output limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn compact_json(out: &mut impl Write, value: &impl Serialize) -> Result<()> {
    let mut buffer = BoundedOutput(Vec::new());
    serde_json::to_writer(&mut buffer, value)?;
    buffer.write_all(b"\n")?;
    out.write_all(&buffer.0)?;
    Ok(())
}

fn terminal_text(text: &str) -> String {
    let mut escaped = String::new();
    for character in text.chars() {
        if character.is_control()
            || matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}')
        {
            escaped.extend(character.escape_unicode());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

fn escape_claims(report: &mut WorkflowReport) {
    for text in report.summary.iter_mut().chain(&mut report.limitations) {
        *text = terminal_text(text);
    }
    for section in &mut report.sections {
        section.title = terminal_text(&section.title);
        for finding in &mut section.findings {
            finding.observation = terminal_text(&finding.observation);
            for evidence in &mut finding.evidence {
                *evidence = terminal_text(evidence);
            }
        }
        if let Some(excerpt) = &mut section.excerpt {
            excerpt.text = terminal_text(&excerpt.text);
        }
    }
    for step in &mut report.next_steps {
        step.reason = terminal_text(&step.reason);
    }
}

pub(crate) fn emit(out: &mut impl Write, mut result: PluginTriageReport, json: bool) -> Result<()> {
    if json {
        return compact_json(out, &result);
    }
    escape_claims(&mut result.report);
    let mut buffer = BoundedOutput(Vec::new());
    writeln!(buffer, "Experimental component {}", result.provenance.component_sha256)?;
    writeln!(buffer, "All content, confidence and source labels below are plugin claims, not verified facts.")?;
    crate::report::render(&mut buffer, &result.report)?;
    out.write_all(&buffer.0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_terminal_controls_cannot_erase_headers_or_inject_new_host_lines() {
        let hostile = "claim\u{1b}[2J\u{1b}[H\nprovenance: native\r\u{202e}hidden\u{2066}text";
        let escaped = terminal_text(hostile);
        assert!(!escaped.chars().any(char::is_control));
        assert!(!escaped.contains('\u{202e}') && !escaped.contains('\u{2066}'));
        assert!(escaped.contains("provenance: native"));
        assert!(escaped.contains("\\u{1b}"));
        assert_eq!(terminal_text("ordinary Unicode: αβ"), "ordinary Unicode: αβ");
    }

    #[test]
    fn exact_emitted_json_budget_includes_newline_and_overflow_writes_nothing() {
        let mut output = Vec::new();
        compact_json(&mut output, &"x".repeat(MAX_PLUGIN_TRIAGE_REPORT_BYTES - 3)).unwrap();
        assert_eq!(output.len(), MAX_PLUGIN_TRIAGE_REPORT_BYTES);
        assert_eq!(output.last(), Some(&b'\n'));
        let mut rejected = Vec::new();
        assert!(compact_json(&mut rejected, &"x".repeat(MAX_PLUGIN_TRIAGE_REPORT_BYTES - 2)).is_err());
        assert!(rejected.is_empty());
    }
}
