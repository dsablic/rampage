use std::io::{self, Write};

use rampage_plugin_contract as contract;
use serde::Serialize;

use super::{MAX_PLUGIN_TRIAGE_SOURCE_BYTES, invalid};
use crate::{ApiError, Project, ProjectWorkspaceTaskControl};

#[derive(Default)]
pub(super) struct FactBudget {
    records: u32,
    text_bytes: usize,
    text_items: usize,
}

impl FactBudget {
    pub(super) fn record(&mut self) -> Result<u32, ApiError> {
        if self.records as usize >= contract::MAX_RECORDS {
            return Err(invalid("complete plugin triage inventory exceeds the record limit"));
        }
        self.records += 1;
        Ok(self.records)
    }

    pub(super) fn records(&self) -> u32 {
        self.records
    }

    pub(super) fn text(&mut self, text: &str) -> Result<(), ApiError> {
        self.text_length(text.len())
    }

    fn text_length(&mut self, length: usize) -> Result<(), ApiError> {
        self.text_bytes = self.text_bytes.checked_add(length).ok_or_else(|| invalid("text budget overflow"))?;
        self.text_items += 1;
        if length > contract::MAX_TEXT_BYTES
            || self.text_bytes > contract::MAX_INPUT_BYTES
            || self.text_items > contract::MAX_RECORDS
        {
            return Err(invalid("complete plugin triage inventory exceeds the text limit"));
        }
        Ok(())
    }

    pub(super) fn texts(&mut self, texts: &[String]) -> Result<(), ApiError> {
        if texts.len() > contract::MAX_RECORDS {
            return Err(invalid("too many evidence strings"));
        }
        for text in texts {
            self.text(text)?;
        }
        Ok(())
    }
}

pub(super) fn preflight_source(project: &Project, control: &ProjectWorkspaceTaskControl<'_>) -> Result<(), ApiError> {
    let binary = &project.binary;
    if binary.file_bytes().len() > MAX_PLUGIN_TRIAGE_SOURCE_BYTES
        || binary.image_bytes().len() > MAX_PLUGIN_TRIAGE_SOURCE_BYTES
    {
        return Err(invalid("plugin triage source exceeds 16 MiB"));
    }
    let (selection, ranges, rebases) = binary.inventory_source_context();
    if selection.len() > MAX_PLUGIN_TRIAGE_SOURCE_BYTES
        || ranges.len() > contract::MAX_RECORDS
        || rebases.len() > contract::MAX_RECORDS
    {
        return Err(invalid("plugin triage private loader inventory exceeds admission limits"));
    }
    let counts = [
        binary.sections.len(),
        binary.segments.len(),
        binary.symbols.len(),
        binary.imports.len(),
        binary.import_slots.len(),
        binary.exports.len(),
        binary.function_starts.len(),
        binary.slices.len(),
        binary.warnings.len(),
        binary.thumb.len(),
        binary.go_arguments.len(),
    ];
    let total = counts.into_iter().try_fold(0usize, |sum, count| sum.checked_add(count));
    if total.is_none_or(|total| total > contract::MAX_RECORDS) {
        return Err(invalid("existing loader and function metadata exceeds plugin admission limits"));
    }
    // Serialization is bounded without building a Value or cloning metadata. It also accounts for nested
    // details and Go metadata that the triage primitive clones internally. Escaped text has a conservative cap.
    serialized_preflight(binary)?;
    let mut section_bytes = 0usize;
    for section in &binary.sections {
        control.check()?;
        if let Some(bytes) = binary.section_file_bytes(section) {
            section_bytes = section_bytes.checked_add(bytes.len()).ok_or_else(|| invalid("section span overflow"))?;
            if section_bytes > MAX_PLUGIN_TRIAGE_SOURCE_BYTES {
                return Err(invalid("overlapping section scans exceed the plugin source budget"));
            }
        }
    }
    let mut scanned_bytes = 0usize;
    for segment in &binary.segments {
        control.check()?;
        if let Some(bytes) = binary.read_to_segment_end(segment.address) {
            scanned_bytes = scanned_bytes.checked_add(bytes.len()).ok_or_else(|| invalid("scan span overflow"))?;
            if scanned_bytes > MAX_PLUGIN_TRIAGE_SOURCE_BYTES {
                return Err(invalid("overlapping scan spans exceed the plugin source budget"));
            }
            segment.address.checked_add(bytes.len() as u64).ok_or_else(|| invalid("scan address overflow"))?;
        }
    }
    Ok(())
}

pub(super) fn preflight_analysis(
    project: &Project,
    analysis: &crate::project::Analysis,
    control: &ProjectWorkspaceTaskControl<'_>,
) -> Result<(), ApiError> {
    if analysis.program.functions.len() > contract::MAX_RECORDS {
        return Err(invalid("existing function metadata exceeds plugin admission limits"));
    }
    let binary = &project.binary;
    let mut body_bytes = 0usize;
    for function in &analysis.program.functions {
        control.check()?;
        let body = function
            .body(binary)
            .ok_or_else(|| invalid("complete signature search requires a backed body for every function"))?;
        body_bytes = body_bytes.checked_add(body.len()).ok_or_else(|| invalid("function span overflow"))?;
        if body_bytes > MAX_PLUGIN_TRIAGE_SOURCE_BYTES {
            return Err(invalid("function hashing spans exceed the plugin source budget"));
        }
    }
    Ok(())
}

/// Allocation-free admission for the exact printable runs the existing scanner will allocate. This does not
/// classify strings or remove code runs early: the existing primitive allocates those before filtering them.
pub(super) fn preflight_strings(project: &Project, control: &ProjectWorkspaceTaskControl<'_>) -> Result<(), ApiError> {
    let mut budget = FactBudget::default();
    for segment in &project.binary.segments {
        let Some(bytes) = project.binary.read_to_segment_end(segment.address) else { continue };
        for wide in [false, true] {
            let mut offset = 0;
            while offset < bytes.len() {
                control.check()?;
                let mut length = 0;
                if wide {
                    while offset + length * 2 + 1 < bytes.len()
                        && printable(bytes[offset + length * 2])
                        && bytes[offset + length * 2 + 1] == 0
                    {
                        length += 1;
                        if length % 4096 == 0 {
                            control.check()?;
                        }
                    }
                } else {
                    while offset + length < bytes.len() && printable(bytes[offset + length]) {
                        length += 1;
                        if length % 4096 == 0 {
                            control.check()?;
                        }
                    }
                }
                if length >= 4 {
                    budget.record()?;
                    budget.text_length(length)?;
                }
                offset += if wide && length >= 4 {
                    length * 2
                } else if wide {
                    1
                } else {
                    length.max(1)
                };
            }
        }
    }
    Ok(())
}

fn printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte) || byte == b'\t'
}

pub(super) fn serialized_preflight(value: &impl Serialize) -> Result<(), ApiError> {
    let mut writer = PreflightWriter::default();
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| invalid("existing producer metadata exceeds admission limits"))
}

#[derive(Default)]
struct PreflightWriter {
    bytes: usize,
    string_bytes: usize,
    in_string: bool,
    escaped: bool,
    containers: usize,
}

impl Write for PreflightWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self.bytes.checked_add(bytes.len()).ok_or_else(limit)?;
        if self.bytes > contract::MAX_INPUT_BYTES {
            return Err(limit());
        }
        for &byte in bytes {
            if self.in_string {
                if !self.escaped && byte == b'"' {
                    self.in_string = false;
                } else {
                    self.string_bytes += 1;
                    if self.string_bytes > contract::MAX_TEXT_BYTES {
                        return Err(limit());
                    }
                    self.escaped = !self.escaped && byte == b'\\';
                }
            } else if byte == b'"' {
                self.in_string = true;
                self.string_bytes = 0;
            } else if byte == b'{' || byte == b'[' {
                self.containers += 1;
                if self.containers > contract::MAX_RECORDS {
                    return Err(limit());
                }
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn limit() -> io::Error {
    io::Error::other("plugin triage serialization limit")
}

pub(super) fn serialize_bounded(value: &impl Serialize, max: usize) -> Result<Vec<u8>, ApiError> {
    struct BoundedBytes {
        bytes: Vec<u8>,
        max: usize,
    }
    impl Write for BoundedBytes {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.max.saturating_sub(self.bytes.len()) {
                return Err(limit());
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = BoundedBytes { bytes: Vec::new(), max };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| invalid("complete serialized plugin payload exceeds limit"))?;
    Ok(writer.bytes)
}
