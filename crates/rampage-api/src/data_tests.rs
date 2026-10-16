use rampage_loaders::{Binary, Format, Section, SectionKind};
use serde_json::json;

use super::*;

fn native(big_endian: bool) -> Binary {
    let words = if big_endian { "00000000000020000000000000003000" } else { "00200000000000000030000000000000" };
    let mut binary = Binary::from_snapshot_bytes(
        serde_json::to_vec(&json!({
            "format": "rampage-snapshot-v1", "arch": "aarch64", "big_endian": big_endian,
            "provenance": "owned synthetic data inspection fixture",
            "regions": [
                { "name": "words", "address": "0x1000", "permissions": "rw-",
                  "bytes": words },
                { "name": "text", "address": "0x2000", "permissions": "r-x", "bytes": "c0035fd6" },
                { "name": "name", "address": "0x3000", "permissions": "r--", "bytes": "6f776e65645f626c6f636b00" },
            ],
        }))
        .unwrap(),
    )
    .unwrap();
    binary.format = Format::Elf;
    binary.big_endian = big_endian;
    binary.function_starts.push(0x2000);
    binary
}

fn inspect(binary: Binary, address: u64, size: usize) -> DataInspection {
    Project::new(binary).inspect_data(&DataQuery { address, size, word_size: None }).unwrap()
}

#[test]
fn data_words_link_code_and_strings_without_analysis_or_pointer_promotion() {
    for big_endian in [false, true] {
        let project = Project::new(native(big_endian));
        let report = project.inspect_data(&DataQuery { address: 0x1000, size: 16, word_size: None }).unwrap();
        assert!(!project.analysis_cache_status().program);
        assert_eq!(report.words[0].raw_value, Some(0x2000));
        assert_eq!(report.words[0].interpretation, "raw_word_candidate");
        let target = report.words[0].candidate.as_ref().unwrap();
        assert!(target.code_range && target.declared_function_start);
        let target = report.words[1].candidate.as_ref().unwrap();
        assert_eq!(target.ascii_preview.as_deref(), Some("owned_block"));
        assert!(target.ascii_terminated);
        assert!(!target.code_range);
        assert_eq!(report.spans[0].status, DataStatus::Stored);
        assert_eq!(report.spans[0].image_offset, Some(0));
        assert!(!report.backing_metadata_checked);
        assert!(!report.pointer_targets_suppressed);
        assert_eq!(report.loader_diagnostics.warnings_total, 0);
        assert_eq!(report.loader_diagnostics.warnings_omitted, 0);
        assert!(!report.loader_diagnostics.truncated);
        assert!(report.loader_diagnostics.warnings.is_empty());
        assert!(serde_json::to_vec(&report).unwrap().len() <= MAX_DATA_RESULT_BYTES);
    }
}

#[test]
fn gaps_zero_fill_unreadable_and_missing_backing_never_supply_zero_words() {
    let mut binary = native(false);
    binary.segments[0].size = 24;
    let report = inspect(binary, 0x1008, 24);
    assert_eq!(
        report.spans.iter().map(|span| span.status).collect::<Vec<_>>(),
        [DataStatus::Stored, DataStatus::ZeroFill, DataStatus::Unmapped]
    );
    assert!(report.spans[1].hex.is_none());
    assert!(report.words[1].raw_value.is_none() && report.words[2].raw_value.is_none());

    let mut binary = native(false);
    binary.format = Format::MachO;
    binary.sections.push(Section {
        name: "declared_bss".into(),
        address: 0x1000,
        size: 8,
        kind: SectionKind::UninitializedData,
        file_offset: None,
        file_size: 0,
    });
    assert_eq!(inspect(binary, 0x1000, 8).spans[0].status, DataStatus::ZeroFill);

    let mut binary = native(false);
    binary.segments[0].perms.read = false;
    let report = inspect(binary, 0x1000, 8);
    assert_eq!(report.spans[0].status, DataStatus::Unreadable);
    assert!(report.words[0].raw_value.is_none());

    let mut binary = native(false);
    binary.segments[0].file_offset = 1_000_000;
    let report = inspect(binary, 0x1000, 8);
    assert_eq!(report.spans[0].status, DataStatus::Unavailable);
    assert!(report.words[0].raw_value.is_none());
}

#[test]
fn native_data_preflight_rejects_ambiguous_ranges_and_capture_context() {
    for query in [
        DataQuery { address: 0x1000, size: 0, word_size: None },
        DataQuery { address: 0x1000, size: MAX_DATA_BYTES + 1, word_size: None },
        DataQuery { address: u64::MAX, size: 8, word_size: None },
        DataQuery { address: 0x1000, size: 8, word_size: Some(3) },
    ] {
        assert!(Project::new(native(false)).inspect_data(&query).is_err());
    }
    let query = DataQuery { address: 0x1000, size: 8, word_size: None };
    let mut binary = native(false);
    binary.segments.push(binary.segments[0].clone());
    assert!(Project::new(binary).inspect_data(&query).is_err());
    let mut binary = native(false);
    binary.format = Format::Snapshot;
    assert!(Project::new(binary).inspect_data(&query).is_err());
    let mut binary = native(false);
    binary.arch = Arch::X86;
    assert!(Project::new(binary).inspect_data(&DataQuery { address: 0xffff_fffc, size: 8, word_size: None }).is_err());
}

#[test]
fn import_bindings_do_not_present_raw_loader_words_as_function_targets() {
    let mut binary = native(false);
    binary.import_slots.push(rampage_loaders::ImportSlot { address: 0x1000, name: "external".into(), library: None });
    let report = inspect(binary, 0x1000, 9);
    assert_eq!(report.words[0].interpretation, "import_binding");
    assert_eq!(report.words[0].import.as_ref().unwrap().name, "external");
    assert!(report.words[0].candidate.is_none());
    assert_eq!(report.trailing_bytes, 1);
}

#[test]
#[ignore = "requires an explicitly centrally compiled owned data-navigation dylib via RAMPAGE_DATA_FIXTURE"]
fn compiled_stripped_descriptor_links_have_independent_source_ground_truth() {
    let path = std::env::var_os("RAMPAGE_DATA_FIXTURE").expect("set RAMPAGE_DATA_FIXTURE to the owned dylib");
    let project = Project::new(Binary::open(path).unwrap());
    let table = project.resolve("_owned_blocks").unwrap();
    let size = usize::from(project.binary.arch.pointer_size());
    let report = project.inspect_data(&DataQuery { address: table, size, word_size: None }).unwrap();
    let descriptor = report.words[0].candidate.as_ref().unwrap();
    assert!(!descriptor.code_range);
    let fields =
        project.inspect_data(&DataQuery { address: descriptor.address, size: size * 4, word_size: None }).unwrap();
    assert_eq!(fields.words[0].candidate.as_ref().unwrap().ascii_preview.as_deref(), Some("owned_gain"));
    for callback in &fields.words[1..] {
        let target = callback.candidate.as_ref().unwrap();
        assert!(target.code_range && target.permissions.execute);
        assert_ne!(callback.interpretation, "import_binding");
    }
    if project.binary.has_chained_fixups() {
        assert_eq!(report.words[0].interpretation, "macho_chained_rebase");
        assert!(fields.words.iter().all(|word| word.interpretation == "macho_chained_rebase"));
        assert!(
            fields.words.iter().any(|word| { word.raw_value != word.candidate.as_ref().map(|target| target.address) })
        );
        for offset in [0, 4] {
            let part = inspect_native_data(
                &project.binary,
                &DataQuery { address: descriptor.address + offset, size: 4, word_size: Some(4) },
            )
            .unwrap();
            assert_eq!(part.words[0].interpretation, "partial_pointer_metadata");
            assert!(part.words[0].candidate.is_none());
        }
    }
}

#[test]
fn imports_preserve_library_identity_and_partial_slots_cannot_suggest_targets() {
    let mut binary = native(false);
    binary.import_slots = ["first.dll", "second.dll"]
        .into_iter()
        .enumerate()
        .map(|(index, library)| rampage_loaders::ImportSlot {
            address: 0x1000 + index as u64 * 8,
            name: "#7".into(),
            library: Some(library.into()),
        })
        .collect();
    let report = inspect_native_data(&binary, &DataQuery { address: 0x1000, size: 16, word_size: None }).unwrap();
    assert_eq!(report.words[0].import.as_ref().unwrap().library.as_deref(), Some("first.dll"));
    assert_eq!(report.words[1].import.as_ref().unwrap().library.as_deref(), Some("second.dll"));
    let report = inspect_native_data(&binary, &DataQuery { address: 0x1000, size: 8, word_size: Some(4) }).unwrap();
    for word in report.words {
        assert_eq!(word.interpretation, "partial_pointer_metadata");
        assert!(word.raw_value.is_some() && word.candidate.is_none());
    }
}

#[test]
fn any_loader_warning_suppresses_all_targets_but_preserves_bytes_words_and_import_identity() {
    for warning in [
        "import slots unreadable: owned malformed table",
        "chained fixup rebases unreadable: owned malformed chain",
        "an arbitrary diagnostic with no recognized prefix",
        "",
    ] {
        let mut binary = native(false);
        binary.warnings.push(warning.into());
        binary.import_slots.push(rampage_loaders::ImportSlot {
            address: 0x1000,
            name: "retained_external".into(),
            library: Some("owned.dylib".into()),
        });
        for word_size in [4, 8] {
            let report =
                inspect_native_data(&binary, &DataQuery { address: 0x1000, size: 16, word_size: Some(word_size) })
                    .unwrap();
            assert!(report.pointer_targets_suppressed);
            assert!(report.words.iter().all(|word| {
                word.candidate.is_none() && word.interpretation == "loader_warnings_pointer_targets_suppressed"
            }));
            assert_eq!(report.words[0].raw_value, Some(0x2000));
            assert!(report.spans[0].hex.is_some());
            let import = report.words[0].import.as_ref().unwrap();
            assert_eq!(import.name, "retained_external");
            assert_eq!(import.library.as_deref(), Some("owned.dylib"));
            let diagnostics = &report.loader_diagnostics;
            assert_eq!(diagnostics.warnings_total, 1);
            assert_eq!(diagnostics.warnings_omitted, 0);
            assert!(!diagnostics.truncated);
            assert_eq!(diagnostics.warnings[0].message, warning);
            assert!(!diagnostics.warnings[0].text_truncated);
            let json = serde_json::to_value(&report).unwrap();
            assert_eq!(json["loader_diagnostics"]["warnings_total"], 1);
            assert_eq!(json["loader_diagnostics"]["warnings"][0]["message"], warning);
            assert!(json["words"].as_array().unwrap().iter().all(|word| word["candidate"].is_null()));
        }
        let report = inspect_native_data(&binary, &DataQuery { address: 0x4000, size: 8, word_size: None }).unwrap();
        assert_eq!(report.words[0].interpretation, "unavailable");
        assert!(report.pointer_targets_suppressed && report.words[0].raw_value.is_none());
    }
}

#[test]
fn loader_diagnostic_count_and_utf8_text_caps_report_exact_display_truncation() {
    let mut binary = native(false);
    binary.warnings = (0..MAX_LOADER_WARNINGS + 5).map(|index| format!("owned warning {index}")).collect();
    let report = inspect_native_data(&binary, &DataQuery { address: 0x1000, size: 8, word_size: None }).unwrap();
    let diagnostics = &report.loader_diagnostics;
    assert_eq!(diagnostics.warnings_total, MAX_LOADER_WARNINGS + 5);
    assert_eq!(diagnostics.warnings.len(), MAX_LOADER_WARNINGS);
    assert_eq!(diagnostics.warnings_omitted, 5);
    assert!(diagnostics.truncated);
    assert!(diagnostics.warnings.iter().all(|warning| !warning.text_truncated));

    let long = format!("{}{}", "a".repeat(MAX_LOADER_WARNING_BYTES - 1), "\u{20000}".repeat(100));
    binary.warnings = vec![long; MAX_LOADER_WARNINGS + 10];
    let report = inspect_native_data(&binary, &DataQuery { address: 0x1000, size: 8, word_size: None }).unwrap();
    let diagnostics = &report.loader_diagnostics;
    assert_eq!(diagnostics.warnings_total, binary.warnings.len());
    assert_eq!(diagnostics.warnings_omitted, binary.warnings.len() - diagnostics.warnings.len());
    assert!(diagnostics.truncated && diagnostics.warnings_omitted > 0);
    assert_eq!(diagnostics.warnings[0].message, "a".repeat(MAX_LOADER_WARNING_BYTES - 1));
    assert!(
        diagnostics
            .warnings
            .iter()
            .all(|warning| { warning.text_truncated && warning.message.len() <= MAX_LOADER_WARNING_BYTES })
    );
    assert!(
        diagnostics.warnings.iter().map(|warning| warning.message.len()).sum::<usize>()
            <= MAX_LOADER_DIAGNOSTIC_TEXT_BYTES
    );
    assert!(serde_json::to_vec(&report).unwrap().len() <= MAX_DATA_RESULT_BYTES);
    assert!(report.pointer_targets_suppressed && report.words[0].candidate.is_none());
}

fn owned_chained_macho(next: Option<u16>) -> Vec<u8> {
    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn put16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    let mut bytes = vec![0; 0x400];
    put32(&mut bytes, 0, 0xfeed_facf);
    put32(&mut bytes, 4, 0x0100_000c);
    put32(&mut bytes, 12, 6);
    put32(&mut bytes, 16, 2);
    put32(&mut bytes, 20, 88);
    put32(&mut bytes, 32, 0x19);
    put32(&mut bytes, 36, 72);
    bytes[40..46].copy_from_slice(b"__TEXT");
    put64(&mut bytes, 56, 0x1000);
    put64(&mut bytes, 64, 0x400);
    put64(&mut bytes, 80, 0x400);
    put32(&mut bytes, 88, 7);
    put32(&mut bytes, 92, 5);
    put32(&mut bytes, 104, 0x8000_0034);
    put32(&mut bytes, 108, 16);
    put32(&mut bytes, 112, if next.is_some() { 0x300 } else { 0x800 });
    put32(&mut bytes, 116, 64);
    put64(&mut bytes, 0x100, 0x1200 | (u64::from(next.unwrap_or(0)) << 51));
    put64(&mut bytes, 0x108, 0x1200);
    bytes[0x200..0x206].copy_from_slice(b"owned\0");

    // One DYLD_CHAINED_PTR_64 rebase; a nonzero next value can walk outside the stored segment.
    put32(&mut bytes, 0x304, 28);
    put32(&mut bytes, 0x308, 64);
    put32(&mut bytes, 0x30c, 64);
    put32(&mut bytes, 0x314, 1);
    put32(&mut bytes, 0x31c, 1);
    put32(&mut bytes, 0x320, 8);
    put32(&mut bytes, 0x324, 24);
    put16(&mut bytes, 0x328, 0x1000);
    put16(&mut bytes, 0x32a, 2);
    put16(&mut bytes, 0x338, 1);
    put16(&mut bytes, 0x33a, 0x100);
    bytes
}

struct OwnedMachoSource(std::path::PathBuf);

impl OwnedMachoSource {
    fn new(bytes: &[u8]) -> Self {
        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-owned-data-fixups-{}-{}.macho",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        let source = Self(path);
        file.write_all(bytes).unwrap();
        source
    }
}

impl Drop for OwnedMachoSource {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn actual_loader_malformed_fixups_never_link_native_words_or_partial_width_fragments() {
    for next in [None, Some(0x0fff)] {
        let source = OwnedMachoSource::new(&owned_chained_macho(next));
        let binary = Binary::open_image_metadata(&source.0, None, None).unwrap();
        assert_eq!(binary.format, Format::MachO);
        for expected in ["import slots unreadable", "chained fixup rebases unreadable"] {
            assert!(binary.warnings.iter().any(|warning| warning.contains(expected)), "{:?}", binary.warnings);
        }
        assert!(binary.import_slots.is_empty());
        assert_eq!(binary.rebase_target(0x1100), next.map(|_| 0x1200));
        for word_size in [4, 8] {
            let report =
                inspect_native_data(&binary, &DataQuery { address: 0x1100, size: 16, word_size: Some(word_size) })
                    .unwrap();
            assert!(report.pointer_targets_suppressed);
            assert_eq!(report.loader_diagnostics.warnings_total, binary.warnings.len());
            assert_eq!(report.loader_diagnostics.warnings_omitted, 0);
            assert!(!report.loader_diagnostics.truncated);
            for (shown, original) in report.loader_diagnostics.warnings.iter().zip(&binary.warnings) {
                assert_eq!(&shown.message, original);
            }
            assert!(report.words.iter().all(|word| {
                word.raw_value.is_some()
                    && word.candidate.is_none()
                    && word.interpretation == "loader_warnings_pointer_targets_suppressed"
            }));
            assert_eq!(report.spans[0].status, DataStatus::Stored);
            if word_size == 4 {
                assert_eq!(report.words[0].raw_value, Some(0x1200));
                assert_eq!(report.words[2].raw_value, Some(0x1200));
            }
        }
    }
}

#[test]
fn actual_loader_warning_free_fixups_and_raw_candidates_keep_their_interpretations() {
    let source = OwnedMachoSource::new(&owned_chained_macho(Some(0)));
    let binary = Binary::open_image_metadata(&source.0, None, None).unwrap();
    assert!(binary.warnings.is_empty(), "{:?}", binary.warnings);
    let report = inspect_native_data(&binary, &DataQuery { address: 0x1100, size: 16, word_size: None }).unwrap();
    assert!(!report.pointer_targets_suppressed);
    assert_eq!(report.words[0].interpretation, "macho_chained_rebase");
    assert_eq!(report.words[1].interpretation, "raw_word_candidate");
    assert!(report.words.iter().all(|word| word.candidate.as_ref().unwrap().address == 0x1200));
    let report = inspect_native_data(&binary, &DataQuery { address: 0x1100, size: 16, word_size: Some(4) }).unwrap();
    for word in &report.words[..2] {
        assert_eq!(word.interpretation, "partial_pointer_metadata");
        assert!(word.candidate.is_none());
    }
    assert_eq!(report.words[2].interpretation, "raw_word_candidate");
    assert_eq!(report.words[2].candidate.as_ref().unwrap().address, 0x1200);
}

#[test]
fn lightweight_resolution_checks_metadata_before_indexes_and_refuses_ambiguous_names() {
    let mut binary = native(false);
    for address in [0x2000, 0x3000] {
        binary.exports.push(rampage_loaders::Export { address, name: "same_name".into() });
    }
    assert!(resolve_data_address(&binary, "same_name").unwrap_err().to_string().contains("ambiguous"));
    assert_eq!(resolve_data_address(&binary, "0x2000").unwrap(), 0x2000);
    binary.exports.push(rampage_loaders::Export { address: 0x3000, name: "sub_2000".into() });
    assert_eq!(resolve_data_address(&binary, "sub_2000").unwrap(), 0x3000);
    binary.exports.push(rampage_loaders::Export { address: 0x2000, name: "sub_2000".into() });
    assert!(resolve_data_address(&binary, "sub_2000").unwrap_err().to_string().contains("ambiguous"));
    binary.function_starts = vec![0x2000; MAX_METADATA + 1];
    assert!(resolve_data_address(&binary, "0x2000").unwrap_err().to_string().contains("metadata budget"));
}

#[test]
fn repeated_target_labels_cannot_truncate_the_json_result() {
    let mut binary = Binary::from_snapshot_bytes(
        serde_json::to_vec(&json!({
            "format": "rampage-snapshot-v1", "arch": "aarch64", "provenance": "owned output bound fixture",
            "regions": [
                { "name": "words", "address": "0x1000", "permissions": "r--", "bytes": "0020000000000000".repeat(128) },
                { "name": "text", "address": "0x2000", "permissions": "r-x", "bytes": "c0035fd6" },
            ],
        }))
        .unwrap(),
    )
    .unwrap();
    binary.format = Format::Elf;
    for _ in 0..2 {
        binary.exports.push(rampage_loaders::Export { address: 0x2000, name: "\u{20000}".repeat(100) });
    }
    let error = inspect_native_data(&binary, &DataQuery { address: 0x1000, size: MAX_DATA_BYTES, word_size: None })
        .unwrap_err();
    assert!(error.to_string().contains("smaller size"));
    let report = inspect_native_data(&binary, &DataQuery { address: 0x1000, size: 8, word_size: None }).unwrap();
    assert!(report.words[0].candidate.as_ref().unwrap().labels[0].ends_with("[display truncated]"));
}

#[test]
fn thumb_callback_tags_require_declared_mode_and_do_not_change_data_addresses() {
    let mut binary = Binary::from_snapshot_bytes(
        serde_json::to_vec(&json!({
            "format": "rampage-snapshot-v1", "arch": "arm", "provenance": "owned Thumb callback fixture",
            "regions": [
                { "name": "words", "address": "0x1000", "permissions": "r--", "bytes": "0120000001300000" },
                { "name": "text", "address": "0x2000", "permissions": "r-x", "bytes": "7047", "thumb": true },
                { "name": "name", "address": "0x3000", "permissions": "r--", "bytes": "6f776e65645f626c6f636b00" },
            ],
        }))
        .unwrap(),
    )
    .unwrap();
    binary.format = Format::Elf;
    binary.symbols.push(rampage_loaders::Symbol {
        address: 0x2000,
        name: "callback".into(),
        size: 2,
        kind: SymbolKind::Function,
    });
    let report = inspect_native_data(&binary, &DataQuery { address: 0x1000, size: 8, word_size: None }).unwrap();
    assert_eq!(report.words[0].raw_value, Some(0x2001));
    let target = report.words[0].candidate.as_ref().unwrap();
    assert_eq!(target.address, 0x2000);
    assert_eq!(target.address_adjustment, Some("thumb_bit_with_declared_mode"));
    assert!(target.declared_function_start);
    assert_eq!(target.labels, ["callback"]);
    let target = report.words[1].candidate.as_ref().unwrap();
    assert_eq!(target.address, 0x3001);
    assert!(target.address_adjustment.is_none());
}

#[test]
#[ignore = "requires a centrally compiled ELF with TLS and init_array via RAMPAGE_DATA_FIXTURE"]
fn native_elf_tls_nobits_overlap_does_not_hide_stored_initializers() {
    let path = std::env::var_os("RAMPAGE_DATA_FIXTURE").expect("set RAMPAGE_DATA_FIXTURE to the owned ELF");
    let binary = Binary::open(path).unwrap();
    assert_eq!(binary.format, Format::Elf);
    let tls = binary.sections.iter().find(|section| section.name == ".tbss").unwrap();
    let init = binary.sections.iter().find(|section| section.name == ".init_array").unwrap();
    assert!(tls.address <= init.address && init.address < tls.address + tls.size);
    let report = inspect_native_data(&binary, &DataQuery { address: init.address, size: 8, word_size: None }).unwrap();
    assert_eq!(report.spans[0].status, DataStatus::Stored);
    let expected = rampage_arch::hex::bytes(binary.read(init.address, 8).unwrap());
    assert_eq!(report.spans[0].hex.as_deref(), Some(expected.as_str()));
}
