#[path = "../../../tests/fixtures/pdb/support.rs"]
mod support;

use rampage_loaders::pdb::{MAX_PDB_BYTES, matched_symbols, pdb_symbols, pdb_symbols_bytes};
use rampage_loaders::{Binary, Details};
use support::{TempFiles, fixture, module_stream, rsds_offset, stream_offset, uint};

#[test]
fn real_codeview_pdb_reads_procedures_and_excludes_data() {
    let report = pdb_symbols(&fixture("fixture.pdb")).unwrap();
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    for name in ["pdb_local", "pdb_mix", "pdb_export", "pdb_entry"] {
        let functions: Vec<_> = report.functions.iter().filter(|function| function.name == name).collect();
        assert_eq!(functions.len(), 1, "{name}: {:?}", report.functions);
        assert!(functions[0].address >= 0x1000 && functions[0].address < 0x2000);
    }
    assert!(!report.functions.iter().any(|function| function.name == "pdb_value"));
}

#[test]
fn real_pe_and_pdb_identity_match_and_rvas_become_code_vas() {
    let binary = Binary::open(fixture("fixture.exe")).unwrap();
    let rvas = pdb_symbols(&fixture("fixture.pdb")).unwrap();
    let matched = matched_symbols(&binary, &fixture("fixture.pdb")).unwrap();
    let Details::Pe(details) = &binary.details else { panic!("not PE") };
    let codeview = details.codeview.as_ref().unwrap();
    let identity = rvas.identity.as_ref().unwrap();
    assert_eq!(identity.guid, codeview.guid);
    assert_eq!(identity.age, codeview.age);
    for (rva, va) in rvas.functions.iter().zip(&matched.functions) {
        assert_eq!(va.address, 0x140000000 + rva.address);
        assert!(binary.is_code(va.address));
        assert!(binary.read(va.address, 1).is_some());
    }
}

#[test]
fn real_fixture_truncation_and_hostile_headers_never_return_partial_names() {
    let bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    for length in [0, 31, 512, bytes.len() / 2, bytes.len() - 4096, bytes.len() - 1] {
        assert!(pdb_symbols_bytes(&bytes[..length]).is_err(), "accepted {length} bytes");
    }
    for offset in [32, 40, 44, 52] {
        let mut corrupt = bytes.clone();
        corrupt[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(pdb_symbols_bytes(&corrupt).is_err(), "accepted corrupt field {offset}");
    }
}

#[test]
fn oversized_and_nonregular_files_are_rejected_before_reading() {
    let files = TempFiles::new();
    let path = files.write("oversized.pdb", b"");
    std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(MAX_PDB_BYTES as u64 + 1).unwrap();
    assert!(pdb_symbols(&path).is_err());
    assert!(pdb_symbols(&fixture(".")).is_err());
}

#[test]
fn pe_guid_and_age_mismatches_missing_identity_and_va_overflow_are_rejected() {
    let bytes = std::fs::read(fixture("fixture.exe")).unwrap();
    let rsds = rsds_offset(&bytes);
    let files = TempFiles::new();
    for offset in [rsds, rsds + 4, rsds + 20] {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        let path = files.write("mismatch.exe", &corrupt);
        assert!(matched_symbols(&Binary::open(path).unwrap(), &fixture("fixture.pdb")).is_err());
    }
    let mut corrupt = bytes;
    let optional_header = uint(&corrupt, 0x3c) + 24;
    corrupt[optional_header + 24..optional_header + 32].copy_from_slice(&(u64::MAX - 15).to_le_bytes());
    let path = files.write("overflow.exe", &corrupt);
    assert!(matched_symbols(&Binary::open(path).unwrap(), &fixture("fixture.pdb")).is_err());
}

#[test]
fn conflicting_public_name_is_an_alias_and_a_late_corrupt_procedure_rejects_the_whole_pdb() {
    let bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    let globals = uint(&bytes, stream_offset(&bytes, 3, 20)) & 0xffff;
    let global_start = stream_offset(&bytes, globals, 0);
    let name = bytes[global_start..global_start + 512].windows(8).position(|name| name == b"pdb_mix\0").unwrap();
    let mut alias = bytes.clone();
    alias[global_start + name + 4] = b'f';
    // `pdb_mif` now names pdb_mix's address too: an identical-code-folding alias, not a conflict.
    let report = pdb_symbols_bytes(&alias).unwrap();
    assert!(report.functions.iter().any(|function| function.name == "pdb_mix"));
    assert!(!report.functions.iter().any(|function| function.name == "pdb_mif"));

    let module = module_stream(&bytes);
    let module_start = stream_offset(&bytes, module, 0);
    let name = bytes[module_start..module_start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
    let procedure = module_start + name - 39;
    assert_eq!(u16::from_le_bytes(bytes[procedure + 2..procedure + 4].try_into().unwrap()), 0x110f);
    let mut corrupt = bytes;
    corrupt[procedure..procedure + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(pdb_symbols_bytes(&corrupt).is_err());
}

#[test]
fn conflicting_pdb_age_rejects_even_a_readable_symbol_stream() {
    let mut bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    let age = stream_offset(&bytes, 3, 8);
    bytes[age..age + 4].copy_from_slice(&2u32.to_le_bytes());
    assert!(pdb_symbols_bytes(&bytes).is_err());
}

#[test]
fn duplicate_pe_codeview_records_are_not_resolved_by_first_match() {
    let mut bytes = std::fs::read(fixture("fixture.exe")).unwrap();
    let pe = object::read::pe::PeFile64::parse(bytes.as_slice()).unwrap();
    let directory = pe.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_DEBUG).unwrap();
    let records = directory.data(pe.data(), &pe.section_table()).unwrap();
    assert_eq!(records.len(), 28);
    let start = records.as_ptr() as usize - bytes.as_ptr() as usize;
    let mut first = records.to_vec();
    let length = uint(&first, 16);
    let original = uint(&first, 24);
    let info = bytes[original..original + length].to_vec();
    let rva = uint(&first, 20) - (original - start);
    first[20..24].copy_from_slice(&((rva + 256) as u32).to_le_bytes());
    first[24..28].copy_from_slice(&((start + 256) as u32).to_le_bytes());
    bytes[start + 256..start + 256 + length].copy_from_slice(&info);
    bytes[start..start + 28].copy_from_slice(&first);
    bytes[start + 28..start + 56].copy_from_slice(&first);
    let nt = uint(&bytes, 0x3c);
    let optional = nt + 24;
    let debug_size = optional + 112 + 6 * 8 + 4;
    bytes[debug_size..debug_size + 4].copy_from_slice(&56u32.to_le_bytes());
    let optional_size = u16::from_le_bytes(bytes[nt + 20..nt + 22].try_into().unwrap()) as usize;
    let rdata_virtual_size = optional + optional_size + 40 + 8;
    bytes[rdata_virtual_size..rdata_virtual_size + 4].copy_from_slice(&512u32.to_le_bytes());
    let files = TempFiles::new();
    let path = files.write("duplicate.exe", &bytes);
    let binary = Binary::open(path).unwrap();
    let error = matched_symbols(&binary, &fixture("fixture.pdb")).unwrap_err();
    assert!(error.to_string().contains("ambiguous PE CodeView identity"), "{error}");
}

#[test]
fn a_real_procedure_relocated_into_data_is_never_an_importable_function() {
    let mut bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    let module_start = stream_offset(&bytes, module_stream(&bytes), 0);
    let name = bytes[module_start..module_start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
    let procedure = module_start + name - 39;
    bytes[procedure + 32..procedure + 36].copy_from_slice(&0u32.to_le_bytes());
    bytes[procedure + 36..procedure + 38].copy_from_slice(&3u16.to_le_bytes());
    let files = TempFiles::new();
    let path = files.write("data-function.pdb", &bytes);
    let read = pdb_symbols(&path).unwrap();
    assert!(read.functions.iter().any(|function| function.name == "pdb_local" && function.address == 0x3000));
    let binary = Binary::open(fixture("fixture.exe")).unwrap();
    assert!(matched_symbols(&binary, &path).is_err());
}

#[test]
fn corrupt_real_fixture_section_offset_overflow_is_rejected_without_panic_or_wrap() {
    let bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    let corrupt = support::corrupt_local_offset(&bytes, 3, 0xffffe020);
    let error = pdb_symbols_bytes(&corrupt).unwrap_err();
    assert!(error.to_string().contains("section RVA plus offset overflows"), "{error}");
    let files = TempFiles::new();
    let path = files.write("corrupt-wrapping-offset.pdb", &corrupt);
    assert!(matched_symbols(&Binary::open(fixture("fixture.exe")).unwrap(), &path).is_err());
}

#[test]
fn corrupt_pe_code_classification_without_execute_or_read_permission_is_rejected() {
    let bytes = std::fs::read(fixture("fixture.exe")).unwrap();
    let files = TempFiles::new();
    for permission in [0x20000000, 0x40000000] {
        let path = files.write("corrupt-permissions.exe", &support::corrupt_text_permissions(&bytes, permission));
        let binary = Binary::open(path).unwrap();
        assert!(binary.is_code(0x140001020));
        let error = matched_symbols(&binary, &fixture("fixture.pdb")).unwrap_err();
        assert!(error.to_string().contains("readable, executable"), "{error}");
    }
}

#[test]
fn corrupt_multi_gib_stream_is_rejected_before_dependency_page_list_allocation() {
    let bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    let corrupt = support::corrupt_aliased_msf(&bytes, &[3 * 1024 * 1024 * 1024], 4096, MAX_PDB_BYTES - 4096);
    assert!(corrupt.len() < MAX_PDB_BYTES);
    let error = pdb_symbols_bytes(&corrupt).unwrap_err();
    assert!(error.to_string().contains("MSF stream size exceeds limit"), "{error}");
}

#[test]
fn corrupt_256_byte_page_aliases_are_rejected_before_dependency_slice_vector_allocation() {
    let bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    let corrupt = support::corrupt_aliased_msf(&bytes, &[512 * 1024 * 1024], 256, MAX_PDB_BYTES - 256);
    assert!(corrupt.len() < MAX_PDB_BYTES);
    let error = pdb_symbols_bytes(&corrupt).unwrap_err();
    assert!(error.to_string().contains("MSF directory exceeds size limit"), "{error}");
}

#[test]
fn corrupt_small_stream_padding_cannot_bypass_the_total_page_reference_budget() {
    let bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    let mut sizes = vec![1; 1001];
    sizes[0] = MAX_PDB_BYTES as u32 - 1000;
    let corrupt = support::corrupt_aliased_msf(&bytes, &sizes, 256, 0);
    let error = pdb_symbols_bytes(&corrupt).unwrap_err();
    assert!(error.to_string().contains("MSF page-reference count exceeds limit"), "{error}");
}

#[test]
fn corrupt_align_and_skip_records_in_modules_and_globals_all_count_toward_the_raw_record_limit() {
    let bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    for module in [false, true] {
        for kind in [0x0007, 0x0402] {
            let corrupt = support::corrupt_skipped_symbols(&bytes, module, kind, 1_000_001);
            let error = pdb_symbols_bytes(&corrupt).unwrap_err();
            assert!(error.to_string().contains("raw symbol record count exceeds limit"), "{module}/{kind}: {error}");
        }
    }
}

#[test]
fn corrupt_real_fixture_omap_streams_are_explicitly_unsupported() {
    let original = std::fs::read(fixture("fixture.pdb")).unwrap();
    let dbi = stream_offset(&original, 3, 0);
    let mut extra = 64;
    for offset in [24, 28, 32, 36, 40, 52] {
        extra += uint(&original, dbi + offset);
    }
    for index in [3, 4, 10] {
        let mut corrupt = original.clone();
        let at = stream_offset(&original, 3, extra + index * 2);
        corrupt[at..at + 2].copy_from_slice(&1u16.to_le_bytes());
        let error = pdb_symbols_bytes(&corrupt).unwrap_err();
        assert!(matches!(error, rampage_loaders::LoadError::Unsupported(_)), "{error}");
        assert!(error.to_string().contains("OMAP/original-section address translation"), "{error}");
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn fifo_and_final_component_symlinks_are_rejected_without_waiting_for_a_writer() {
    let files = TempFiles::new();
    let fifo = files.fifo("corrupt-fifo.pdb");
    let error = pdb_symbols(&fifo).unwrap_err();
    assert!(error.to_string().contains("requires a regular file"), "{error}");
    let link = files.write("corrupt-link.pdb", b"");
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&fifo, &link).unwrap();
    assert!(matches!(pdb_symbols(&link), Err(rampage_loaders::LoadError::Io { .. })));
}

#[test]
fn corrupt_repeated_high_index_module_lookups_exhaust_preflight_work_before_dependency_traversal() {
    let original = std::fs::read(fixture("fixture.pdb")).unwrap();
    let corrupt = support::corrupt_module_lookup_work(&original);
    let error = pdb_symbols_bytes(&corrupt).unwrap_err();
    assert!(error.to_string().contains("structural work budget exceeded"), "{error}");
}

#[test]
fn corrupt_real_fixture_constant_numeric_prefix_rejects_the_whole_report_in_every_profile() {
    let original = std::fs::read(fixture("fixture.pdb")).unwrap();
    let corrupt = support::corrupt_local_constant_numeric_prefix(&original, 0x1107, 0xffff);
    assert_eq!(original.len(), corrupt.len());
    assert_eq!(&original[..64], &corrupt[..64]);
    let identity = stream_offset(&original, 1, 0);
    assert_eq!(&original[identity..identity + 28], &corrupt[identity..identity + 28]);
    let error = pdb_symbols_bytes(&corrupt).unwrap_err();
    assert!(error.to_string().contains("unsupported constant numeric prefix 0xffff"), "{error}");
    let files = TempFiles::new();
    let path = files.write("corrupt-constant-prefix.pdb", &corrupt);
    assert!(matched_symbols(&Binary::open(fixture("fixture.exe")).unwrap(), &path).is_err());
}

#[test]
fn corrupt_supported_constant_with_missing_name_still_rejects_the_whole_report() {
    let original = std::fs::read(fixture("fixture.pdb")).unwrap();
    let mut corrupt = support::corrupt_local_constant_numeric_prefix(&original, 0x1107, 0x800a);
    let start = stream_offset(&original, module_stream(&original), 0);
    let name = original[start..start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
    let record = start + name - 39;
    let length = u16::from_le_bytes(original[record..record + 2].try_into().unwrap()) as usize;
    corrupt[record + 18..record + 2 + length].fill(0xff);
    let error = pdb_symbols_bytes(&corrupt).unwrap_err();
    assert!(matches!(error, rampage_loaders::LoadError::Malformed(_)), "{error}");
    assert!(!error.to_string().contains("unsupported constant numeric prefix"), "{error}");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod checked {
    use super::*;
    use rampage_loaders::pdb::matched_symbols_checked;

    #[test]
    fn checked_matching_hashes_the_owned_fixture_buffer_and_returns_checked_code_vas() {
        let binary = Binary::open(fixture("fixture.exe")).unwrap();
        let (report, provenance) = matched_symbols_checked(&binary, &fixture("fixture.pdb")).unwrap();
        assert!(report.functions.iter().any(|function| function.address == 0x140001000 && function.name == "pdb_mix"));
        assert!(
            report.functions.iter().any(|function| function.address == 0x140001020 && function.name == "pdb_local")
        );
        assert_eq!(
            rampage_arch::hex::bytes(provenance.sha256()),
            "618b154d83ecd8e0ec08056913371116e193d9d00569be07b6615183c9b3d644"
        );
        assert_eq!(provenance.path(), std::path::absolute(fixture("fixture.pdb")).unwrap());
        provenance.validate_current().unwrap();
    }

    #[test]
    fn current_bytes_and_provenance_are_both_required_even_when_pdb_guid_and_age_still_match() {
        let binary = Binary::open(fixture("fixture.exe")).unwrap();
        let original = std::fs::read(fixture("fixture.pdb")).unwrap();
        for replacement in [false, true] {
            let files = TempFiles::new();
            let path = files.write("selected.pdb", &original);
            let (report, provenance) = matched_symbols_checked(&binary, &path).unwrap();
            if replacement {
                std::fs::rename(files.write("replacement.pdb", &original), &path).unwrap();
            } else {
                let mut changed = original.clone();
                let start = stream_offset(&original, module_stream(&original), 0);
                let name = original[start..start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
                changed[start + name..start + name + 10].copy_from_slice(b"new_local\0");
                std::fs::write(&path, changed).unwrap();
            }
            let (current, current_provenance) = matched_symbols_checked(&binary, &path).unwrap();
            assert_eq!(report.identity, current.identity);
            if replacement {
                assert_eq!(provenance.sha256(), current_provenance.sha256());
            } else {
                assert!(current.functions.iter().any(|function| function.name == "new_local"));
                assert_ne!(provenance.sha256(), current_provenance.sha256());
            }
            let error = provenance.validate_current().unwrap_err();
            assert!(error.to_string().contains("bytes or provenance changed"), "{error}");
            assert!(report.functions.iter().any(|function| function.name == "pdb_local"));
        }
    }

    #[test]
    fn checked_matching_refuses_modified_replaced_and_truncated_original_maps_before_parsing() {
        let original = std::fs::read(fixture("fixture.exe")).unwrap();
        for mutation in ["overwrite", "replace", "truncate"] {
            let files = TempFiles::new();
            let path = files.write("selected.exe", &original);
            let binary = Binary::open(&path).unwrap();
            match mutation {
                "overwrite" => {
                    let mut changed = original.clone();
                    changed[0x400] ^= 1;
                    std::fs::write(&path, changed).unwrap();
                }
                "replace" => std::fs::rename(files.write("replacement.exe", &original), &path).unwrap(),
                "truncate" => {
                    std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(1).unwrap();
                }
                _ => unreachable!(),
            }
            let error = matched_symbols_checked(&binary, &fixture("fixture.pdb")).unwrap_err();
            assert!(error.to_string().contains("backing file was modified or replaced"), "{mutation}: {error}");
        }
    }

    #[test]
    fn checked_matching_reuses_numeric_record_and_code_address_guards() {
        let files = TempFiles::new();
        let binary = Binary::open(fixture("fixture.exe")).unwrap();
        let original = std::fs::read(fixture("fixture.pdb")).unwrap();
        let corrupt = support::corrupt_local_constant_numeric_prefix(&original, 0x1107, 0xffff);
        let path = files.write("numeric.pdb", &corrupt);
        let error = matched_symbols_checked(&binary, &path).unwrap_err();
        assert!(error.to_string().contains("unsupported constant numeric prefix"), "{error}");
        let corrupt = support::corrupt_local_offset(&original, 3, 0);
        let path = files.write("data.pdb", &corrupt);
        let error = matched_symbols_checked(&binary, &path).unwrap_err();
        assert!(error.to_string().contains("readable, executable"), "{error}");
    }

    #[test]
    fn checked_matching_resolves_selected_embedded_pe_rvas_not_outer_file_offsets() {
        let files = TempFiles::new();
        let image = std::fs::read(fixture("fixture.exe")).unwrap();
        let mut outer = vec![b'x'; 1001];
        outer.extend_from_slice(&image);
        outer.extend_from_slice(b"not part of the selected image");
        let path = files.write("embedded.bin", &outer);
        let binary = Binary::open_at(&path, 1001, Some(image.len() as u64)).unwrap();
        let (report, provenance) = matched_symbols_checked(&binary, &fixture("fixture.pdb")).unwrap();
        assert!(report.functions.iter().any(|function| function.address == 0x140001000 && function.name == "pdb_mix"));
        provenance.validate_current().unwrap();
    }
}
