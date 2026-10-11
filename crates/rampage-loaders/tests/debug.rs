use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use object::{Object, ObjectSection};

use rampage_loaders::Binary;

use rampage_loaders::debug;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn check_signatures(name: &str, symbol_prefix: &str) {
    let binary = Binary::open(fixture(name)).unwrap();
    let report = debug::signatures(&binary).unwrap();
    let expected = [
        ("debug_mix", "uint64_t debug_mix(uint64_t total, char * message, int32_t delta, double ratio);"),
        (
            "debug_scalars",
            "bool debug_scalars(int8_t small, uint8_t byte, int16_t half, uint32_t word, float fraction);",
        ),
        ("debug_variadic", "int32_t debug_variadic(char * format, ...);"),
        ("main", "int32_t main(void);"),
    ];
    for (name, declaration) in expected {
        let signature = report
            .signatures
            .iter()
            .find(|signature| signature.name == name)
            .unwrap_or_else(|| panic!("missing {name}: {report:?}"));
        let symbol = binary.symbol_by_name(&format!("{symbol_prefix}{name}")).unwrap();
        assert_eq!(signature.address, symbol.address, "{name}");
        assert_eq!(signature.declaration, declaration);
    }
    for unsupported in [
        "debug_reset",
        "debug_aggregate",
        "debug_aggregate_pointer",
        "debug_callback",
        "debug_nested_pointer",
        "debug_extended_float",
    ] {
        assert!(!report.signatures.iter().any(|signature| signature.name == unsupported), "{report:?}");
        assert!(report.warnings.iter().any(|warning| warning.contains(unsupported)), "{report:?}");
    }
    for qualified in ["debug_mix", "debug_variadic"] {
        assert!(
            report.warnings.iter().any(|warning| {
                warning.contains(qualified) && warning.contains("const qualifiers intentionally erased")
            }),
            "{report:?}"
        );
    }
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| { warning.contains("debug_reset") && warning.contains("DW_TAG_volatile_type") }),
        "{report:?}"
    );
    let json = serde_json::to_value(report).unwrap();
    assert!(json["signatures"][0]["address"].as_str().unwrap().starts_with("0x"));
}

#[test]
fn reads_elf_dwarf5_indexed_addresses_and_typedef_parameters() {
    check_signatures("debug-x64.elf", "");
}

#[test]
fn reads_macho_embedded_dwarf_with_standard_section_name_translation() {
    check_signatures("debug-x64.macho", "_");
}

#[test]
fn missing_debug_metadata_is_a_warning_not_a_load_failure() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
    let report = debug::signatures(&Binary::open(path).unwrap()).unwrap();
    assert!(report.signatures.is_empty());
    assert!(report.warnings.iter().any(|warning| warning.contains("no embedded DWARF")));
}

#[test]
fn relocatable_objects_do_not_supply_importable_function_addresses() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-elf.o");
    let report = debug::signatures(&Binary::open(path).unwrap()).unwrap();
    assert!(report.signatures.is_empty());
    assert!(report.warnings.iter().any(|warning| warning.contains("relocatable")));
}

fn modified_elf(modify: impl FnOnce(&mut [u8], usize, usize)) -> debug::DebugReport {
    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
    let mut bytes = std::fs::read(fixture("debug-x64.elf")).unwrap();
    let object = object::File::parse(bytes.as_slice()).unwrap();
    let section = object.section_by_name(".debug_info").unwrap();
    let data_offset = section.file_range().unwrap().0 as usize;
    let table_offset = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let entry_size = u16::from_le_bytes(bytes[58..60].try_into().unwrap()) as usize;
    let header_offset = table_offset + section.index().0 * entry_size;
    modify(&mut bytes, header_offset, data_offset);
    let path = std::env::temp_dir().join(format!(
        "rampage-debug-{}-{}.elf",
        std::process::id(),
        NEXT_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    struct RemoveFile(PathBuf);
    impl Drop for RemoveFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let cleanup = RemoveFile(path);
    std::fs::write(&cleanup.0, bytes).unwrap();
    let binary = Binary::open(&cleanup.0).unwrap();
    debug::signatures(&binary).unwrap()
}

#[test]
fn compressed_debug_sections_are_rejected_without_decompression() {
    let report = modified_elf(|bytes, header, data| {
        bytes[header + 8..header + 16].copy_from_slice(&0x800u64.to_le_bytes());
        bytes[data..data + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[data + 4..data + 8].fill(0);
        bytes[data + 8..data + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[data + 16..data + 24].copy_from_slice(&1u64.to_le_bytes());
    });
    assert!(report.signatures.is_empty());
    assert!(report.warnings.iter().any(|warning| warning.contains("compressed DWARF")), "{report:?}");
}

#[test]
fn oversized_section_lengths_are_rejected_before_reading_section_data() {
    let report = modified_elf(|bytes, header, _| {
        bytes[header + 32..header + 40].copy_from_slice(&(65 * 1024 * 1024u64).to_le_bytes());
    });
    assert!(report.signatures.is_empty());
    assert!(report.warnings.iter().any(|warning| warning.contains("64 MiB")), "{report:?}");
}

#[test]
fn malformed_dwarf_is_reported_without_a_partial_signature_list() {
    let report = modified_elf(|bytes, _, data| {
        bytes[data..data + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
    });
    assert!(report.signatures.is_empty());
    assert!(report.warnings.iter().any(|warning| warning.contains("preview stopped")), "{report:?}");
}

#[test]
fn unsigned_char_dwarf_is_not_reinterpreted_as_signed_native_char_pointers() {
    let report = modified_elf(|bytes, _, data| {
        let object = object::File::parse(&*bytes).unwrap();
        let dwarf = gimli::Dwarf::load(|id| -> Result<_, object::Error> {
            let section = object.section_by_name(id.name()).map(|section| section.data()).transpose()?;
            Ok(gimli::EndianSlice::new(section.unwrap_or_default(), gimli::LittleEndian))
        })
        .unwrap();
        let unit = dwarf.unit(dwarf.units().next().unwrap().unwrap()).unwrap();
        let mut entries = unit.entries();
        let mut encoding_offset = None;
        while let Some(entry) = entries.next_dfs().unwrap() {
            if entry.tag() != gimli::DW_TAG_base_type {
                continue;
            }
            let Some(value) = entry.attr_value(gimli::DW_AT_name) else { continue };
            if dwarf.attr_string(&unit, value).unwrap().slice() == b"char" {
                let relative = entry.offset().0;
                assert!(
                    entry
                        .attrs()
                        .iter()
                        .any(|attr| attr.name() == gimli::DW_AT_encoding && attr.form() == gimli::DW_FORM_data1)
                );
                encoding_offset = Some(relative + 2);
                break;
            }
        }
        let offset = data + encoding_offset.expect("dedicated DWARF5 fixture contains a char base type");
        assert_eq!(bytes[offset], gimli::DW_ATE_signed_char.0);
        bytes[offset] = gimli::DW_ATE_unsigned_char.0;
    });
    let signature = report.signatures.iter().find(|signature| signature.name == "debug_mix").unwrap();
    assert_eq!(
        signature.declaration,
        "uint64_t debug_mix(uint64_t total, uint8_t * message, int32_t delta, double ratio);"
    );
    assert!(
        report.warnings.iter().any(|warning| {
            warning.contains("debug_mix") && warning.contains("const qualifiers intentionally erased")
        })
    );
}
