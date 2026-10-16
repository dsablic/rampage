use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

const OPTIONAL: usize = 0x98;
const SECTIONS: usize = OPTIONAL + 240;
const BASE: u64 = 0x1_4000_0000;

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn raw(rva: u32) -> usize {
    (rva - 0x2000) as usize + 0x400
}

fn directory(bytes: &mut [u8], index: usize, rva: u32, size: u32) {
    put32(bytes, OPTIONAL + 112 + index * 8, rva);
    put32(bytes, OPTIONAL + 116 + index * 8, size);
}

fn image() -> Vec<u8> {
    let mut bytes = vec![0; 0x10400];
    bytes[..2].copy_from_slice(b"MZ");
    put32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut bytes, 0x84, 0x8664);
    put16(&mut bytes, 0x86, 2);
    put16(&mut bytes, 0x94, 240);
    put16(&mut bytes, 0x96, 0x22);
    put16(&mut bytes, OPTIONAL, 0x20b);
    put32(&mut bytes, OPTIONAL + 16, 0x1000);
    put64(&mut bytes, OPTIONAL + 24, BASE);
    put32(&mut bytes, OPTIONAL + 32, 0x1000);
    put32(&mut bytes, OPTIONAL + 36, 0x200);
    put32(&mut bytes, OPTIONAL + 56, 0x12000);
    put32(&mut bytes, OPTIONAL + 60, 0x200);
    put32(&mut bytes, OPTIONAL + 108, 16);
    bytes[SECTIONS..SECTIONS + 5].copy_from_slice(b".text");
    put32(&mut bytes, SECTIONS + 8, 0x200);
    put32(&mut bytes, SECTIONS + 12, 0x1000);
    put32(&mut bytes, SECTIONS + 16, 0x200);
    put32(&mut bytes, SECTIONS + 20, 0x200);
    put32(&mut bytes, SECTIONS + 36, 0x6000_0020);
    bytes[SECTIONS + 40..SECTIONS + 46].copy_from_slice(b".rdata");
    put32(&mut bytes, SECTIONS + 48, 0x10000);
    put32(&mut bytes, SECTIONS + 52, 0x2000);
    put32(&mut bytes, SECTIONS + 56, 0x10000);
    put32(&mut bytes, SECTIONS + 60, 0x400);
    put32(&mut bytes, SECTIONS + 76, 0x4000_0040);
    bytes[0x200] = 0xc3;
    bytes
}

fn with_imports() -> Vec<u8> {
    let mut bytes = image();
    directory(&mut bytes, 1, 0x2100, 40);
    put32(&mut bytes, raw(0x2100), 0x2140);
    put32(&mut bytes, raw(0x2100) + 12, 0x21c0);
    put32(&mut bytes, raw(0x2100) + 16, 0x2180);
    put64(&mut bytes, raw(0x2140), 0x2200);
    put64(&mut bytes, raw(0x2180), 0x2200);
    bytes[raw(0x21c0)..raw(0x21c0) + 13].copy_from_slice(b"provider.dll\0");
    bytes[raw(0x2202)..raw(0x2202) + 4].copy_from_slice(b"add\0");
    bytes
}

fn with_exports() -> Vec<u8> {
    let mut bytes = image();
    directory(&mut bytes, 0, 0x2000, 0x100);
    let header = raw(0x2000);
    put32(&mut bytes, header + 12, 0x2080);
    put32(&mut bytes, header + 16, 1);
    put32(&mut bytes, header + 20, 1);
    put32(&mut bytes, header + 24, 1);
    put32(&mut bytes, header + 28, 0x2040);
    put32(&mut bytes, header + 32, 0x2044);
    put32(&mut bytes, header + 36, 0x2048);
    put32(&mut bytes, raw(0x2040), 0x1000);
    put32(&mut bytes, raw(0x2044), 0x2060);
    bytes[raw(0x2060)..raw(0x2060) + 4].copy_from_slice(b"add\0");
    bytes[raw(0x2080)..raw(0x2080) + 19].copy_from_slice(b"owned-provider.dll\0");
    bytes
}

fn with_tls() -> Vec<u8> {
    let mut bytes = image();
    directory(&mut bytes, 9, 0x2300, 40);
    for (field, rva) in [(0, 0x2350), (8, 0x2358), (16, 0x2360), (24, 0x2340)] {
        put64(&mut bytes, raw(0x2300) + field, BASE + rva);
    }
    put64(&mut bytes, raw(0x2340), BASE + 0x1000);
    bytes
}

fn with_unwind() -> Vec<u8> {
    let mut bytes = image();
    directory(&mut bytes, 3, 0x2400, 12);
    put32(&mut bytes, raw(0x2400), 0x1000);
    put32(&mut bytes, raw(0x2400) + 4, 0x1001);
    put32(&mut bytes, raw(0x2400) + 8, 0x2440);
    bytes[raw(0x2440)] = 1;
    bytes
}

fn refused(bytes: &[u8], reason: &str) {
    let error = admit(bytes).unwrap_err().to_string();
    assert!(error.contains(reason), "expected {reason:?}, got {error:?}");
}

struct Source(PathBuf);

impl Source {
    fn new(bytes: &[u8]) -> Self {
        use std::io::Write;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-pe-admission-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        let source = Self(path);
        file.write_all(bytes).unwrap();
        source
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn loaded(bytes: &[u8]) -> (Source, rampage_loaders::Binary) {
    let source = Source::new(bytes);
    let binary = rampage_loaders::Binary::open_image_checked_admitted(
        &source.0,
        None,
        None,
        MAX_PLUGIN_TRIAGE_SOURCE_BYTES,
        |actual| admit(actual).map_err(|error| rampage_loaders::LoadError::Unsupported(error.to_string())),
    )
    .unwrap();
    (source, binary)
}

#[test]
fn both_native_code_flags_charge_real_constructor_thunks_before_names_construction() {
    for flag in [0x20, 0x2000_0000] {
        for (name_length, count, reason) in
            [(1, MAX_RECORDS / 4 + 1, "record admission"), (MAX_NAME, 512, "repeated-name")]
        {
            let mut bytes = with_imports();
            put32(&mut bytes, SECTIONS + 76, 0x4000_0000 | flag);
            put64(&mut bytes, raw(0x2140), 0x2800);
            bytes[raw(0x2802)..raw(0x2802) + name_length].fill(b'a');
            // Every actual FF25 RIP-relative window resolves to the same backed IAT slot, not merely a
            // marker counted by preflight. Keep the single referenced long name outside the thunk array.
            for index in 0..count {
                let rva = 0x3000 + index as u32 * 6;
                let offset = raw(rva);
                bytes[offset..offset + 2].copy_from_slice(&[0xff, 0x25]);
                let displacement = (0x2180i64 - i64::from(rva) - 6) as i32;
                bytes[offset + 2..offset + 6].copy_from_slice(&displacement.to_le_bytes());
            }
            // Import walking itself remains within budget; only the constructor-thunk pass refuses this.
            let optional = &bytes[OPTIONAL..OPTIONAL + 240];
            let pe = Pe { bytes: &bytes, sections: &bytes[SECTIONS..SECTIONS + 80], optional, base: BASE };
            imports(&pe, &mut Budget::default()).unwrap();
            let source = Source::new(&bytes);
            let admitted = Cell::new(false);
            let constructed = Cell::new(false);
            let result = rampage_loaders::Binary::open_image_checked_admitted(
                &source.0,
                None,
                None,
                MAX_PLUGIN_TRIAGE_SOURCE_BYTES,
                |actual| {
                    admitted.set(true);
                    assert_eq!(actual, bytes);
                    admit(actual).map_err(|error| rampage_loaders::LoadError::Unsupported(error.to_string()))
                },
            )
            .map(|binary| {
                constructed.set(true);
                crate::Project::new(binary)
            });
            assert!(admitted.get());
            assert!(!constructed.get());
            assert!(result.err().unwrap().to_string().contains(reason));
        }
        // A small control reaches the real Names constructor and demonstrates the same flag classifies Code.
        let mut bytes = with_imports();
        put32(&mut bytes, SECTIONS + 76, 0x4000_0000 | flag);
        bytes[raw(0x3000)..raw(0x3000) + 2].copy_from_slice(&[0xff, 0x25]);
        bytes[raw(0x3002)..raw(0x3002) + 4].copy_from_slice(&(0x2180i32 - 0x3006).to_le_bytes());
        let (_source, binary) = loaded(&bytes);
        assert_eq!(binary.sections[1].kind, rampage_loaders::SectionKind::Code);
        let project = crate::Project::new(binary);
        assert!(project.inventory_loader_names().any(|(address, name)| address == BASE + 0x3000 && name == "add"));
    }
}

fn with_debug() -> Vec<u8> {
    let mut bytes = image();
    directory(&mut bytes, 6, 0x2600, 28);
    put32(&mut bytes, raw(0x2600) + 12, 2);
    put32(&mut bytes, raw(0x2600) + 16, 28);
    put32(&mut bytes, raw(0x2600) + 20, 0x2680);
    put32(&mut bytes, raw(0x2600) + 24, raw(0x2680) as u32);
    bytes[raw(0x2680)..raw(0x2680) + 4].copy_from_slice(b"RSDS");
    bytes[raw(0x2680) + 24..raw(0x2680) + 28].copy_from_slice(b"pdb\0");
    bytes
}

fn with_relocations() -> Vec<u8> {
    let mut bytes = image();
    directory(&mut bytes, 5, 0x2500, 12);
    put32(&mut bytes, raw(0x2500), 0x1000);
    put32(&mut bytes, raw(0x2500) + 4, 12);
    put16(&mut bytes, raw(0x2500) + 8, 0xa000);
    bytes
}

#[test]
fn admitted_import_spellings_and_iat_slots_are_the_ones_the_native_loader_consumes() {
    for (ordinal, expected) in [(false, "#7"), (true, "#7")] {
        let mut bytes = with_imports();
        if ordinal {
            put64(&mut bytes, raw(0x2140), 1 << 63 | 7);
        } else {
            bytes[raw(0x2202)..raw(0x2202) + 3].copy_from_slice(b"#7\0");
        }
        let (_source, binary) = loaded(&bytes);
        binary.validate_backing_source().unwrap();
        assert_eq!(binary.imports.len(), 1);
        assert_eq!(binary.imports[0].name, expected);
        assert_eq!(binary.imports[0].library.as_deref(), Some("provider.dll"));
        assert_eq!(binary.import_slots.len(), 1);
        assert_eq!(binary.import_slots[0].address, BASE + 0x2180);
        assert_eq!(binary.import_slots[0].name, expected);
        // Display spelling collapses these identities; bounded raw linkage must still distinguish them.
        let linkage = binary.linkage_metadata(rampage_loaders::LinkageLimits::default()).unwrap();
        let symbol = &linkage.imports[0].symbol;
        if ordinal {
            assert_eq!(symbol, &rampage_loaders::LinkageSymbol::Ordinal(7));
        } else {
            assert_eq!(symbol, &rampage_loaders::LinkageSymbol::Named(b"#7".to_vec()));
        }
    }
}

#[test]
fn admitted_direct_exports_and_forwarders_match_native_export_filtering() {
    let (_source, binary) = loaded(&with_exports());
    assert_eq!(binary.exports.len(), 1);
    assert_eq!(binary.exports[0].name, "add");
    assert_eq!(binary.exports[0].address, BASE + 0x1000);
    for target in [b"other.#7\0".as_slice(), b"other.add\0".as_slice()] {
        let mut bytes = with_exports();
        put32(&mut bytes, raw(0x2040), 0x20c0);
        bytes[raw(0x20c0)..raw(0x20c0) + target.len()].copy_from_slice(target);
        let (_source, binary) = loaded(&bytes);
        assert!(binary.exports.is_empty());
        assert!(binary.warnings.is_empty());
        assert_eq!(binary.read(BASE + 0x20c0, target.len() as u64).unwrap(), target);
    }
}

#[test]
fn admitted_tls_unwind_and_codeview_use_the_preflighted_address_backing() {
    for (bytes, rva, length) in [(with_tls(), 0x2340, 8), (with_unwind(), 0x2440, 4)] {
        let (_source, binary) = loaded(&bytes);
        assert_eq!(binary.function_starts, [BASE + 0x1000]);
        assert_eq!(binary.read(BASE + 0x1000, 1).unwrap(), &[0xc3]);
        assert_eq!(binary.read(BASE + u64::from(rva), length as u64).unwrap(), &bytes[raw(rva)..raw(rva) + length]);
        assert!(binary.warnings.is_empty());
    }
    let bytes = with_debug();
    let (_source, binary) = loaded(&bytes);
    let rampage_loaders::Details::Pe(details) = &binary.details else { panic!("expected PE details") };
    let codeview = details.codeview.as_ref().unwrap();
    assert_eq!(codeview.path, "pdb");
    assert_eq!(codeview.guid, [0; 16]);
    assert_eq!(codeview.age, 0);
    assert_eq!(binary.read(BASE + 0x2680, 28).unwrap(), &bytes[raw(0x2680)..raw(0x2680) + 28]);
    binary.validate_backing_source().unwrap();
}

#[test]
fn admitted_relocations_preserve_the_backed_bytes_without_claiming_native_relocation_application() {
    let mut bytes = with_relocations();
    put64(&mut bytes, 0x200, BASE + 0x1000);
    let (_source, binary) = loaded(&bytes);
    assert_eq!(binary.read(BASE + 0x2500, 12).unwrap(), &bytes[raw(0x2500)..raw(0x2500) + 12]);
    assert_eq!(binary.read(BASE + 0x1000, 8).unwrap(), &(BASE + 0x1000).to_le_bytes());
    assert!(binary.inventory_source_context().2.is_empty());
    assert!(binary.warnings.is_empty());
    binary.validate_backing_source().unwrap();
}

#[test]
fn fresh_hello_and_small_named_or_ordinal_profiles_are_admitted_without_a_binary() {
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.exe");
    admit(&std::fs::read(fixture).unwrap()).unwrap();
    for bytes in [image(), with_imports(), with_exports(), with_tls(), with_unwind()] {
        admit(&bytes).unwrap();
    }
    let mut ordinal = with_imports();
    put64(&mut ordinal, raw(0x2140), 1 << 63 | 7);
    admit(&ordinal).unwrap();
    // A literal named '#7' is admitted by the name path, not converted to ordinal identity.
    let mut named = with_imports();
    named[raw(0x2202)..raw(0x2202) + 3].copy_from_slice(b"#7\0");
    admit(&named).unwrap();
    put64(&mut ordinal, raw(0x2140), 1 << 63);
    refused(&ordinal, "zero ordinal");
    put64(&mut ordinal, raw(0x2140), 1 << 63 | 1 << 32 | 7);
    refused(&ordinal, "reserved bits");
    put64(&mut named, raw(0x2140), 1 << 32 | 0x2200);
    refused(&named, "canonical RVA");
}

#[test]
fn counts_and_symbol_or_long_section_names_are_refused_before_native_allocations() {
    let mut bytes = image();
    put16(&mut bytes, 0x86, u16::MAX);
    refused(&bytes, "section count");
    let mut bytes = image();
    put32(&mut bytes, 0x8c, 0x400);
    put32(&mut bytes, 0x90, u32::MAX);
    refused(&bytes, "COFF symbol/string");
    let mut bytes = image();
    bytes[SECTIONS..SECTIONS + 8].copy_from_slice(b"/123456\0");
    refused(&bytes, "section names");
    let mut bytes = with_exports();
    put32(&mut bytes, raw(0x2000) + 20, u32::MAX);
    refused(&bytes, "record admission");
    let mut bytes = with_exports();
    put32(&mut bytes, raw(0x2000) + 24, u32::MAX);
    refused(&bytes, "record admission");
}

#[test]
fn every_export_name_reference_is_charged_even_when_all_reuse_one_string() {
    let mut bytes = with_exports();
    directory(&mut bytes, 0, 0x2000, 0x10000);
    put32(&mut bytes, raw(0x2000) + 24, 1000);
    put32(&mut bytes, raw(0x2000) + 32, 0x3000);
    put32(&mut bytes, raw(0x2000) + 36, 0x4000);
    for index in 0..1000 {
        put32(&mut bytes, raw(0x3000) + index * 4, 0x5000);
    }
    bytes[raw(0x5000)..raw(0x5000) + MAX_NAME].fill(b'a');
    refused(&bytes, "repeated-name");
}

#[test]
fn repeated_import_library_and_thunk_names_are_charged_on_every_descriptor_walk() {
    let mut bytes = with_imports();
    let descriptor = bytes[raw(0x2100)..raw(0x2100) + 20].to_vec();
    directory(&mut bytes, 1, 0x3000, 20 * 401);
    bytes[raw(0x6000)..raw(0x6000) + MAX_NAME].fill(b'l');
    for index in 0..400 {
        bytes[raw(0x3000) + index * 20..raw(0x3000) + (index + 1) * 20].copy_from_slice(&descriptor);
        put32(&mut bytes, raw(0x3000) + index * 20 + 12, 0x6000);
    }
    refused(&bytes, "repeated-name");
}

#[test]
fn names_and_import_walks_must_be_complete_in_the_actual_producer_section() {
    let mut bytes = with_imports();
    bytes[raw(0x2202)..raw(0x2202) + MAX_NAME + 1].fill(b'a');
    refused(&bytes, "referenced name");
    let mut bytes = with_imports();
    directory(&mut bytes, 1, 0x2100, 20);
    refused(&bytes, "descriptors must terminate");
    let mut bytes = with_imports();
    put32(&mut bytes, raw(0x2100), 0x11ff8);
    put64(&mut bytes, raw(0x11ff8), 0x2200);
    refused(&bytes, "thunk list");
    let mut bytes = with_imports();
    put32(&mut bytes, raw(0x2100), 0x1000);
    refused(&bytes, "full section backing");
    let mut bytes = with_imports();
    put32(&mut bytes, raw(0x2100) + 16, 0x1000);
    refused(&bytes, "producer's section mapping");
    let mut bytes = with_imports();
    put64(&mut bytes, raw(0x2140), 0xffff_ffff);
    refused(&bytes, "canonical RVA");
}

#[test]
fn delay_directories_are_refused_including_obsolete_va_mode_and_huge_counts() {
    for attributes in [0, 1, u32::MAX] {
        let mut bytes = image();
        directory(&mut bytes, 13, 0x2100, 64);
        put32(&mut bytes, raw(0x2100), attributes);
        put32(&mut bytes, raw(0x2100) + 16, 0xffff_fff8);
        refused(&bytes, "delay/resource");
    }
}

#[test]
fn export_forwarders_and_ordinals_need_complete_backing_and_width_safe_identity() {
    let mut bytes = with_exports();
    put32(&mut bytes, raw(0x2040), 0x20c0);
    bytes[raw(0x20c0)..raw(0x20c0) + 9].copy_from_slice(b"other.#7\0");
    admit(&bytes).unwrap();
    bytes[raw(0x20c0)..raw(0x2100)].fill(b'x');
    refused(&bytes, "referenced name");
    let mut bytes = with_exports();
    put32(&mut bytes, raw(0x2000) + 16, 65536);
    refused(&bytes, "ordinal width");
    let mut bytes = with_exports();
    put16(&mut bytes, raw(0x2048), 1);
    refused(&bytes, "absent address slot");
    let mut bytes = with_exports();
    put32(&mut bytes, raw(0x2040), 0x1200);
    refused(&bytes, "full section backing");
    let mut bytes = with_exports();
    put32(&mut bytes, raw(0x2000) + 24, 0);
    put32(&mut bytes, raw(0x2000) + 32, 0);
    put32(&mut bytes, raw(0x2000) + 36, 0);
    admit(&bytes).unwrap();
}

#[test]
fn tls_callback_arrays_cannot_use_zero_fill_unbacked_vas_or_missing_terminators() {
    let mut bytes = with_tls();
    put64(&mut bytes, raw(0x2300) + 24, BASE - 8);
    refused(&bytes, "width-safe RVA");
    let mut bytes = with_tls();
    put64(&mut bytes, raw(0x2340), BASE + 0x1200);
    refused(&bytes, "full section backing");
    let mut bytes = with_tls();
    put64(&mut bytes, raw(0x2300) + 24, BASE + 0x11ff8);
    put64(&mut bytes, raw(0x11ff8), BASE + 0x1000);
    refused(&bytes, "full section backing");
    let mut bytes = with_tls();
    for index in 0..4096 {
        put64(&mut bytes, raw(0x2340) + index * 8, BASE + 0x1000);
    }
    refused(&bytes, "terminated-array");
}

#[test]
fn unwind_must_use_backed_address_bytes_not_an_unrelated_raw_offset() {
    let mut bytes = with_unwind();
    directory(&mut bytes, 3, 0x2400, 13);
    refused(&bytes, "partial runtime-function");
    let mut bytes = with_unwind();
    put32(&mut bytes, raw(0x2400) + 8, 0x2441);
    refused(&bytes, "indirect or malformed");
    let mut bytes = with_unwind();
    bytes[raw(0x2440)] = 1 | 4 << 3;
    refused(&bytes, "chained");
    let mut bytes = with_unwind();
    put32(&mut bytes, raw(0x2400) + 8, 0x1200);
    refused(&bytes, "full section backing");
    let mut bytes = with_unwind();
    put32(&mut bytes, SECTIONS + 48, 0x11000);
    put32(&mut bytes, OPTIONAL + 56, 0x13000);
    put32(&mut bytes, raw(0x2400) + 8, 0x12000);
    refused(&bytes, "zero-fill");
}

#[test]
fn ambiguous_padding_header_and_overflow_rvas_cannot_authorize_metadata() {
    let mut bytes = image();
    put32(&mut bytes, SECTIONS + 52, 0x1000);
    refused(&bytes, "ambiguous");
    let mut bytes = image();
    put32(&mut bytes, SECTIONS + 60, 0x200);
    refused(&bytes, "ambiguous");
    let mut bytes = with_imports();
    directory(&mut bytes, 1, 0x80, 40);
    refused(&bytes, "full section backing");
    let mut bytes = image();
    put32(&mut bytes, SECTIONS + 8, 1);
    directory(&mut bytes, 1, 0x1008, 40);
    refused(&bytes, "raw padding");
    let mut bytes = image();
    put32(&mut bytes, SECTIONS + 52, 0xffff_fff0);
    refused(&bytes, "extent overflow");
    let mut bytes = image();
    put64(&mut bytes, OPTIONAL + 24, u64::MAX - 0x1000);
    refused(&bytes, "VA overflow");
    let mut bytes = image();
    put32(&mut bytes, SECTIONS + 60, u32::MAX - 2);
    refused(&bytes, "extent overflow");
}

#[test]
fn debug_raw_rva_mapping_and_relocation_targets_are_checked_before_parsing() {
    let mut bytes = with_debug();
    admit(&bytes).unwrap();
    put32(&mut bytes, raw(0x2600) + 24, raw(0x2680) as u32 + 4);
    refused(&bytes, "same backing");
    let mut bytes = with_relocations();
    admit(&bytes).unwrap();
    put16(&mut bytes, raw(0x2500) + 8, 0xafff);
    refused(&bytes, "full section backing");
}

#[test]
fn recovery_names_and_mangled_prefixes_are_explicit_policy_refusals() {
    for name in [b".eh_fram".as_slice(), b"__gopcl".as_slice(), b".plt.sec".as_slice(), b"__stubs".as_slice()] {
        let mut bytes = image();
        bytes[SECTIONS..SECTIONS + 8].fill(0);
        bytes[SECTIONS..SECTIONS + name.len()].copy_from_slice(name);
        refused(&bytes, "recovery section alias");
    }
    for name in [b"?bad".as_slice(), b"_Zbad", b"__Zbad", b"_Rbad", b"__Rbad", b"ZNbad"] {
        let mut bytes = with_imports();
        bytes[raw(0x2202)..raw(0x2202) + 16].fill(0);
        bytes[raw(0x2202)..raw(0x2202) + name.len()].copy_from_slice(name);
        refused(&bytes, "mangled-name");
    }
}

#[test]
fn partial_and_overflowing_debug_data_never_authorize_codeview_parsing() {
    let mut bytes = with_debug();
    directory(&mut bytes, 6, 0x2600, 29);
    refused(&bytes, "partial row");
    let mut bytes = with_debug();
    put32(&mut bytes, raw(0x2600) + 16, 24);
    refused(&bytes, "referenced name");
    let mut bytes = with_debug();
    put32(&mut bytes, raw(0x2600) + 24, u32::MAX - 8);
    refused(&bytes, "outside the retained source");
    let mut bytes = with_debug();
    put32(&mut bytes, raw(0x2600) + 20, u32::MAX - 8);
    refused(&bytes, "extent overflow");
    let mut bytes = with_debug();
    directory(&mut bytes, 6, u32::MAX - 8, 28);
    refused(&bytes, "extent overflow");
}

#[test]
fn unwind_handlers_and_function_extents_require_executable_fully_backed_bytes() {
    let mut bytes = with_unwind();
    bytes[raw(0x2440)] = 1 | 1 << 3;
    put32(&mut bytes, raw(0x2440) + 4, 0x1000);
    let (_source, binary) = loaded(&bytes);
    assert_eq!(binary.function_starts, [BASE + 0x1000]);
    put32(&mut bytes, raw(0x2440) + 4, 0x2000);
    refused(&bytes, "executable code");
    put32(&mut bytes, raw(0x2440) + 4, 0x1200);
    refused(&bytes, "full section backing");
    let mut bytes = with_unwind();
    put32(&mut bytes, raw(0x2400) + 4, 0x1201);
    refused(&bytes, "full section backing");
    let mut bytes = with_unwind();
    put32(&mut bytes, raw(0x2400), 0x2000);
    put32(&mut bytes, raw(0x2400) + 4, 0x2001);
    refused(&bytes, "executable code");
    let mut bytes = with_unwind();
    put32(&mut bytes, raw(0x2400) + 8, 0x11ffc);
    bytes[raw(0x11ffc)] = 1 | 1 << 3;
    refused(&bytes, "full section backing");
}

#[test]
fn recovery_aliases_go_candidates_and_unreviewed_directories_are_not_enabled() {
    for name in [b".got\0\0\0\0", b".plt\0\0\0\0", b"/99\0\0\0\0\0"] {
        let mut bytes = image();
        bytes[SECTIONS..SECTIONS + 8].copy_from_slice(name);
        assert!(admit(&bytes).is_err());
    }
    let mut bytes = image();
    bytes[raw(0x2800)..raw(0x2800) + 8].copy_from_slice(&[0xf1, 255, 255, 255, 0, 0, 1, 8]);
    refused(&bytes, "Go recovery");
    for index in [2, 4, 7, 10, 11, 15] {
        let mut bytes = image();
        directory(&mut bytes, index, 0x2000, 16);
        refused(&bytes, "unknown directory");
    }
}
