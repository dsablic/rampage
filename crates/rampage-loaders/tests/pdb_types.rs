use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_loaders::Binary;
use rampage_loaders::debug_types::{DebugType, DebugTypeKind, DebugTypeReport};
use rampage_loaders::pdb::matched_types_checked;

struct Files(PathBuf);

impl Files {
    fn new() -> Self {
        static COUNT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-pdb-types-{}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        for entry in std::fs::read_dir(&self.0).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        std::fs::remove_dir(&self.0).unwrap();
    }
}

fn fixture() -> Option<(PathBuf, PathBuf)> {
    let root = PathBuf::from(std::env::var_os("RAMPAGE_DEBUG_TYPE_FIXTURES")?);
    Some((root.join("debug-types.exe"), root.join("debug-types.pdb")))
}

fn cpp_fixture() -> Option<(PathBuf, PathBuf)> {
    let root = PathBuf::from(std::env::var_os("RAMPAGE_DEBUG_TYPE_FIXTURES")?);
    let exe = root.join("debug-types-cpp.exe");
    let pdb = root.join("debug-types-cpp.pdb");
    (exe.is_file() && pdb.is_file()).then_some((exe, pdb))
}

fn named<'a>(report: &'a DebugTypeReport, name: &str) -> &'a DebugType {
    report
        .types
        .iter()
        .find(|ty| {
            ty.original_name.as_deref() == Some(name)
                && matches!(
                    ty.kind,
                    DebugTypeKind::Struct { .. } | DebugTypeKind::Union { .. } | DebugTypeKind::Enum { .. }
                )
        })
        .unwrap_or_else(|| panic!("missing complete producer type {name}: {:?}", report.types))
}

#[test]
fn generated_c_graph_keeps_exact_facts_and_unproven_forwards_preview_only() {
    let Some((exe, pdb)) = fixture() else { return };
    let binary = Binary::open(exe).unwrap();
    let (report, provenance) = matched_types_checked(&pdb, &binary).unwrap();
    assert_eq!(report.provenance.source_sha256, rampage_arch::hex::bytes(provenance.sha256()));
    assert!(report.types.iter().all(|ty| ty.alignment.is_none()));
    let types: BTreeMap<_, _> = report.types.iter().map(|ty| (ty.id.clone(), ty)).collect();
    for ty in &report.types {
        for reference in ty.kind.references() {
            assert!(types.contains_key(reference), "{} -> {reference}", ty.id);
        }
    }
    let record = named(&report, "DebugRecord");
    assert!(!record.unsupported.is_empty(), "unproven C forwards must not yield a complete record");
    assert_eq!(record.byte_size, Some(56));
    let DebugTypeKind::Struct { members } = &record.kind else { panic!("not struct") };
    let by_name: BTreeMap<_, _> = members.iter().map(|m| (m.name.as_deref().unwrap(), m)).collect();
    assert_eq!(by_name["nested"].byte_offset, 4);
    assert_eq!(by_name["taps"].byte_offset, 12);
    assert_eq!(by_name["payload"].byte_offset, 32);
    assert_eq!(by_name["next"].byte_offset, 40);
    assert_eq!(by_name["callback"].byte_offset, 48);
    let inner = named(&report, "DebugInner");
    assert!(inner.unsupported.is_empty());
    let inner_forward = types[&by_name["nested"].type_id];
    assert_ne!(inner_forward.id, inner.id);
    assert_eq!(inner_forward.original_name.as_deref(), Some("DebugInner"));
    assert!(matches!(inner_forward.kind, DebugTypeKind::Unsupported { .. }));
    assert!(!inner_forward.unsupported.is_empty());
    let DebugTypeKind::Array { element, count, stride } = &types[&by_name["taps"].type_id].kind else {
        panic!("taps lost array identity")
    };
    assert_eq!(element, &inner_forward.id);
    assert_eq!((*count, *stride), (None, None));
    assert_eq!(types[&by_name["taps"].type_id].byte_size, Some(16));
    assert!(!types[&by_name["taps"].type_id].unsupported.is_empty());
    let DebugTypeKind::Pointer { target } = &types[&by_name["next"].type_id].kind else {
        panic!("next lost pointer identity")
    };
    assert_ne!(target, &record.id);
    assert_eq!(types[target].original_name.as_deref(), Some("DebugRecord"));
    assert!(matches!(types[target].kind, DebugTypeKind::Unsupported { .. }));
    assert!(!types[target].unsupported.is_empty());
    let DebugTypeKind::Pointer { target: callback } = &types[&by_name["callback"].type_id].kind else {
        panic!("callback lost pointer identity")
    };
    let DebugTypeKind::Function { parameters, return_type, .. } = &types[callback].kind else {
        panic!("callback prototype missing")
    };
    assert_eq!(parameters.len(), 2);
    assert_eq!(parameters[0], by_name["next"].type_id);
    assert!(matches!(types[return_type].kind, DebugTypeKind::Scalar { .. }));
    assert!(!types[callback].unsupported.is_empty());
    let callback_alias = report
        .types
        .iter()
        .find(|ty| ty.id.starts_with("pdb:sym:") && ty.original_name.as_deref() == Some("DebugCallback"))
        .expect("explicit S_UDT callback alias missing");
    assert!(!callback_alias.unsupported.is_empty(), "an alias cannot complete unresolved C forwards");
    let mode = named(&report, "DebugMode");
    assert!(mode.unsupported.is_empty(), "{mode:#?}");
    let DebugTypeKind::Enum { values, .. } = &mode.kind else { panic!("not enum") };
    assert!(values.iter().any(|value| value.name == "DEBUG_FAULT" && value.value == "-3"), "{mode:#?}");
    assert!(values.iter().any(|value| value.name == "DEBUG_READY" && value.value == "7"));
    assert_eq!(named(&report, "DebugPayload").byte_size, Some(8));
    let bits = named(&report, "DebugBits");
    assert!(!bits.unsupported.is_empty());
    let DebugTypeKind::Struct { members } = &bits.kind else { panic!("not struct") };
    let facts: Vec<_> = members
        .iter()
        .map(|member| {
            let bitfield = member.bitfield.as_ref().expect("bitfield producer fact erased");
            assert!(!member.unsupported.is_empty());
            assert!(matches!(&types[&member.type_id].kind,
                DebugTypeKind::Bitfield { bit_size, bit_offset, .. }
                    if *bit_size == bitfield.bit_size && *bit_offset == bitfield.bit_offset));
            (bitfield.bit_size, bitfield.bit_offset)
        })
        .collect();
    assert_eq!(facts, [(1, 0), (3, 1), (28, 4)]);
    for name in ["debug_types_query", "debug_types_identity", "debug_types_main"] {
        let signature = report.signatures.iter().find(|s| s.name.as_deref() == Some(name)).unwrap();
        assert_eq!(signature.unsupported.is_empty(), name == "debug_types_main", "{name}: {:?}", signature.unsupported);
        assert!(binary.is_code(signature.address));
        assert!(binary.read(signature.address, 1).is_some());
        assert!(matches!(&types[&signature.type_id].kind,
            DebugTypeKind::Function { convention, .. } if convention == "cdecl"));
    }
}

#[test]
fn generated_cpp_wrapper_has_a_closed_identity_proven_nested_array_self_callback_graph() {
    let Some((exe, pdb)) = cpp_fixture() else { return };
    let binary = Binary::open(exe).unwrap();
    let (report, _) = matched_types_checked(&pdb, &binary).unwrap();
    let types: BTreeMap<_, _> = report.types.iter().map(|ty| (ty.id.clone(), ty)).collect();
    let record = named(&report, "DebugRecord");
    let inner = named(&report, "DebugInner");
    assert!(record.unsupported.is_empty(), "{record:#?}");
    assert!(inner.unsupported.is_empty(), "{inner:#?}");
    assert_eq!(record.byte_size, Some(56));
    assert_eq!(inner.byte_size, Some(8));
    assert!(report.types.iter().all(|ty| ty.alignment.is_none()));
    let DebugTypeKind::Struct { members } = &record.kind else { panic!("not struct") };
    let members: BTreeMap<_, _> = members.iter().map(|member| (member.name.as_deref().unwrap(), member)).collect();
    assert_eq!(members["nested"].type_id, inner.id);
    assert_eq!(members["nested"].byte_offset, 4);
    assert_eq!(members["taps"].byte_offset, 12);
    assert!(matches!(&types[&members["taps"].type_id].kind,
        DebugTypeKind::Array { element, count: Some(2), stride: Some(8) } if element == &inner.id));
    assert!(matches!(&types[&members["next"].type_id].kind,
        DebugTypeKind::Pointer { target } if target == &record.id));
    let DebugTypeKind::Pointer { target: callback } = &types[&members["callback"].type_id].kind else {
        panic!("callback pointer missing")
    };
    assert!(matches!(&types[callback].kind,
        DebugTypeKind::Function { convention, parameters, .. }
            if convention == "cdecl" && parameters.len() == 2 && parameters[0] == members["next"].type_id));
    let callback_alias = report
        .types
        .iter()
        .find(|ty| ty.id.starts_with("pdb:sym:") && ty.original_name.as_deref() == Some("DebugCallback"))
        .expect("explicit S_UDT callback alias missing");
    assert!(matches!(&callback_alias.kind,
        DebugTypeKind::Typedef { target, constant: false, volatile: false }
            if target == &members["callback"].type_id));
    assert_eq!(callback_alias.byte_size, Some(8));
    assert_eq!(callback_alias.alignment, None);
    assert_eq!(callback_alias.origin.source, rampage_loaders::debug_types::DebugSourceKind::Pdb);
    assert!(callback_alias.origin.unit.as_deref().unwrap().starts_with("symbols:"));
    assert!(callback_alias.unsupported.is_empty(), "{callback_alias:#?}");
    let mode = named(&report, "DebugMode");
    assert!(mode.unsupported.is_empty(), "{mode:#?}");
    let DebugTypeKind::Enum { values, .. } = &mode.kind else { panic!("not enum") };
    assert!(values.iter().any(|value| value.name == "DEBUG_FAULT" && value.value == "-3"), "{mode:#?}");
    for name in ["debug_types_query", "debug_types_identity", "debug_types_main"] {
        let signature = report.signatures.iter().find(|s| s.name.as_deref() == Some(name)).unwrap();
        assert!(signature.unsupported.is_empty(), "{signature:#?}");
        assert!(binary.is_code(signature.address));
        assert!(binary.read(signature.address, 1).is_some());
    }
    for ty in &report.types {
        for reference in ty.kind.references() {
            assert!(types.contains_key(reference), "{} -> {reference}", ty.id);
        }
    }
}

#[test]
fn generated_guid_age_mismatch_and_same_guid_changed_bytes_are_not_equivalent_sources() {
    let Some((exe, pdb)) = fixture() else { return };
    let files = Files::new();
    let executable = std::fs::read(exe).unwrap();
    let pe = object::read::pe::PeFile64::parse(executable.as_slice()).unwrap();
    let directory = pe.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_DEBUG).unwrap();
    let records = directory.data(pe.data(), &pe.section_table()).unwrap();
    let codeview = records.as_chunks::<28>().0.iter().find(|record| read_u32(*record, 12) == 2).unwrap();
    let rsds = read_u32(codeview, 24) as usize;
    assert_eq!(&executable[rsds..rsds + 4], b"RSDS");
    for offset in [rsds + 4, rsds + 20] {
        let mut changed = executable.clone();
        if offset == rsds + 20 {
            let age = read_u32(&executable, offset);
            put_u32(&mut changed, offset, if age == u32::MAX { 1 } else { age + 1 });
        } else {
            changed[offset] ^= 1;
            if changed[rsds + 4..rsds + 20].iter().all(|&byte| byte == 0) {
                changed[rsds + 5] = 1;
            }
        }
        assert_ne!(&changed[rsds + 4..rsds + 24], &executable[rsds + 4..rsds + 24]);
        assert!(read_u32(&changed, rsds + 20) > 0);
        let path = files.write("mismatched.exe", &changed);
        let error = matched_types_checked(&pdb, &Binary::open(path).unwrap()).unwrap_err();
        assert!(error.to_string().contains("GUID/age"), "{error}");
    }
    let original = std::fs::read(pdb).unwrap();
    let selected = files.write("selected.pdb", &original);
    let image = files.write("image.exe", &executable);
    let binary = Binary::open(image).unwrap();
    let (before, provenance) = matched_types_checked(&selected, &binary).unwrap();
    let mut changed = original;
    // The free-page map is not a producer identity or type record; changing it preserves GUID/age and graph.
    let page_size = read_u32(&changed, 32) as usize;
    changed[page_size + 32] ^= 1;
    files.write("selected.pdb", &changed);
    assert!(provenance.validate_current().is_err());
    let (after, _) = matched_types_checked(&selected, &binary).unwrap();
    assert_eq!(before.provenance.pdb_guid, after.provenance.pdb_guid);
    assert_eq!(before.provenance.pdb_age, after.provenance.pdb_age);
    assert_eq!(before.types, after.types);
    assert_ne!(before.provenance.source_sha256, after.provenance.source_sha256);
}

#[test]
fn dbi_machine_must_match_the_selected_pe_without_changing_the_matched_names_contract() {
    let Some((exe, pdb)) = fixture() else { return };
    let files = Files::new();
    let binary = Binary::open(exe).unwrap();
    let (baseline, _) = rampage_loaders::pdb::matched_symbols_checked(&binary, &pdb).unwrap();
    let original = std::fs::read(&pdb).unwrap();
    let original_streams = read_streams(&original);
    let dbi = original_streams[3].as_ref().unwrap();
    let original_machine = u16::from_le_bytes(dbi[58..60].try_into().unwrap());
    matched_types_checked(&pdb, &binary).unwrap();
    for machine in [0x014cu16, 0xaa64, 0xa641, 0xa64e, 0, 0xffff] {
        if machine == original_machine {
            continue;
        }
        let mut streams = original_streams.clone();
        streams[3].as_mut().unwrap()[58..60].copy_from_slice(&machine.to_le_bytes());
        assert_eq!(streams[1], original_streams[1], "PDB GUID/age stream must remain unchanged");
        let selected = files.write("wrong-machine.pdb", &msf_streams(&streams));
        let error = matched_types_checked(&selected, &binary).unwrap_err();
        assert!(error.to_string().contains("machine"), "machine {machine:#06x}: {error}");
        let (names, _) = rampage_loaders::pdb::matched_symbols_checked(&binary, &selected).unwrap();
        assert_eq!(names.identity, baseline.identity);
        assert_eq!(names.functions, baseline.functions);
        assert_eq!(names.warnings, baseline.warnings);
    }
}

#[test]
fn proc32_id_uses_ipi_function_identity_not_the_same_number_in_tpi() {
    let Some((exe, pdb)) = fixture() else { return };
    let files = Files::new();
    let binary = Binary::open(exe).unwrap();
    let original = std::fs::read(pdb).unwrap();
    let (baseline, _) = matched_types_checked(&files.write("original.pdb", &original), &binary).unwrap();
    let mut streams = read_streams(&original);
    let dbi = streams[3].as_ref().unwrap();
    let module = u16::from_le_bytes(dbi[98..100].try_into().unwrap()) as usize;
    let symbol_size = read_u32(dbi, 100) as usize;
    let symbols = streams[module].as_ref().unwrap();
    let mut procedure = 4;
    while procedure < symbol_size {
        let kind = u16::from_le_bytes(symbols[procedure + 2..procedure + 4].try_into().unwrap());
        if matches!(kind, 0x110f | 0x1110) {
            break;
        }
        procedure += u16::from_le_bytes(symbols[procedure..procedure + 2].try_into().unwrap()) as usize + 2;
    }
    assert!(procedure < symbol_size);
    let tpi_index = read_u32(symbols, procedure + 28);
    let ipi = streams[4].as_ref().unwrap();
    let mut at = 56;
    let mut ipi_index = 0x1000;
    while at < ipi.len() {
        let leaf = u16::from_le_bytes(ipi[at + 2..at + 4].try_into().unwrap());
        if leaf == 0x1601 && read_u32(ipi, at + 8) == tpi_index {
            break;
        }
        at += u16::from_le_bytes(ipi[at..at + 2].try_into().unwrap()) as usize + 2;
        ipi_index += 1;
    }
    assert!(at < ipi.len(), "generated producer omitted the explicit function identity");
    let symbols = streams[module].as_mut().unwrap();
    symbols[procedure + 2..procedure + 4].copy_from_slice(&0x1147u16.to_le_bytes());
    put_u32(symbols, procedure + 28, ipi_index);
    let selected = files.write("with-id.pdb", &msf_streams(&streams));
    let (with_id, _) = matched_types_checked(&selected, &binary).unwrap();
    assert_eq!(with_id.signatures, baseline.signatures);
    // 0x1000 is a string ID in this generated IPI, not a function. It is not silently treated as TPI.
    put_u32(streams[module].as_mut().unwrap(), procedure + 28, 0x1000);
    let selected = files.write("bad-id.pdb", &msf_streams(&streams));
    let error = matched_types_checked(&selected, &binary).unwrap_err();
    assert!(error.to_string().contains("IPI function identity"), "{error}");
    let mut public_only = read_streams(&original);
    public_only[module].as_mut().unwrap()[procedure + 2..procedure + 4].copy_from_slice(&0x0007u16.to_le_bytes());
    let selected = files.write("public-only.pdb", &msf_streams(&public_only));
    let names = rampage_loaders::pdb::matched_symbols(&binary, &selected).unwrap();
    let (without_procedure, _) = matched_types_checked(&selected, &binary).unwrap();
    let removed_address = baseline.signatures[0].address;
    assert!(names.functions.iter().any(|function| function.address == removed_address));
    assert!(!without_procedure.signatures.iter().any(|signature| signature.address == removed_address));
}

#[test]
fn bounded_raw_msf_rejects_counts_lengths_bad_refs_and_continuations_before_dependency_parsing() {
    let files = Files::new();
    let binary = Binary::open(files.write("minimal.exe", &minimal_pe())).unwrap();
    let cases = [
        ("arg count", type_records(&[record(0x1201, &u32::MAX.to_le_bytes())]), "argument-list"),
        ("bad ref", type_records(&[record(0x1001, &[0xff, 0xff, 0xff, 0xff, 0, 0])]), "reference"),
        ("self continuation", type_records(&[record(0x1203, &[4, 0x14, 0, 0, 0, 0x10, 0, 0])]), "continuation"),
        (
            "wrong continuation",
            type_records(&[record(0x1203, &[4, 0x14, 0, 0, 1, 0x10, 0, 0]), record(0x1201, &[0, 0, 0, 0])]),
            "field list",
        ),
    ];
    for (name, tpi, expected) in cases {
        let pdb = files.write("malformed.pdb", &minimal_msf(tpi));
        let error = matched_types_checked(&pdb, &binary).unwrap_err();
        assert!(error.to_string().contains(expected), "{name}: {error}");
    }
    let continued: Vec<_> = (0..33u32)
        .map(|index| {
            if index == 32 {
                record(0x1203, &[])
            } else {
                let mut payload = 0x1404u16.to_le_bytes().to_vec();
                payload.extend_from_slice(&0u16.to_le_bytes());
                payload.extend_from_slice(&(0x1001 + index).to_le_bytes());
                record(0x1203, &payload)
            }
        })
        .collect();
    let pdb = files.write("too-deep.pdb", &minimal_msf(type_records(&continued)));
    let error = matched_types_checked(&pdb, &binary).unwrap_err();
    assert!(error.to_string().contains("continuation"), "{error}");
    let mut bad_count = type_records(&[]);
    put_u32(&mut bad_count, 12, 0x2001);
    let mut bad_length = type_records(&[record(0x1201, &[0, 0, 0, 0])]);
    bad_length[56..58].copy_from_slice(&0xfffeu16.to_le_bytes());
    for (tpi, expected) in [(bad_count, "TPI/IPI"), (bad_length, "truncated")] {
        let pdb = files.write("malformed.pdb", &minimal_msf(tpi));
        let error = matched_types_checked(&pdb, &binary).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn record(leaf: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 2];
    bytes.extend_from_slice(&leaf.to_le_bytes());
    bytes.extend_from_slice(payload);
    let padding = (4 - bytes.len() % 4) % 4;
    for count in (1..=padding).rev() {
        bytes.push(0xf0 + count as u8);
    }
    let length = (bytes.len() - 2) as u16;
    bytes[..2].copy_from_slice(&length.to_le_bytes());
    bytes
}

fn type_records(records: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![0; 56];
    put_u32(&mut bytes, 0, 20040203);
    put_u32(&mut bytes, 4, 56);
    put_u32(&mut bytes, 8, 0x1000);
    put_u32(&mut bytes, 12, 0x1000 + records.len() as u32);
    put_u32(&mut bytes, 16, records.iter().map(Vec::len).sum::<usize>() as u32);
    for record in records {
        bytes.extend_from_slice(record);
    }
    bytes
}

/// Just enough MSF/DBI structure to reach the type audit. No valid PDB information stream is supplied.
fn minimal_msf(tpi: Vec<u8>) -> Vec<u8> {
    let mut dbi = vec![0; 64 + 22];
    put_u32(&mut dbi, 0, u32::MAX);
    dbi[20..22].copy_from_slice(&5u16.to_le_bytes());
    put_u32(&mut dbi, 48, 22);
    dbi[58..60].copy_from_slice(&0x8664u16.to_le_bytes());
    dbi[64..].fill(0xff);
    dbi[74..76].copy_from_slice(&6u16.to_le_bytes());
    let streams = [None, Some(Vec::new()), Some(tpi), Some(dbi), None, Some(Vec::new()), Some(vec![0; 40])];
    msf_streams(&streams)
}

fn msf_streams(streams: &[Option<Vec<u8>>]) -> Vec<u8> {
    let page_size = 4096;
    let mut bytes = vec![0; page_size * 3];
    let mut directory = (streams.len() as u32).to_le_bytes().to_vec();
    for stream in streams {
        directory.extend_from_slice(&stream.as_ref().map_or(u32::MAX, |s| s.len() as u32).to_le_bytes());
    }
    for stream in streams.iter().flatten() {
        for chunk in stream.chunks(page_size) {
            directory.extend_from_slice(&((bytes.len() / page_size) as u32).to_le_bytes());
            let at = bytes.len();
            bytes.resize(at + page_size, 0);
            bytes[at..at + chunk.len()].copy_from_slice(chunk);
        }
    }
    let directory_page = bytes.len() / page_size;
    bytes.resize(bytes.len() + page_size, 0);
    bytes[directory_page * page_size..directory_page * page_size + directory.len()].copy_from_slice(&directory);
    let map_page = bytes.len() / page_size;
    bytes.resize(bytes.len() + page_size, 0);
    put_u32(&mut bytes, map_page * page_size, directory_page as u32);
    bytes[..32].copy_from_slice(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0");
    put_u32(&mut bytes, 32, page_size as u32);
    put_u32(&mut bytes, 36, 1);
    let pages = (bytes.len() / page_size) as u32;
    put_u32(&mut bytes, 40, pages);
    put_u32(&mut bytes, 44, directory.len() as u32);
    put_u32(&mut bytes, 52, map_page as u32);
    bytes
}

fn read_streams(bytes: &[u8]) -> Vec<Option<Vec<u8>>> {
    let page_size = read_u32(bytes, 32) as usize;
    let map = read_u32(bytes, 52) as usize * page_size;
    let directory_size = read_u32(bytes, 44) as usize;
    let mut directory = Vec::new();
    for index in 0..directory_size.div_ceil(page_size) {
        let page = read_u32(bytes, map + index * 4) as usize * page_size;
        directory.extend_from_slice(&bytes[page..page + (directory_size - directory.len()).min(page_size)]);
    }
    let count = read_u32(&directory, 0) as usize;
    let mut at = 4 + count * 4;
    let mut streams = Vec::new();
    for index in 0..count {
        let size = read_u32(&directory, 4 + index * 4);
        if size == u32::MAX {
            streams.push(None);
            continue;
        }
        let size = size as usize;
        let mut stream = Vec::new();
        for _ in 0..size.div_ceil(page_size) {
            let page = read_u32(&directory, at) as usize * page_size;
            at += 4;
            stream.extend_from_slice(&bytes[page..page + (size - stream.len()).min(page_size)]);
        }
        streams.push(Some(stream));
    }
    streams
}

fn minimal_pe() -> Vec<u8> {
    let mut bytes = vec![0; 1024];
    bytes[..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 128);
    bytes[128..132].copy_from_slice(b"PE\0\0");
    bytes[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[134..136].copy_from_slice(&1u16.to_le_bytes());
    bytes[148..150].copy_from_slice(&240u16.to_le_bytes());
    bytes[150..152].copy_from_slice(&0x22u16.to_le_bytes());
    let optional = 152;
    bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    put_u32(&mut bytes, optional + 4, 512);
    put_u32(&mut bytes, optional + 16, 0x1000);
    put_u32(&mut bytes, optional + 20, 0x1000);
    bytes[optional + 24..optional + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
    put_u32(&mut bytes, optional + 32, 4096);
    put_u32(&mut bytes, optional + 36, 512);
    put_u32(&mut bytes, optional + 56, 8192);
    put_u32(&mut bytes, optional + 60, 512);
    bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
    put_u32(&mut bytes, optional + 108, 16);
    let section = optional + 240;
    bytes[section..section + 8].copy_from_slice(b".text\0\0\0");
    put_u32(&mut bytes, section + 8, 512);
    put_u32(&mut bytes, section + 12, 4096);
    put_u32(&mut bytes, section + 16, 512);
    put_u32(&mut bytes, section + 20, 512);
    put_u32(&mut bytes, section + 36, 0x60000020);
    bytes[512] = 0xc3;
    bytes
}
