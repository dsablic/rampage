//! A binary whose code section is encrypted: triage, binary_info and list_functions name the region and its
//! evidence, discovery leaves it alone, and decompile refuses it.

use rampage_api::{FunctionsQuery, Project};
use rampage_loaders::Binary;

/// Deterministic noise standing in for encrypted bytes (xorshift64*).
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..len)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

/// The static musl fixture with `.text` replaced by noise, so its entry point lies in encrypted code.
fn encrypted_project() -> Project {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/musl-static-x86_64.elf");
    let binary = Binary::open(&path).unwrap();
    let text = binary.sections.iter().find(|section| section.name == ".text").unwrap();
    let (offset, len) = (text.file_offset.unwrap() as usize, text.file_size as usize);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[offset..offset + len].copy_from_slice(&noise(len));
    let project = Project::new(Binary::from_owned_native_bytes(bytes, rampage_arch::Arch::X86_64).unwrap());
    project.set_analysis_store(None);
    project
}

#[test]
fn encrypted_code_is_reported_skipped_and_refused() {
    let project = encrypted_project();
    let entry = project.binary.entry.unwrap();

    let triage = project.triage();
    let [region] = triage.encrypted_or_packed_code.as_slice() else { panic!("{:?}", triage.encrypted_or_packed_code) };
    assert_eq!(region.name, ".text");
    assert!(region.contains(entry) && region.entropy >= 7.9 && region.valid_share < 0.97, "{region:?}");
    assert!(triage.hints.iter().any(|hint| hint.contains("likely_encrypted_or_packed")), "{:?}", triage.hints);

    let info = serde_json::to_value(project.summary()).unwrap();
    assert_eq!(info["encrypted_or_packed_code"][0]["verdict"], "likely_encrypted_or_packed");

    let page = project.functions_page(&FunctionsQuery::default()).unwrap();
    assert!(page.page.items.iter().all(|row| !region.contains(row.address)), "{:?}", page.page.items);
    let [unexplored] = page.unexplored_code.as_slice() else { panic!("{:?}", page.unexplored_code) };
    assert!(unexplored.known_entry_points >= 1 && unexplored.note.contains("not explored"), "{unexplored:?}");

    let refused = project.decompile(entry).unwrap_err().to_string();
    assert!(refused.contains("encrypted or packed"), "{refused}");
}

#[test]
fn ordinary_binaries_report_no_encrypted_code() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.exe");
    let project = Project::new(Binary::open(path).unwrap());
    assert!(project.triage().encrypted_or_packed_code.is_empty());
    let info = serde_json::to_value(project.summary()).unwrap();
    assert!(info.get("encrypted_or_packed_code").is_none());
    assert!(project.functions_page(&FunctionsQuery::default()).unwrap().unexplored_code.is_empty());
}
