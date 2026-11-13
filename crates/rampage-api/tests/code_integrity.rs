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
    let regions = &triage.encrypted_or_packed_code;
    assert!(!regions.is_empty() && regions.iter().all(|region| region.name == ".text"), "{regions:?}");
    // The entry point runs before anything could decrypt it, so its block stays code.
    assert!(regions.iter().all(|region| !region.contains(entry)), "{regions:?}");
    let region = &regions[0];
    assert!(region.entropy >= 7.9 && region.valid_share < 0.97, "{region:?}");
    assert!(triage.hints.iter().any(|hint| hint.contains("likely_encrypted_or_packed")), "{:?}", triage.hints);

    let info = serde_json::to_value(project.summary()).unwrap();
    assert_eq!(info["encrypted_or_packed_code"][0]["verdict"], "likely_encrypted_or_packed");

    let page = project.functions_page(&FunctionsQuery::default()).unwrap();
    for row in &page.page.items {
        assert!(regions.iter().all(|region| !region.contains(row.address)), "{row:?}");
    }
    assert_eq!(page.unexplored_code.len(), regions.len());
    assert!(page.unexplored_code[0].note.contains("not explored"), "{:?}", page.unexplored_code);

    let inside = region.address;
    let refused = project.decompile(inside).unwrap_err().to_string();
    assert!(refused.contains("encrypted or packed") && refused.contains("explore_encrypted"), "{refused}");
    // The override proceeds: whatever happens next is the decompiler's doing, not the refusal.
    if let Err(error) = project.decompile_encrypted(inside) {
        assert!(!error.to_string().contains("judged encrypted"), "{error}");
    }
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
