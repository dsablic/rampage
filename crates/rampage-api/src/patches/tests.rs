use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::{FunctionsQuery, Session, StringsQuery};

struct Files {
    directory: PathBuf,
    source: PathBuf,
    log: PathBuf,
    export: PathBuf,
}

impl Files {
    fn new(fixture: &str) -> Self {
        let bytes =
            fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(fixture)).unwrap();
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-patches-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&directory).unwrap();
        let source = directory.join("source.elf");
        OpenOptions::new().write(true).create_new(true).open(&source).unwrap().write_all(bytes).unwrap();
        let log = source.with_file_name("source.elf.rampage");
        let export = directory.join("export.elf");
        Self { directory, source, log, export }
    }

    fn project(&self) -> Arc<Project> {
        let binary = Binary::open(&self.source).unwrap();
        let hash = Sha256::digest(binary.file_bytes()).into();
        Arc::new(Project::with_annotations(
            binary,
            Annotations::open_for_image_checked(self.log.clone(), Some(hash)).unwrap(),
        ))
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        for name in [
            "source.elf",
            "source.elf.rampage",
            "source.elf.rampage.lock",
            "export.elf",
            "export.elf.rampage",
            "export.elf.rampage.lock",
            "replacement.elf",
        ] {
            let _ = fs::remove_file(self.directory.join(name));
        }
        let _ = fs::remove_dir(&self.directory);
    }
}

fn assert_return(project: &Project, value: u8) {
    let main = project.resolve("main").unwrap();
    let code = project.decompile(main).unwrap().code;
    assert!(code.contains(&format!("return {value};")), "{code}");
}

fn roundtrip(files: Files, address: u64, offset: usize, original: &[u8], replacement: &[u8]) {
    let source_bytes = fs::read(&files.source).unwrap();
    assert_eq!(&source_bytes[offset..offset + original.len()], original);
    let project = files.project();
    assert_return(&project, 5);
    let main = project.resolve("main").unwrap();
    project.function_listing(main).unwrap();
    project.strings(&StringsQuery::default());
    project.triage();
    assert!(project.analysis_cache_status().program);
    let result = project.patch_bytes(address, original, replacement, false).unwrap();
    assert!(result.changed);
    assert_eq!(result.receipt.active_ranges, 1);
    assert_eq!(result.receipt.changed_bytes, replacement.len());
    assert_ne!(result.receipt.source_sha256, result.receipt.effective_sha256);
    assert!(!result.receipt.original_backing_identity);
    let patched = result.project;
    assert_eq!(patched.analysis_cache_status(), crate::AnalysisCacheStatus::default());
    assert!(!patched.binary.validate_available_backing_source().unwrap());
    assert!(patched.binary.backing_path().is_none());
    let instruction = patched.disassemble(Some(&format!("{address:#x}")), 1).unwrap();
    assert_eq!(instruction[0].bytes, hex(replacement));
    assert!(
        patched
            .function_listing(main)
            .unwrap()
            .blocks
            .into_iter()
            .flatten()
            .any(|line| line.address == address && line.bytes == hex(replacement))
    );
    assert!(patched.functions(&FunctionsQuery::default()).unwrap().items.iter().any(|row| row.address == main));
    assert_return(&patched, 7);
    assert_return(&project, 5);
    assert_eq!(fs::read(&files.source).unwrap(), source_bytes);

    assert_eq!(patched.undo().unwrap()[0].field, Field::Patch);
    let undone = patched.effective_snapshot().unwrap();
    assert!(undone.list_patches().unwrap().is_empty());
    assert_return(&undone, 5);
    assert_return(&patched, 7);
    assert_eq!(undone.redo().unwrap()[0].field, Field::Patch);
    let redone = undone.effective_snapshot().unwrap();
    assert_return(&redone, 7);
    let reverted = redone.revert_patch(address).unwrap();
    assert!(reverted.changed);
    assert_return(&reverted.project, 5);
    reverted.project.undo().unwrap();
    let redone = reverted.project.effective_snapshot().unwrap();
    assert_return(&redone, 7);

    let receipt = redone.patch_receipt().unwrap();
    assert!(redone.export_patched(&files.export, &"0".repeat(64)).is_err());
    assert!(!files.export.exists());
    assert!(redone.export_patched(&files.source, &receipt.revision_sha256).is_err());
    assert_eq!(fs::read(&files.source).unwrap(), source_bytes);
    let exported = redone.export_patched(&files.export, &receipt.revision_sha256).unwrap();
    assert_eq!(exported.receipt, receipt);
    let output = fs::read(&files.export).unwrap();
    assert_eq!(digest(&output), receipt.effective_sha256);
    assert_eq!(&output[offset..offset + replacement.len()], replacement);
    let existing = output.clone();
    assert!(redone.export_patched(&files.export, &receipt.revision_sha256).is_err());
    assert_eq!(fs::read(&files.export).unwrap(), existing);
    let reopened_export = Arc::new(Project::new(Binary::open(&files.export).unwrap()));
    assert!(reopened_export.list_patches().unwrap().is_empty());
    assert_return(&reopened_export, 7);
    assert!(!files.directory.join("export.elf.rampage").exists());
    let reopened_source = files.project().effective_snapshot().unwrap();
    assert_return(&reopened_source, 7);
    assert!(reopened_source.undo().unwrap().is_empty(), "undo history is not durable across a fresh project");
    let session = Session::default();
    let session_project = session.open(&files.source, None).unwrap();
    session_project.set_decompiler_worker(None);
    assert_return(&session_project, 7);
    assert_eq!(fs::read(&files.source).unwrap(), source_bytes);
}

#[test]
fn owned_x64_listing_native_decompile_history_export_and_reopen_share_effective_bytes() {
    roundtrip(Files::new("hello-x64.elf"), 0x100191e, 0x91e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0]);
}

/// A generated static ET_EXEC with a real `main` symbol and MOV/RET payload. The existing hello-arm64 fixture
/// has PT_INTERP/PT_DYNAMIC and is deliberately not relabelled or stripped to pass the static-only profile.
fn static_aarch64_elf() -> Vec<u8> {
    fn put(bytes: &mut [u8], at: usize, value: u64, width: usize) {
        bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }
    let mut bytes = vec![0u8; 0x740];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (at, value, width) in [
        (16, 2, 2),
        (18, 183, 2),
        (20, 1, 4),
        (24, 0x1010534, 8),
        (32, 64, 8),
        (40, 0x600, 8),
        (52, 64, 2),
        (54, 56, 2),
        (56, 1, 2),
        (58, 64, 2),
        (60, 5, 2),
        (62, 4, 2),
        (64, 1, 4),
        (68, 5, 4),
        (80, 0x1010000, 8),
        (88, 0x1010000, 8),
        (96, 0x740, 8),
        (104, 0x740, 8),
        (112, 0x1000, 8),
    ] {
        put(&mut bytes, at, value, width);
    }
    bytes[0x534..0x53c].copy_from_slice(&[0xa0, 0, 0x80, 0x52, 0xc0, 3, 0x5f, 0xd6]);
    put(&mut bytes, 0x568, 1, 4);
    bytes[0x56c] = 0x12;
    put(&mut bytes, 0x56e, 1, 2);
    put(&mut bytes, 0x570, 0x1010534, 8);
    put(&mut bytes, 0x578, 8, 8);
    bytes[0x580..0x586].copy_from_slice(b"\0main\0");
    let names = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";
    bytes[0x590..0x590 + names.len()].copy_from_slice(names);
    for (index, name, kind, flags, address, offset, size, link, info, alignment, entry) in [
        (1, 1, 1, 6, 0x1010534, 0x534, 8, 0, 0, 4, 0),
        (2, 7, 2, 0, 0, 0x550, 48, 3, 1, 8, 24),
        (3, 15, 3, 0, 0, 0x580, 6, 0, 0, 1, 0),
        (4, 23, 3, 0, 0, 0x590, names.len() as u64, 0, 0, 1, 0),
    ] {
        let at = 0x600 + index * 64;
        for (field, value, width) in [
            (0, name, 4),
            (4, kind, 4),
            (8, flags, 8),
            (16, address, 8),
            (24, offset, 8),
            (32, size, 8),
            (40, link, 4),
            (44, info, 4),
            (48, alignment, 8),
            (56, entry, 8),
        ] {
            put(&mut bytes, at + field, value, width);
        }
    }
    bytes
}

#[test]
fn owned_static_aarch64_listing_native_decompile_history_export_and_reopen_share_effective_bytes() {
    roundtrip(
        Files::from_bytes(&static_aarch64_elf()),
        0x1010534,
        0x534,
        &[0xa0, 0, 0x80, 0x52],
        &[0xe0, 0, 0x80, 0x52],
    );
}

#[test]
fn owned_data_requires_consent_and_refreshes_strings_without_mutating_held_views() {
    let files = Files::new("hello-x64.elf");
    let project = files.project();
    let query = StringsQuery { contains: Some("rampage fixture greeting".into()), ..Default::default() };
    let string = project.strings(&query).items.into_iter().next().unwrap();
    let original = b"rampage";
    let replacement = b"patched";
    assert!(project.patch_bytes(string.address, original, replacement, false).is_err());
    let result = project.patch_bytes(string.address, original, replacement, true).unwrap();
    assert_eq!(result.project.strings(&query).total, 0);
    let changed = StringsQuery { contains: Some("patched fixture greeting".into()), ..Default::default() };
    assert_eq!(result.project.strings(&changed).total, 1);
    assert_eq!(project.strings(&query).total, 1);
}

#[test]
fn wrong_preimages_overlaps_headers_boundaries_and_exact_key_resize_never_append() {
    let files = Files::new("hello-x64.elf");
    let project = files.project();
    let at = 0x100191e;
    let original = [0xb8, 5, 0, 0, 0];
    project.patch_bytes(at, &original, &[0xb8, 7, 0, 0, 0], false).unwrap();
    let before = fs::read(&files.log).unwrap();
    for result in [
        project.patch_bytes(at, &[0xb8, 7, 0, 0, 0], &[0xb8, 9, 0, 0, 0], false),
        project.patch_bytes(at + 1, &[5], &[8], false),
        project.patch_bytes(at, &original[..4], &[0xb8, 9, 0, 0], false),
        project.patch_bytes(u64::MAX, &[0], &[1], false),
        project.patch_bytes(at, &[], &[], false),
        project.patch_bytes(at, &original, &[0], false),
    ] {
        assert!(result.is_err());
        assert_eq!(fs::read(&files.log).unwrap(), before);
    }
    let mapped_header = project.binary.segments.iter().find(|segment| segment.file_offset == 0).unwrap().address;
    assert!(project.patch_bytes(mapped_header, &[0x7f], &[0], true).is_err());
    let text = project.binary.sections.iter().find(|section| section.name == ".text").unwrap();
    let at = text.address + text.size - 1;
    let offset = (text.file_offset.unwrap() + text.file_size - 1) as usize;
    let original = &project.binary.file_bytes()[offset..offset + 2];
    let replacement: Vec<_> = original.iter().map(|byte| byte ^ 1).collect();
    assert!(project.patch_bytes(at, original, &replacement, false).is_err());
    assert_eq!(fs::read(&files.log).unwrap(), before);
}

#[test]
fn shared_names_and_comments_preserve_patch_state_and_frozen_read_view() {
    let files = Files::new("hello-x64.elf");
    let first = files.project();
    let second = files.project();
    let result = first.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap();
    let held = result.project;
    let second = second.effective_snapshot().unwrap();
    let patch_revision = second.annotations().patches_revision();
    second.rename(0x100191e, Some("patched_return")).unwrap();
    second.comment(0x100191e, Some("analyst comment")).unwrap();
    let current = held.effective_snapshot().unwrap();
    assert_eq!(held.name_at(0x100191e), None);
    assert_eq!(held.comment_at(0x100191e), None);
    assert_eq!(current.name_at(0x100191e).as_deref(), Some("patched_return"));
    assert_eq!(current.comment_at(0x100191e).as_deref(), Some("analyst comment"));
    assert_eq!(current.patch_receipt().unwrap().revision_sha256, result.receipt.revision_sha256);
    assert!(Arc::ptr_eq(&patch_revision, &second.annotations.read().unwrap().patches_revision()));
    assert_return(&current, 7);
    second.undo().unwrap();
    second.undo().unwrap();
    assert_eq!(current.effective_snapshot().unwrap().list_patches().unwrap().len(), 1);
}

#[test]
fn incompatible_operand_metadata_is_refused_before_append_in_both_orders() {
    let files = Files::new("hello-x64.elf");
    let project = files.project();
    let entry = crate::annotations::OperandTypeAnnotation {
        operand: 0,
        kind: crate::annotations::OperandTypeKind::Enum,
        type_name: "Mode".into(),
        instruction_hex: "b805000000".into(),
    };
    let value = crate::annotations::encode_operand_types(&[entry]).unwrap();
    project.annotations.write().unwrap().set(Field::OperandType, 0x100191e, Some(value.clone())).unwrap();
    let before = fs::read(&files.log).unwrap();
    assert!(project.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).is_err());
    assert_eq!(fs::read(&files.log).unwrap(), before);
    project.annotations.write().unwrap().set(Field::OperandType, 0x100191e, None).unwrap();
    project.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap();
    let before = fs::read(&files.log).unwrap();
    assert!(project.annotations.write().unwrap().set(Field::OperandType, 0x100191e, Some(value)).is_err());
    assert_eq!(fs::read(&files.log).unwrap(), before);
}

#[test]
fn invalid_identity_replay_is_an_error_and_does_not_publish_refreshed_patch_map() {
    let files = Files::new("hello-x64.elf");
    let project = files.project();
    let result = project.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap();
    let valid = result.project.list_patches().unwrap().remove(0);
    let mut wrong = valid.clone();
    wrong.source_sha256 = "f".repeat(64);
    wrong.preimage_sha256 = preimage_digest(&wrong);
    let edit = crate::annotations::Edit {
        field: Field::Patch,
        address: wrong.address,
        value: Some(encode_patch(&wrong).unwrap()),
        previous: Some(encode_patch(&valid).unwrap()),
    };
    let mut file = OpenOptions::new().append(true).open(&files.log).unwrap();
    serde_json::to_writer(&mut file, &edit).unwrap();
    file.write_all(b"\n").unwrap();
    assert!(project.effective_snapshot().is_err());
    assert_eq!(project.annotations.read().unwrap().patches().get(&valid.address), Some(&encode_patch(&valid).unwrap()));
    assert!(Session::default().open(&files.source, None).is_err());
}

#[test]
fn replaced_original_source_refuses_snapshot_history_and_export_without_creating_output() {
    let files = Files::new("hello-x64.elf");
    let project = files.project();
    let patched = project.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap();
    let before = fs::read(&files.log).unwrap();
    let mut replacement = fs::read(&files.source).unwrap();
    replacement[0x91f] = 9;
    let path = files.directory.join("replacement.elf");
    fs::write(&path, replacement).unwrap();
    fs::rename(&path, &files.source).unwrap();
    assert!(patched.project.effective_snapshot().is_err());
    assert!(patched.project.undo().is_err());
    assert!(patched.project.export_patched(&files.export, &patched.receipt.revision_sha256).is_err());
    assert!(!files.export.exists());
    assert_eq!(fs::read(&files.log).unwrap(), before);
}

#[test]
fn unsupported_sources_are_explicitly_rejected() {
    for fixture in [
        "hello-arm64.elf",
        "hello-x64-elf.o",
        "hello-x64.exe",
        "hello-arm64.macho",
        "hello-universal.macho",
        "hello-arm.elf",
    ] {
        let files = Files::new(fixture);
        let project = files.project();
        assert!(project.patch_bytes(0, &[0], &[1], false).is_err(), "{fixture}");
        assert!(!files.log.exists());
    }
}

fn logged_patch() -> (Files, BytePatch) {
    let files = Files::new("hello-x64.elf");
    let project = files.project();
    let outcome = project.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap();
    let patch = outcome.project.list_patches().unwrap().remove(0);
    (files, patch)
}

fn patch_edit(patch: &BytePatch) -> String {
    serde_json::to_string(&crate::annotations::Edit {
        field: Field::Patch,
        address: patch.address,
        value: Some(encode_patch(patch).unwrap()),
        previous: None,
    })
    .unwrap()
}

fn assert_bad_patch_log(files: &Files, bytes: &[u8]) {
    fs::write(&files.log, bytes).unwrap();
    assert!(Annotations::open(files.log.clone()).is_err(), "legacy discovery must not skip invalid patches");
    assert!(Session::default().open(&files.source, None).is_err(), "ordinary session must refuse invalid patches");
}

#[test]
fn review_static_profile_refuses_dynamic_images_and_loader_metadata_disguised_as_payload() {
    let files = Files::new("hello-x64-dyn.elf");
    let source = fs::read(&files.source).unwrap();
    assert!(ElfPayload::parse(&source, Arch::X86_64).is_err());
    let mut et_exec = source;
    et_exec[16..18].copy_from_slice(&2u16.to_le_bytes());
    assert!(ElfPayload::parse(&et_exec, Arch::X86_64).is_err(), "ET_EXEC alone must not admit PT_DYNAMIC/INTERP");
    let files = Files::new("hello-x64.elf");
    let mut source = fs::read(&files.source).unwrap();
    let phoff = uint(&source, 32, 8).unwrap() as usize;
    source[phoff..phoff + 4].copy_from_slice(&2u32.to_le_bytes());
    assert!(ElfPayload::parse(&source, Arch::X86_64).is_err(), "a payload-looking dynamic segment is still refused");
}

#[test]
fn review_numeric_batch_ids_and_mismatched_patch_members_never_become_standalone_edits() {
    let (files, patch) = logged_patch();
    let edit = patch_edit(&patch);
    for batch in ["123", "null", "[]", "\"\"", "{}"] {
        let member = format!("{},\"batch\":{batch}}}", edit.strip_suffix('}').unwrap());
        assert_bad_patch_log(&files, format!("{{\"batch\":\"pair\",\"edits\":2}}\n{member}\n{member}\n").as_bytes());
    }
    let first = format!("{},\"batch\":\"pair\"}}", edit.strip_suffix('}').unwrap());
    let second = format!("{},\"batch\":\"different\"}}", edit.strip_suffix('}').unwrap());
    assert_bad_patch_log(&files, format!("{{\"batch\":\"pair\",\"edits\":2}}\n{first}\n{second}\n").as_bytes());
    assert_bad_patch_log(&files, format!("{{\"batch\":\"pair\",\"edits\":2}}\n{first}\n").as_bytes());
    assert_bad_patch_log(&files, format!("{first}\n").as_bytes());
}

#[test]
fn review_positional_arrays_wrapped_patches_and_scalars_refuse_without_publishing_prefix_or_cursor() {
    let (_payload_files, patch) = logged_patch();
    let array = serde_json::to_string(&serde_json::json!([
        "patch",
        format!("{:#x}", patch.address),
        encode_patch(&patch).unwrap(),
        null
    ]))
    .unwrap();
    let edit = patch_edit(&patch);
    let records = [
        format!("{array}\n"),
        format!("[{edit}]\n"),
        format!("{}\n", edit.replacen("\"field\":\"patch\"", "\"field\":{\"patch\":null}", 1)),
        format!("{{\"wrapped\":{array}}}\n"),
        format!("{{\"wrapped\":{{\"nested\":{edit}}}}}\n"),
        format!("{{\"wrapped\":[{edit}"),
        format!("{{\"batch\":\"pair\",\"edits\":2}}\n{array}\n{array}\n"),
        "null\n".into(),
        "123\n".into(),
        "\"patch\"\n".into(),
    ];
    for record in records {
        assert_rejected_record_is_atomic(&record);
    }
}

fn assert_rejected_record_is_atomic(record: &str) {
    let files = Files::new("hello-x64.elf");
    let project = files.project();
    project.comment(1, Some("before")).unwrap();
    project.refresh_annotations().unwrap();
    let revision = project.authoritative_annotation_revision().unwrap();
    let cursor = project.annotations.read().unwrap().test_log_cursor();
    let mut file = OpenOptions::new().append(true).open(&files.log).unwrap();
    writeln!(
        file,
        "{{\"field\":\"comment\",\"address\":\"0x1\",\"value\":\"must_not_publish\",\"previous\":\"before\"}}"
    )
    .unwrap();
    file.write_all(record.as_bytes()).unwrap();
    assert!(Annotations::open(files.log.clone()).is_err(), "{record}");
    assert!(Session::default().open(&files.source, None).is_err(), "{record}");
    assert!(project.refresh_annotations().is_err(), "{record}");
    let authority = project.annotations.read().unwrap();
    assert_eq!(authority.comment(1), Some("before"), "{record}");
    assert!(authority.patches().is_empty(), "{record}");
    assert_eq!(authority.test_log_cursor(), cursor, "{record}");
    assert!(Arc::ptr_eq(&revision, &authority.revision()), "{record}");
}

#[test]
fn review_single_object_records_reject_concatenated_roots_trailing_tokens_and_malformed_json_atomically() {
    let (_files, patch) = logged_patch();
    let edit = patch_edit(&patch);
    let array = serde_json::to_string(&serde_json::json!([
        "patch",
        format!("{:#x}", patch.address),
        encode_patch(&patch).unwrap(),
        null
    ]))
    .unwrap();
    let comment = "{\"field\":\"comment\",\"address\":\"0x2\",\"value\":\"pending\",\"previous\":null}";
    for root in ["{}", comment, edit.as_str()] {
        for suffix in [array.as_str(), edit.as_str(), "{}", "null", "123", "true", "\"patch\"", "trailing"] {
            for separator in ["", " \t"] {
                for ending in ["", "\n"] {
                    assert_rejected_record_is_atomic(&format!("{root}{separator}{suffix}{ending}"));
                }
            }
        }
    }
    for invalid in ["{broken}\n", "{\"value\":}\n", "{\"value\":[1,]}\n", "{\n"] {
        assert_rejected_record_is_atomic(invalid);
    }
    for valid in ["{}\n", " \t{} \r\n", comment, "{\"text\":\"{}[] not roots\"}"] {
        validate_log_record_root(valid.as_bytes()).unwrap();
    }
}

#[test]
fn review_duplicate_fields_torn_patch_records_and_escaped_keys_refuse_legacy_fallback() {
    let (files, patch) = logged_patch();
    let edit = patch_edit(&patch);
    for replacement in [
        "\"field\":\"patch\",\"field\":\"patch\"",
        "\"field\":\"patch\",\"field\":\"comment\"",
        "\"field\":\"comment\",\"field\":\"patch\"",
        "\"fi\\u0065ld\":\"pa\\u0074ch\",\"field\":\"comment\"",
    ] {
        let line = edit.replacen("\"field\":\"patch\"", replacement, 1);
        assert_bad_patch_log(&files, format!("{line}\n").as_bytes());
    }
    assert_bad_patch_log(&files, edit.as_bytes());
    assert_bad_patch_log(&files, format!("{}\n", edit.strip_prefix('{').unwrap()).as_bytes());
    assert_bad_patch_log(&files, &edit.as_bytes()[..edit.len() - 10]);
    assert_bad_patch_log(&files, b"{\"field\":\"pat");
    fs::write(
        &files.log,
        b"{\"legacy_fragment\":true}\n\
        {\"field\":\"comment\",\"address\":\"0x1\",\"value\":\"kept\",\"previous\":null}\n",
    )
    .unwrap();
    assert_eq!(Annotations::open(files.log.clone()).unwrap().comment(1), Some("kept"));
}

#[test]
fn review_first_byte_discovery_caps_sparse_logs_and_newline_free_suffixes() {
    let files = Files::new("hello-x64.elf");
    File::create(&files.log).unwrap().set_len(128 * 1024 * 1024).unwrap();
    assert!(Annotations::open(files.log.clone()).is_err());
    assert!(Session::default().open(&files.source, None).is_err());
    let mut bytes = b"{\"field\":\"comment\",\"address\":1,\"value\":\"legacy\",\"previous\":null}\n".to_vec();
    bytes.resize(bytes.len() + 2 * 1024 * 1024 + 1, b'x');
    fs::write(&files.log, bytes).unwrap();
    assert!(Annotations::open(files.log.clone()).is_err());
    assert!(Session::default().open(&files.source, None).is_err());
}

#[test]
fn review_export_write_and_sync_failures_never_publish_partial_destinations() {
    let files = Files::new("hello-x64.elf");
    let before: Vec<_> = fs::read_dir(&files.directory).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    for sync_failure in [false, true] {
        let result = publish_export(&files.export, b"complete owned export", |file, bytes| {
            file.write_all(if sync_failure { bytes } else { &bytes[..4] })?;
            Err(std::io::Error::other(if sync_failure { "injected sync failure" } else { "injected write failure" }))
        });
        assert!(result.is_err());
        assert!(!files.export.exists());
        let after: Vec<_> = fs::read_dir(&files.directory).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        assert_eq!(before, after);
    }
}

#[test]
fn review_external_patch_refresh_keeps_original_roots_and_loaded_ledgers_byte_consistent() {
    for explicit_refresh in [false, true] {
        let files = Files::new("hello-x64.elf");
        let held = files.project();
        held.rename(0x100191e, Some("original_label")).unwrap();
        assert_return(&held, 5);
        held.function_listing(held.resolve("main").unwrap()).unwrap();
        let writer = files.project();
        writer.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap();
        writer.rename(0x100191e, Some("new_label")).unwrap();
        if explicit_refresh {
            held.refresh_annotations().unwrap();
        }
        let effective = held.effective_snapshot().unwrap();
        assert_return(&effective, 7);
        assert!(held.list_patches().unwrap().is_empty());
        assert_eq!(held.name_at(0x100191e).as_deref(), Some("original_label"));
        assert_return(&held, 5);
        let loaded_root = files.project();
        assert!(loaded_root.list_patches().unwrap().is_empty());
        assert_return(&loaded_root, 5);
        assert_return(&loaded_root.effective_snapshot().unwrap(), 7);
        held.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 9, 0, 0, 0], false).unwrap();
        assert!(held.list_patches().unwrap().is_empty());
        assert_return(&held, 5);
    }
}

#[test]
fn review_delayed_read_view_cannot_lock_patched_authority_after_original_view_freezes() {
    let files = Files::new("hello-x64.elf");
    let held = files.project();
    let delayed = held.read_annotations_lock();
    held.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap();
    assert!(delayed.read().unwrap().patches().is_empty());
    assert!(delayed.try_read().unwrap().patches().is_empty());
}

#[test]
fn review_rejected_first_patch_refresh_does_not_publish_a_frozen_read_cache() {
    let (other_files, mut patch) = logged_patch();
    let files = Files::new("hello-x64.elf");
    let project = files.project();
    project.rename(0x100191e, Some("before_refusal")).unwrap();
    let before = fs::read(&files.log).unwrap();
    patch.source_sha256 = "f".repeat(64);
    patch.preimage_sha256 = preimage_digest(&patch);
    let mut file = OpenOptions::new().append(true).open(&files.log).unwrap();
    writeln!(file, "{}", patch_edit(&patch)).unwrap();
    assert!(project.refresh_annotations().is_err());
    assert!(project.frozen_annotations.get().is_none());
    assert_eq!(project.name_at(0x100191e).as_deref(), Some("before_refusal"));
    fs::write(&files.log, before).unwrap();
    project.rename(0x100191e, Some("after_refusal")).unwrap();
    assert_eq!(project.name_at(0x100191e).as_deref(), Some("after_refusal"));
    drop(other_files);
}

#[test]
fn review_stale_ssa_and_signature_writers_reject_before_validation_or_append() {
    let files = Files::new("hello-x64.elf");
    let original = files.project();
    let held = original.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap().project;
    let add = held.resolve("add").unwrap();
    let descriptor = held.decompile(add).unwrap().variables.into_iter().find(|variable| variable.editable).unwrap();
    let request = crate::VariableEditRequest {
        storage: descriptor.storage.clone(),
        name: Some("stale_variable".into()),
        ..Default::default()
    };
    let first_instruction = held.disassemble(Some("add"), 1).unwrap().remove(0);
    let original_bytes = decode_hex(&first_instruction.bytes).unwrap();
    let mut replacement = vec![0x90; original_bytes.len()];
    replacement[0] = 0xc3;
    let other = files.project().effective_snapshot().unwrap();
    let current = other.patch_bytes(add, &original_bytes, &replacement, false).unwrap().project;
    assert!(
        !current
            .decompile(add)
            .unwrap()
            .variables
            .iter()
            .any(|variable| variable.editable && variable.storage == descriptor.storage)
    );
    let before = fs::read(&files.log).unwrap();
    let error = held.edit_variable(add, &request).unwrap_err().to_string();
    assert!(error.contains("byte revision is stale"), "{error}");
    assert!(
        held.set_signature(add, Some("int4 add(int4 left, int4 right);"))
            .unwrap_err()
            .to_string()
            .contains("byte revision is stale")
    );
    assert!(held.undo().is_err());
    assert_eq!(fs::read(&files.log).unwrap(), before);
}

#[test]
fn review_history_validates_changed_candidate_bytes_with_fresh_native_context_and_rejects_stale_redo() {
    let files = Files::new("hello-x64.elf");
    let project = files.project();
    let main = project.resolve("main").unwrap();
    project.set_signature(main, Some("int4 main(void);")).unwrap();
    let patched = project.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap().project;
    assert_return(&patched, 7);
    patched.undo().unwrap();
    let restored = patched.effective_snapshot().unwrap();
    assert_return(&restored, 5);
    restored.redo().unwrap();
    let again = restored.effective_snapshot().unwrap();
    assert_return(&again, 7);
    again.undo().unwrap();
    let held_zero = again.effective_snapshot().unwrap();
    let writer = files.project();
    writer.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 9, 0, 0, 0], false).unwrap();
    let before = fs::read(&files.log).unwrap();
    assert!(held_zero.redo().unwrap_err().to_string().contains("byte revision is stale"));
    assert_eq!(fs::read(&files.log).unwrap(), before);
}

#[test]
fn review_workspace_capture_checks_authority_not_frozen_view_and_detects_aba() {
    use crate::{
        ProjectWorkspaceModuleInput, ProjectWorkspaceNavigation, ProjectWorkspacePhase, ProjectWorkspaceTaskControl,
    };
    let files = Files::new("hello-x64.elf");
    let project = files.project();
    let patched = project.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap().project;
    patched.undo().unwrap();
    let restored = patched.effective_snapshot().unwrap();
    let input = ProjectWorkspaceModuleInput {
        id: "main".into(),
        label: "owned".into(),
        source_path: files.source.clone(),
        image: None,
        project: Arc::clone(&restored),
        navigation: ProjectWorkspaceNavigation::default(),
    };
    crate::capture_project_workspace_with_session(std::slice::from_ref(&input), "main", &Session::default()).unwrap();
    for aba in [false, true] {
        let frozen = restored.annotation_revision().unwrap();
        let cancellation = std::sync::atomic::AtomicBool::new(false);
        let mut changed = false;
        let mut observer = |progress: crate::ProjectWorkspaceProgress| {
            if progress.phase == ProjectWorkspacePhase::PreparingDocument {
                restored.comment(0x100191e, Some("changed during capture")).unwrap();
                if aba {
                    restored.comment(0x100191e, None).unwrap();
                }
                changed = true;
            }
        };
        let result = crate::capture_project_workspace_controlled(
            std::slice::from_ref(&input),
            "main",
            &Session::default(),
            &mut ProjectWorkspaceTaskControl::new(&cancellation, &mut observer),
        );
        assert!(changed);
        assert!(result.unwrap_err().to_string().contains("annotations changed during capture"));
        assert!(Arc::ptr_eq(&frozen, &restored.annotation_revision().unwrap()));
        restored.comment(0x100191e, None).unwrap();
    }
}

#[test]
fn review_signature_apply_rechecks_current_names_under_commit_lock_even_after_preflight_callback() {
    let files = Files::new("hello-x64.elf");
    let database = files.project().build_signatures();
    let mut binary = Binary::open(&files.source).unwrap();
    let main = binary.symbols.iter().find(|symbol| symbol.name == "main").unwrap().address;
    binary.function_starts.push(main);
    binary.function_starts.sort_unstable();
    binary.function_starts.dedup();
    binary.symbols.clear();
    binary.exports.clear();
    let target = Arc::new(Project::with_annotations(binary, Annotations::open_checked(files.log.clone()).unwrap()));
    let frozen = target.annotations.read().unwrap().read_snapshot();
    let _ = target.frozen_annotations.set(RwLock::new(frozen));
    let writer = files.project();
    for callback_race in [false, true] {
        writer.rename(main, None).unwrap();
        if !callback_race {
            writer.rename(main, Some("analyst_kept")).unwrap();
        }
        let mut after_preflight_names = 0;
        let application = target
            .identify_functions_with_preflight(Some(&database), false, true, |_| {
                if callback_race {
                    writer.rename(main, Some("analyst_kept")).unwrap();
                }
                after_preflight_names = writer.annotations.read().unwrap().names().len();
                Ok(())
            })
            .unwrap();
        assert!(application.matches.iter().any(|candidate| candidate.address == main && candidate.unnamed));
        let authority = target.annotations.read().unwrap();
        assert_eq!(authority.name(main), Some("analyst_kept"));
        assert_eq!(application.applied, authority.names().len() - after_preflight_names);
    }
}

#[test]
fn review_tokens_are_checked_under_commit_lock_and_held_receipts_match_held_patch_rows() {
    let files = Files::new("hello-x64.elf");
    let original = files.project();
    let receipt = original.patch_receipt().unwrap();
    let second = files.project();
    let changed = second.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap();
    let before = fs::read(&files.log).unwrap();
    assert!(
        original
            .patch_bytes_reviewed(
                0x100191e,
                &[0xb8, 5, 0, 0, 0],
                &[0xb8, 9, 0, 0, 0],
                false,
                &receipt.source_sha256,
                &receipt.revision_sha256
            )
            .is_err()
    );
    assert!(original.revert_patch_reviewed(0x100191e, &receipt.source_sha256, &receipt.revision_sha256).is_err());
    assert!(original.revert_patch_reviewed(0x100191e, &"f".repeat(64), &changed.receipt.revision_sha256).is_err());
    assert!(original.revert_patch_reviewed(0x100191e, "bad", &changed.receipt.revision_sha256).is_err());
    assert_eq!(fs::read(&files.log).unwrap(), before);
    let held = changed.project;
    let held_receipt = held.patch_receipt().unwrap();
    second.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 9, 0, 0, 0], false).unwrap();
    assert_eq!(held.list_patches().unwrap()[0].replacement_hex, "b807000000");
    assert_eq!(held.patch_receipt().unwrap(), held_receipt);
    assert_eq!(held_receipt.effective_sha256, digest(held.binary.file_bytes()));
    assert!(held.revert_patch_reviewed(0x100191e, &held_receipt.source_sha256, &held_receipt.revision_sha256).is_err());
    let fresh = held.effective_snapshot().unwrap();
    let receipt = fresh.patch_receipt().unwrap();
    let result = fresh.revert_patch_reviewed(0x100191e, &receipt.source_sha256, &receipt.revision_sha256).unwrap();
    assert!(result.changed);
    assert_return(&result.project, 5);
}

#[test]
fn review_patch_witness_attributes_own_noops_and_external_metadata_without_rejecting_commit() {
    let files = Files::new("hello-x64.elf");
    let source = files.project();
    let initial = source.patch_receipt().unwrap();
    let bound = source.authoritative_annotation_revision().unwrap();
    let own = source
        .patch_bytes_reviewed(
            0x100191e,
            &[0xb8, 5, 0, 0, 0],
            &[0xb8, 7, 0, 0, 0],
            false,
            &initial.source_sha256,
            &initial.revision_sha256,
        )
        .unwrap();
    assert!(own.changed);
    assert!(Arc::ptr_eq(&bound, &own.before_annotation_revision));
    assert!(!Arc::ptr_eq(&own.before_annotation_revision, &own.after_annotation_revision));
    assert!(Arc::ptr_eq(&own.after_annotation_revision, &own.project.annotation_revision().unwrap()));
    assert!(Arc::ptr_eq(&own.after_annotation_revision, &source.authoritative_annotation_revision().unwrap()));
    let noop = own
        .project
        .patch_bytes_reviewed(
            0x100191e,
            &[0xb8, 5, 0, 0, 0],
            &[0xb8, 7, 0, 0, 0],
            false,
            &own.receipt.source_sha256,
            &own.receipt.revision_sha256,
        )
        .unwrap();
    assert!(!noop.changed);
    assert!(Arc::ptr_eq(&own.after_annotation_revision, &noop.before_annotation_revision));
    assert!(Arc::ptr_eq(&noop.before_annotation_revision, &noop.after_annotation_revision));
    assert!(Arc::ptr_eq(&noop.after_annotation_revision, &noop.project.annotation_revision().unwrap()));

    let external = files.project();
    external.comment(0x100191e, Some("between precheck and no-op transaction")).unwrap();
    let refreshed_noop = noop
        .project
        .patch_bytes_reviewed(
            0x100191e,
            &[0xb8, 5, 0, 0, 0],
            &[0xb8, 7, 0, 0, 0],
            false,
            &noop.receipt.source_sha256,
            &noop.receipt.revision_sha256,
        )
        .unwrap();
    assert!(!refreshed_noop.changed);
    assert!(!Arc::ptr_eq(&noop.after_annotation_revision, &refreshed_noop.before_annotation_revision));
    assert!(Arc::ptr_eq(&refreshed_noop.before_annotation_revision, &refreshed_noop.after_annotation_revision));
    assert_eq!(refreshed_noop.project.comment_at(0x100191e).as_deref(), Some("between precheck and no-op transaction"));

    let bound = Arc::clone(&refreshed_noop.after_annotation_revision);
    external.comment(0x100191e, Some("between precheck and patch transaction")).unwrap();
    let changed = refreshed_noop
        .project
        .patch_bytes_reviewed(
            0x100191e,
            &[0xb8, 5, 0, 0, 0],
            &[0xb8, 9, 0, 0, 0],
            false,
            &refreshed_noop.receipt.source_sha256,
            &refreshed_noop.receipt.revision_sha256,
        )
        .unwrap();
    assert!(changed.changed);
    assert!(!Arc::ptr_eq(&bound, &changed.before_annotation_revision));
    assert!(Arc::ptr_eq(&changed.after_annotation_revision, &changed.project.annotation_revision().unwrap()));
    assert_eq!(changed.project.comment_at(0x100191e).as_deref(), Some("between precheck and patch transaction"));
    assert_return(&changed.project, 9);
    external.comment(0x100191e, Some("after the commit")).unwrap();
    assert!(Arc::ptr_eq(&changed.after_annotation_revision, &changed.project.annotation_revision().unwrap()));
    assert!(!Arc::ptr_eq(&changed.after_annotation_revision, &source.authoritative_annotation_revision().unwrap()));
    assert_eq!(changed.project.comment_at(0x100191e).as_deref(), Some("between precheck and patch transaction"));
}

#[test]
fn review_revert_witness_matches_captured_snapshot_for_own_noop_and_external_name_transitions() {
    let files = Files::new("hello-x64.elf");
    let source = files.project();
    let patched = source.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap();
    let bound = Arc::clone(&patched.after_annotation_revision);
    let own = patched
        .project
        .revert_patch_reviewed(0x100191e, &patched.receipt.source_sha256, &patched.receipt.revision_sha256)
        .unwrap();
    assert!(own.changed);
    assert!(Arc::ptr_eq(&bound, &own.before_annotation_revision));
    assert!(!Arc::ptr_eq(&own.before_annotation_revision, &own.after_annotation_revision));
    assert!(Arc::ptr_eq(&own.after_annotation_revision, &own.project.annotation_revision().unwrap()));
    assert!(Arc::ptr_eq(&own.after_annotation_revision, &source.authoritative_annotation_revision().unwrap()));
    let noop =
        own.project.revert_patch_reviewed(0x100191e, &own.receipt.source_sha256, &own.receipt.revision_sha256).unwrap();
    assert!(!noop.changed);
    assert!(Arc::ptr_eq(&own.after_annotation_revision, &noop.before_annotation_revision));
    assert!(Arc::ptr_eq(&noop.before_annotation_revision, &noop.after_annotation_revision));
    assert!(Arc::ptr_eq(&noop.after_annotation_revision, &noop.project.annotation_revision().unwrap()));

    let patched = noop.project.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap();
    let bound = Arc::clone(&patched.after_annotation_revision);
    files.project().rename(0x100191e, Some("external_before_revert")).unwrap();
    let reverted = patched
        .project
        .revert_patch_reviewed(0x100191e, &patched.receipt.source_sha256, &patched.receipt.revision_sha256)
        .unwrap();
    assert!(reverted.changed);
    assert!(!Arc::ptr_eq(&bound, &reverted.before_annotation_revision));
    assert!(Arc::ptr_eq(&reverted.after_annotation_revision, &reverted.project.annotation_revision().unwrap()));
    assert!(Arc::ptr_eq(&reverted.after_annotation_revision, &source.authoritative_annotation_revision().unwrap()));
    assert_eq!(reverted.project.name_at(0x100191e).as_deref(), Some("external_before_revert"));
    assert_return(&reverted.project, 5);
}
