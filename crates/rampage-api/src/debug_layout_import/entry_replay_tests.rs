use super::*;

fn bundle(project: &Project, projected: bool) -> String {
    let ty = super::projected_bundle_tests::projected_type();
    let projections = if projected { ty.projections.as_slice() } else { &[] };
    LayoutBundle::encode_entries(&image_digest(project).unwrap(), &[(&ty.layout, projections)]).unwrap()
}

#[test]
fn entry_replay_keeps_v1_v2_seals_and_opaque_storage_unchanged() {
    let project = Project::new(super::tests::binary());
    for projected in [false, true] {
        let text = bundle(&project, projected);
        let decoded = LayoutBundle::decode(&text).unwrap().unwrap();
        let stored = &decoded.layouts[0];
        let signature_text = format!("int4 method({} *self);", stored.layout.name);
        let sealed = seal_signature(&signature_text, &[stored]).unwrap();
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Types, 0x8000_0000, Some(text.clone())).unwrap();
        annotations.set(Field::Signature, 0x9000_0000, Some(sealed.clone())).unwrap();
        let before = annotations.snapshot();
        validate_entry_replay_source(&project, &annotations).unwrap();
        validate_replay_source(&project, &annotations).unwrap();
        assert_eq!(annotations.types(), before.types());
        assert_eq!(annotations.signatures(), before.signatures());
        assert_eq!(annotations.types().get(&0x8000_0000), Some(&text));
        assert_eq!(annotations.signatures().get(&0x9000_0000), Some(&sealed));
        assert_eq!(stored.projections.is_empty(), !projected);
        assert!(stored_declaration(stored).unwrap().contains("void * rampage_vptr;"));
        let canonical = serde_json::to_string(&stored.layout).unwrap();
        let canonical = if projected {
            format!("{canonical}\n{}", encode_projection_line(&stored.projections).unwrap())
        } else {
            canonical
        };
        let magic = if projected { TYPE_MAGIC_V2 } else { TYPE_MAGIC };
        let identity = format!("{magic}{}\n{LANGUAGE}\n{}\n{canonical}", decoded.image, decoded.specifications);
        assert_eq!(stored.digest, digest_text(identity.as_bytes()));
    }
    assert!(project.cached_analysis().is_none());
    assert!(project.go_prototypes.get().is_none());
}

#[test]
fn malformed_v1_v2_fields_and_stale_context_fail_before_engine_setup() {
    let project = Project::new(super::tests::binary());
    project.set_decompiler_options(Some(rampage_decompiler::DecompilerOptions {
        compiler: Some("entry_must_not_initialize_this_compiler".to_owned()),
        ..Default::default()
    }));
    for projected in [false, true] {
        let original = bundle(&project, projected);
        let bad_field = if projected {
            original.replace("\"name\":\"rampage_vptr\"", "\"name\":\"changed_storage\"")
        } else {
            original.replacen("\"size\":16", "\"size\":0", 1)
        };
        let context = current_specification_digest().unwrap();
        for (text, expected) in [
            (bad_field, if projected { "consumer field name" } else { "size" }),
            (original.replace(&context, &"0".repeat(64)), "image/specification context"),
        ] {
            let mut annotations = Annotations::in_memory();
            annotations.set(Field::Types, 0, Some(text)).unwrap();
            let error = validate_entry_replay_source(&project, &annotations).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
            assert!(!error.contains("entry_must_not_initialize_this_compiler"), "{error}");
        }
    }
    assert!(project.cached_analysis().is_none());
    assert!(project.go_prototypes.get().is_none());
}

#[test]
fn entry_replay_rejects_incompatible_signature_seals_for_both_bundle_versions() {
    let project = Project::new(super::tests::binary());
    for projected in [false, true] {
        let text = bundle(&project, projected);
        let decoded = LayoutBundle::decode(&text).unwrap().unwrap();
        let stored = &decoded.layouts[0];
        let declaration = format!("int4 method({} *self);", stored.layout.name);
        let sealed = seal_signature(&declaration, &[stored]).unwrap().replace(&stored.digest, &"0".repeat(64));
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Types, 0, Some(text)).unwrap();
        annotations.set(Field::Signature, 1, Some(sealed)).unwrap();
        let error = validate_entry_replay_source(&project, &annotations).unwrap_err().to_string();
        assert!(error.contains("missing, incompatible or unused"), "{error}");
    }
}

#[test]
fn entry_replay_retains_image_metadata_and_name_budgets() {
    for (metadata_count, name_bytes, expected) in
        [(8193, 1, "metadata"), (1, 4096, "native name"), (300, 4095, "native name")]
    {
        let mut binary = super::tests::binary();
        let mut symbol = binary.symbols[0].clone();
        symbol.name = "x".repeat(name_bytes);
        binary.symbols = vec![symbol; metadata_count];
        let project = Project::new(binary);
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Types, 0, Some(bundle(&project, false))).unwrap();
        let error = validate_entry_replay_source(&project, &annotations).unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn entry_replay_rechecks_the_retained_image_before_hashing_or_native_work() {
    struct OwnedImage(std::path::PathBuf);
    impl Drop for OwnedImage {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rampage-entry-stale-{}-{index}.elf", std::process::id()));
    let mut output = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
    let _owned = OwnedImage(path.clone());
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
    std::io::copy(&mut std::fs::File::open(fixture).unwrap(), &mut output).unwrap();
    drop(output);
    let project = Project::new(rampage_loaders::Binary::open(&path).unwrap());
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Types, 0, Some(bundle(&project, true))).unwrap();
    validate_entry_replay_source(&project, &annotations).unwrap();
    std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(1).unwrap();
    let error = validate_entry_replay_source(&project, &annotations).unwrap_err().to_string();
    assert!(error.contains("backing file was modified or replaced"), "{error}");
    assert!(project.cached_analysis().is_none());
    assert!(project.go_prototypes.get().is_none());
}

#[test]
fn entry_replay_keeps_checked_aggregate_copy_bounds() {
    struct OwnedImage(std::path::PathBuf);
    impl Drop for OwnedImage {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for (length, aliases, expected) in [
        (MAX_CHECKED_IMAGE_BYTES + 1, 1, "selected image exceeds"),
        (MAX_CHECKED_IMAGE_BYTES / 2, 3, "aggregate mapped bytes"),
    ] {
        let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rampage-entry-replay-{}-{index}.elf", std::process::id()));
        let mut output = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        let _owned = OwnedImage(path.clone());
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
        std::io::copy(&mut std::fs::File::open(fixture).unwrap(), &mut output).unwrap();
        output.set_len(length as u64).unwrap();
        drop(output);
        let mut binary = rampage_loaders::Binary::open(&path).unwrap();
        if aliases > 1 {
            let mut segment = binary.segments[0].clone();
            segment.address = 0x1000;
            segment.file_offset = 0;
            segment.file_size = length as u64;
            segment.size = length as u64;
            segment.perms.read = true;
            binary.segments = vec![segment; aliases];
        }
        let project = Project::new(binary);
        for projected in [false, true] {
            let ty = super::projected_bundle_tests::projected_type();
            let projections = if projected { ty.projections.as_slice() } else { &[] };
            let text = LayoutBundle::encode_entries(&[0; 32], &[(&ty.layout, projections)]).unwrap();
            let mut annotations = Annotations::in_memory();
            annotations.set(Field::Types, 0, Some(text)).unwrap();
            let error = validate_entry_replay_source(&project, &annotations).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
    }
}
