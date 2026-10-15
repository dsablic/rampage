//! Synthetic accessor and manually specified replay records; opaque V2 storage is not C++ ABI evidence.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::{DecompileEntryOrigin, DecompileEntryRequest, EntryDecompilation, EntryValidation};

const TYPE_OWNER: u64 = 0x9000_0000;
const READ_COUNT: [u8; 4] = [0x8b, 0x47, 0x08, 0xc3];
const VALIDATIONS: [EntryValidation; 2] = [EntryValidation::MetadataBacked, EntryValidation::AnalystAsserted];

struct EntryFixture {
    image: PathBuf,
    log: PathBuf,
    address: u64,
}

impl EntryFixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let stem = std::env::temp_dir().join(format!("rampage-entry-layout-native-{}-{index}", std::process::id()));
        let original = super::tests::binary();
        original.validate_backing_source().unwrap();
        let symbol = original.symbol_by_name("debug_mix").unwrap();
        let address = symbol.address;
        assert!(symbol.size >= READ_COUNT.len() as u64);
        let segment = original.segment_containing(address).unwrap();
        let offset = usize::try_from(segment.file_offset.checked_add(address - segment.address).unwrap()).unwrap();
        let mut bytes = original.image_bytes().to_vec();
        original.validate_backing_source().unwrap();
        bytes.get_mut(offset..offset + READ_COUNT.len()).unwrap().copy_from_slice(&READ_COUNT);
        let fixture = Self { image: stem.with_extension("elf"), log: stem.with_extension("jsonl"), address };
        // Patch before mapping: checked replay must retain an actual ELF source identity, not owned snapshot bytes.
        let mut output = std::fs::OpenOptions::new().write(true).create_new(true).open(&fixture.image).unwrap();
        output.write_all(&bytes).unwrap();
        fixture
    }

    fn project(&self, annotations: Annotations) -> Project {
        let binary = rampage_loaders::Binary::open(&self.image).unwrap();
        assert_eq!(binary.read(self.address, READ_COUNT.len() as u64).unwrap(), READ_COUNT.as_slice());
        let project = Project::with_annotations(binary, annotations);
        project.set_decompiler_options(Some(rampage_decompiler::DecompilerOptions {
            compiler: Some("gcc".to_owned()),
            ..Default::default()
        }));
        project
    }

    fn reopen(&self) -> Project {
        self.project(Annotations::open_checked(self.log.clone()).unwrap())
    }
}

impl Drop for EntryFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.image);
        let _ = std::fs::remove_file(&self.log);
        let _ = std::fs::remove_file(self.log.with_extension("jsonl.lock"));
    }
}

fn replay_source(project: &Project, ty: &DebugLayoutType, projected: bool, parameter: &str) -> (String, String) {
    let projections = if projected { ty.projections.as_slice() } else { &[] };
    let text = LayoutBundle::encode_entries(&image_digest(project).unwrap(), &[(&ty.layout, projections)]).unwrap();
    let bundle = LayoutBundle::decode(&text).unwrap().unwrap();
    let signature = format!("int4 read_count({} *{parameter});", ty.layout.name);
    let sealed = seal_signature(&signature, &[&bundle.layouts[0]]).unwrap();
    (text, sealed)
}

fn install(project: &Project, address: u64, text: &str, sealed: &str) {
    project
        .annotations
        .write()
        .unwrap()
        .set_batch_validated(
            &[(Field::Types, TYPE_OWNER, Some(text.to_owned())), (Field::Signature, address, Some(sealed.to_owned()))],
            |_| Ok(()),
        )
        .unwrap();
}

fn replace_loaded_source(project: &Project, address: u64, text: &str, sealed: &str) {
    // Model a newly ingested annotation snapshot; public setters would reject a native mismatch before entry replay.
    *project.annotations.write().unwrap() = Annotations::in_memory();
    install(project, address, text, sealed);
}

fn assert_no_inference(project: &Project) {
    assert!(project.cached_analysis().is_none());
    assert!(project.go_prototypes.get().is_none());
}

fn checked_entry(project: &Project, address: u64, validation: EntryValidation, parameter: &str) -> EntryDecompilation {
    let annotations = serde_json::to_value(project.annotation_list()).unwrap();
    let specifications = specification_identity().unwrap();
    assert_no_inference(project);
    let result = project.decompile_entry(&DecompileEntryRequest { address, validation }).unwrap();
    assert_no_inference(project);
    assert_eq!(specification_identity().unwrap(), specifications);
    assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), annotations);
    assert_eq!(result.decompilation.address, address);
    assert_eq!(result.decompilation.language_id, LANGUAGE);
    assert!(result.decompilation.code.contains(&format!("{parameter}->count")), "{}", result.decompilation.code);
    assert_eq!(result.decompilation.structure.signature.return_type.size, 4);
    let parameters = &result.decompilation.structure.signature.parameters;
    assert_eq!(parameters.len(), 1);
    assert_eq!(parameters[0].name, parameter);
    assert_eq!(parameters[0].data_type.size, 8);
    assert_eq!(result.context.scope, "exact_entry");
    assert_eq!(result.context.validation, validation);
    assert_eq!(result.context.execution, "in_process_native");
    assert!(result.context.full_image_mapping && result.context.mapped_backing_checked);
    assert!(result.context.mapped_regions > 0);
    assert!(result.context.mapped_backed_bytes > 0 && result.context.mapped_backed_bytes <= MAX_CHECKED_IMAGE_BYTES);
    assert_eq!(result.context.generated_dependency_types, 0);
    assert!(result.context.origins.contains(&DecompileEntryOrigin::FunctionSymbol));
    assert_eq!(
        result.context.origins.contains(&DecompileEntryOrigin::AnalystAssertion),
        validation == EntryValidation::AnalystAsserted,
    );
    result
}

#[test]
fn entry_native_replays_v1_v2_sealed_layouts_in_both_scopes_and_observes_fresh_signatures() {
    for projected in [false, true] {
        let fixture = EntryFixture::new();
        let project = fixture.project(Annotations::in_memory());
        let ty = super::projected_bundle_tests::projected_type();
        let (text, sealed) = replay_source(&project, &ty, projected, "record");
        assert!(text.starts_with(if projected { TYPE_MAGIC_V2 } else { TYPE_MAGIC }));
        assert!(sealed.starts_with(SIGNATURE_MAGIC));
        install(&project, fixture.address, &text, &sealed);
        let first = checked_entry(&project, fixture.address, VALIDATIONS[0], "record");
        let second = checked_entry(&project, fixture.address, VALIDATIONS[1], "record");
        assert_eq!(first.decompilation.code, second.decompilation.code);
        assert_eq!(first.decompilation.structure, second.decompilation.structure);

        let (_, changed) = replay_source(&project, &ty, projected, "analyst");
        project.annotations.write().unwrap().set(Field::Signature, fixture.address, Some(changed)).unwrap();
        for validation in VALIDATIONS {
            checked_entry(&project, fixture.address, validation, "analyst");
        }
        assert_eq!(project.annotations().types().get(&TYPE_OWNER), Some(&text));
    }
}

#[test]
fn entry_native_checked_bundles_reopen_with_exact_provenance_and_preserve_one_atomic_undo() {
    for projected in [false, true] {
        let fixture = EntryFixture::new();
        let project = fixture.reopen();
        let ty = super::projected_bundle_tests::projected_type();
        let (text, sealed) = replay_source(&project, &ty, projected, "record");
        install(&project, fixture.address, &text, &sealed);
        let original = LayoutBundle::decode(&text).unwrap().unwrap();
        let annotations = serde_json::to_value(project.annotation_list()).unwrap();
        let log = std::fs::read(&fixture.log).unwrap();
        checked_entry(&project, fixture.address, EntryValidation::MetadataBacked, "record");

        let reopened = fixture.reopen();
        assert_eq!(serde_json::to_value(reopened.annotation_list()).unwrap(), annotations);
        {
            let source = reopened.annotations();
            assert_eq!(source.types().get(&TYPE_OWNER), Some(&text));
            assert_eq!(source.signatures().get(&fixture.address), Some(&sealed));
            let persisted = LayoutBundle::decode(source.types().get(&TYPE_OWNER).unwrap()).unwrap().unwrap();
            assert_eq!(persisted.layouts[0].digest, original.layouts[0].digest);
            assert_eq!(persisted.layouts[0].layout, ty.layout);
            let expected_projections = if projected { ty.projections.as_slice() } else { &[] };
            assert_eq!(persisted.layouts[0].projections.as_slice(), expected_projections);
            assert!(matches!(
                &persisted.layouts[0].layout.fields[0].ty,
                LayoutType::Pointer { pointee, .. } if pointee.name == "void" && pointee.kind == ScalarKind::Void
            ));
        }
        for validation in VALIDATIONS {
            checked_entry(&reopened, fixture.address, validation, "record");
        }
        assert_eq!(std::fs::read(&fixture.log).unwrap(), log);
        let edits = project.undo().unwrap();
        assert_eq!(edits.len(), 2);
        assert!(edits.iter().any(|edit| edit.field == Field::Types && edit.value.as_deref() == Some(text.as_str())));
        assert!(
            edits
                .iter()
                .any(|edit| { edit.field == Field::Signature && edit.value.as_deref() == Some(sealed.as_str()) })
        );
        assert!(project.annotation_list().types.is_empty() && project.annotation_list().signatures.is_empty());
        assert!(project.undo().unwrap().is_empty());
        assert!(reopened.refresh_annotations().unwrap());
        assert!(reopened.annotation_list().types.is_empty() && reopened.annotation_list().signatures.is_empty());
        let removed = fixture.reopen();
        assert!(removed.annotation_list().types.is_empty() && removed.annotation_list().signatures.is_empty());
        assert_no_inference(&project);
        assert_no_inference(&reopened);
    }
}

#[test]
fn entry_native_reasserts_wire_valid_field_offsets_on_every_fresh_request() {
    for projected in [false, true] {
        let fixture = EntryFixture::new();
        let project = fixture.project(Annotations::in_memory());
        let ty = super::projected_bundle_tests::projected_type();
        let (text, sealed) = replay_source(&project, &ty, projected, "record");
        install(&project, fixture.address, &text, &sealed);
        let first = checked_entry(&project, fixture.address, EntryValidation::MetadataBacked, "record");
        let mut wrong = ty.clone();
        wrong.layout.fields[1].offset = 12;
        wrong.layout.validate().unwrap();
        let (wrong_text, wrong_seal) = replay_source(&project, &wrong, projected, "record");
        for validation in VALIDATIONS {
            replace_loaded_source(&project, fixture.address, &wrong_text, &wrong_seal);
            validate_entry_replay_source(&project, &project.annotations()).unwrap();
            let annotations = serde_json::to_value(project.annotation_list()).unwrap();
            let error =
                project.decompile_entry(&DecompileEntryRequest { address: fixture.address, validation }).unwrap_err();
            assert!(matches!(&error, ApiError::Invalid(_)), "{error}");
            assert!(error.to_string().contains("checked native counterpart differs"), "{error}");
            assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), annotations);
            assert_no_inference(&project);

            replace_loaded_source(&project, fixture.address, &text, &sealed);
            let repaired = checked_entry(&project, fixture.address, validation, "record");
            assert_eq!(first.decompilation.code, repaired.decompilation.code);
            assert_eq!(first.decompilation.structure, repaired.decompilation.structure);
        }
    }
}

#[test]
fn entry_native_rejects_out_of_bounds_fields_and_stale_context_without_annotation_publication() {
    for projected in [false, true] {
        let fixture = EntryFixture::new();
        let project = fixture.project(Annotations::in_memory());
        let ty = super::projected_bundle_tests::projected_type();
        let (text, sealed) = replay_source(&project, &ty, projected, "record");
        let specifications = current_specification_digest().unwrap();
        for (bad_text, expected) in [
            (text.replacen("\"offset\":8", "\"offset\":16", 1), "invalid field size, offset, overlap or alignment"),
            (text.replace(&specifications, &"0".repeat(64)), "image/specification context"),
        ] {
            assert_ne!(bad_text, text);
            replace_loaded_source(&project, fixture.address, &bad_text, &sealed);
            for validation in VALIDATIONS {
                let annotations = serde_json::to_value(project.annotation_list()).unwrap();
                let error = project
                    .decompile_entry(&DecompileEntryRequest { address: fixture.address, validation })
                    .unwrap_err();
                assert!(matches!(&error, ApiError::Invalid(_)), "{error}");
                assert!(error.to_string().contains(expected), "{error}");
                assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), annotations);
                assert_no_inference(&project);
            }
        }
        replace_loaded_source(&project, fixture.address, &text, &sealed);
        checked_entry(&project, fixture.address, EntryValidation::MetadataBacked, "record");
    }
}
