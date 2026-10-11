use rampage_api::Project;
use rampage_loaders::Binary;

#[test]
fn debug_signature_preview_and_apply_preserve_existing_user_signatures() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
    let project = Project::new(Binary::open(path).unwrap());
    let preview = project.import_debug_signatures(false).unwrap();
    assert!(preview.applied.is_empty());
    assert!(preview.preview.signatures.iter().any(|signature| signature.name == "debug_mix"));
    let address = project.resolve("debug_mix").unwrap();
    let applied = project.import_debug_signatures(true).unwrap();
    assert!(applied.applied.contains(&address));
    let code = project.decompile(address).unwrap().code;
    assert!(code.contains("total") && code.contains("message") && code.contains("delta"), "{code}");
    project.set_signature(address, Some("uint8 custom(uint8 kept,char *text,int4 delta,float8 ratio);")).unwrap();
    let repeated = project.import_debug_signatures(true).unwrap();
    assert!(repeated.applied.is_empty());
    assert!(repeated.preserved.contains(&address));
    assert!(project.decompile(address).unwrap().code.contains("kept"));
}

#[test]
fn debug_function_identifiers_avoid_user_types_and_inline_global_types() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
    let project = Project::new(Binary::open(path).unwrap());
    let address = project.resolve("debug_mix").unwrap();
    project.set_types(address, Some("typedef int4 debug_mix;")).unwrap();
    let data =
        project.binary.segments.iter().find(|segment| !segment.perms.execute && segment.size >= 4).unwrap().address;
    project.set_global(data, Some("struct delta { int4 value; } record;")).unwrap();
    let preview = project.import_debug_signatures(false).unwrap();
    let declaration =
        &preview.preview.signatures.iter().find(|signature| signature.address == address).unwrap().declaration;
    assert!(declaration.contains("debug_signature("), "{declaration}");
    assert!(declaration.contains("debug_param_2"), "{declaration}");
    project.import_debug_signatures(true).unwrap();
    project.decompile(address).unwrap();
}

#[test]
fn debug_parameter_names_avoid_user_type_identifiers() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
    let project = Project::new(Binary::open(path).unwrap());
    let address = project.resolve("debug_mix").unwrap();
    project.set_types(address, Some("typedef int4 delta; typedef int4 debug_param_2;")).unwrap();
    let preview = project.import_debug_signatures(false).unwrap();
    assert!(
        preview
            .preview
            .signatures
            .iter()
            .find(|signature| signature.name == "debug_mix")
            .unwrap()
            .declaration
            .contains("debug_param_2_1")
    );
    project.import_debug_signatures(true).unwrap();
}
