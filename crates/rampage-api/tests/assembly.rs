use rampage_api::{AssemblyRequest, Project, tools};
use rampage_loaders::{Binary, Symbol, SymbolKind};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn project(arch: &str) -> Project {
    let code = match arch {
        "aarch64" => "00008052c0035fd6",
        "arm" => "0000a0e11eff2fe1",
        _ => "b800000000c3",
    };
    let mut binary = Binary::from_snapshot_bytes(
        serde_json::to_vec(&json!({
            "format":"rampage-snapshot-v1", "arch":arch,
            "provenance":"owned assembly wrapper fixture; never executed",
            "seeds":["0x1000"],"regions":[{
                "name":"code","address":"0x1000","permissions":"r-x","bytes":code
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    binary.symbols.push(Symbol {
        name: "source_function".to_owned(),
        address: 0x1000,
        size: (code.len() / 2) as u64,
        kind: SymbolKind::Function,
    });
    Project::new(binary)
}

fn request(at: &str, source: &str) -> AssemblyRequest {
    AssemblyRequest { at: at.to_owned(), source: source.to_owned() }
}

#[test]
fn known_return_vectors_and_canonical_evidence_follow_the_actual_target() {
    for (arch, source, expected) in [
        ("x86", "mov eax,7\nret", "b807000000c3"),
        ("x86_64", "mov eax,7\nret", "b807000000c3"),
        ("aarch64", "mov w0,7\nret", "e0008052c0035fd6"),
    ] {
        let project = project(arch);
        let before = Sha256::digest(project.binary.file_bytes());
        let report = project.assemble(&request("source_function", source)).unwrap();
        assert_eq!(report.architecture, arch);
        assert_eq!(report.address, 0x1000);
        assert_eq!(report.bytes_hex, expected);
        assert_eq!(rampage_arch::hex::bytes(&report.assembly.bytes), expected);
        assert_eq!(report.assembly.instruction_count, 2);
        assert_eq!(report.assembly.canonical_disassembly.len(), 2);
        assert!(!report.assembly.evidence_profile.is_empty());
        assert!(report.read_only);
        assert!(!report.execution_verified);
        assert_eq!(Sha256::digest(project.binary.file_bytes()), before);
        assert!(!project.analysis_cache_status().program);
        assert!(serde_json::to_vec(&report).unwrap().len() <= 60000);
    }
}

#[test]
fn x86_bitness_and_named_base_are_not_guessed_from_the_assembly_source() {
    let x86 = project("x86");
    assert!(x86.assemble(&request("0x1000", "mov rax,7")).is_err());
    let x64 = project("x86_64");
    assert_eq!(x64.assemble(&request("0x1000", "mov rax,7")).unwrap().bytes_hex, "48b80700000000000000");
    assert_eq!(x64.assemble(&request("source_function", "jmp 0x1010")).unwrap().bytes_hex, "e90b000000");
    let elsewhere = x64.assemble(&request("0x2000", "jmp 0x2010")).unwrap();
    assert_eq!(elsewhere.address, 0x2000);
    assert_eq!(elsewhere.bytes_hex, "e90b000000");
    let error = x64.assemble(&request("0x1000", "jmp source_function")).unwrap_err().to_string();
    assert!(error.contains("assembly line 1"), "{error}");
    assert!(x64.assemble(&request("missing_function", "nop")).unwrap_err().to_string().contains("no symbol or export"));
}

#[test]
fn invalid_batches_and_unsupported_targets_preserve_source_and_analyst_annotations() {
    let project = project("x86_64");
    project.rename(0x1000, Some("analyst_function")).unwrap();
    project.comment(0x1000, Some("preserve this annotation")).unwrap();
    let annotations = serde_json::to_value(project.annotation_list()).unwrap();
    let hash = Sha256::digest(project.binary.file_bytes());
    for source in [
        "nop\ninvalid",
        "nop\nlabel: ret",
        "nop ; comment",
        ".byte 0x90",
        "mov eax,[rax]",
        "/bin/sh",
        "$(touch /must-not-execute)",
        "jmp analyst_function",
    ] {
        assert!(project.assemble(&request("analyst_function", source)).is_err(), "{source}");
        assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), annotations);
        assert_eq!(Sha256::digest(project.binary.file_bytes()), hash);
    }
    let error = project.assemble(&request("analyst_function", "nop\ninvalid")).unwrap_err().to_string();
    assert!(error.contains("assembly line 2"), "{error}");
    assert!(project.assemble(&request("0x1000", &"nop\n".repeat(65))).is_err());
    assert!(project.assemble(&request("0x1000", &" ".repeat(16 * 1024 + 1))).is_err());
    assert!(self::project("arm").assemble(&request("0x1000", "nop")).is_err());
    assert!(self::project("aarch64").assemble(&request("0x1001", "ret")).is_err());
}

#[test]
fn core_tool_is_read_only_and_returns_complete_original_typed_assembly_details() {
    let registry = tools::tools();
    let tool = registry.iter().find(|tool| tool.name == "assemble").unwrap();
    assert_eq!(tool.group, tools::Group::Core);
    assert_eq!(tool.effect, tools::Effect::None);
    let project = project("x86_64");
    let (text, failed) =
        tools::call(&registry, &project, "assemble", json!({"at":"source_function","source":"mov eax,7\nret"}));
    assert!(!failed, "{text}");
    assert!(text.len() <= 60000);
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["bytes_hex"], "b807000000c3");
    assert_eq!(value["bytes"], json!([184, 7, 0, 0, 0, 195]));
    assert_eq!(value["canonical_disassembly"].as_array().unwrap().len(), 2);
    assert_eq!(value["instruction_count"], 2);
    assert_eq!(value["execution_verified"], false);
    let (text, failed) =
        tools::call(&registry, &project, "assemble", json!({"at":"0x1000","source":"nop","apply":true}));
    assert!(failed, "{text}");
}
