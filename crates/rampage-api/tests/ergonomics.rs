use std::sync::Arc;

use rampage_api::{Project, ToolView, ToolViewKind, project_tool_view, tools};
use rampage_loaders::{Binary, Symbol, SymbolKind};
use serde_json::{Value, json};

fn project() -> Project {
    let mut image = Binary::from_snapshot_bytes(
        serde_json::to_vec(&json!({
            "format":"rampage-snapshot-v1","arch":"x86_64","provenance":"owned ergonomics fixture; never executed",
            "seeds":["0x1000"],"regions":[
                {"name":"code","address":"0x1000","permissions":"r-x","bytes":"b807000000c3"},
                {"name":"data","address":"0x3000","permissions":"rw-","bytes":"0000000000000000"}
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    image.symbols.push(Symbol { name: "entry_name".into(), address: 0x1000, size: 6, kind: SymbolKind::Function });
    Project::new(image)
}

fn call(project: &Project, name: &str, args: Value) -> Value {
    let (text, failed) = tools::call(&tools::tools(), project, name, args);
    assert!(!failed, "{name}: {text}");
    assert!(text.len() <= 60000);
    serde_json::from_str(&text).expect("complete JSON, never a plaintext truncation")
}

fn annotations(project: &Project) -> Value {
    serde_json::to_value(project.annotation_list()).unwrap()
}

fn mixed_entries() -> Value {
    json!([
        {"operation":"rename","at":"sub_1000","value":"reviewed_entry"},
        {"operation":"comment","at":"sub_1000","value":"reviewed together"},
        {"operation":"signature","at":"4097","value":"batch_number reviewed_entry(void);"},
        {"operation":"global","at":"0x3000","value":"batch_number reviewed_counter;"},
        {"operation":"types","at":"sub_1000","value":"typedef int4 batch_number;"}
    ])
}

#[test]
fn five_project_views_delegate_to_one_projection_and_default_full_is_native_json() {
    let project = project();
    let source = project.binary.file_bytes().to_vec();
    let before = annotations(&project);
    let cases = [
        ("binary_info", ToolViewKind::BinaryInfo, serde_json::to_value(project.summary()).unwrap(), json!({})),
        (
            "disassemble",
            ToolViewKind::Disassemble,
            serde_json::to_value(project.disassemble(Some("entry_name"), 2).unwrap()).unwrap(),
            json!({"at":"entry_name","count":2}),
        ),
        (
            "function_graph",
            ToolViewKind::FunctionGraph,
            serde_json::to_value(project.function_graph(0x1000).unwrap()).unwrap(),
            json!({"at":"entry_name"}),
        ),
        (
            "function_summary",
            ToolViewKind::FunctionSummary,
            serde_json::to_value(project.function_summary(0x1000).unwrap()).unwrap(),
            json!({"at":"entry_name"}),
        ),
        (
            "decompile",
            ToolViewKind::Decompile,
            {
                // The tool adds where native code ran; this project has no worker, so in-process.
                let mut raw = serde_json::to_value(project.decompile(0x1000).unwrap()).unwrap();
                raw["decompiler"] = json!("in-process");
                raw
            },
            json!({"at":"entry_name"}),
        ),
    ];
    for (name, kind, raw, args) in cases {
        assert_eq!(call(&project, name, args.clone()), raw, "{name} default full parity");
        for view in [ToolView::Full, ToolView::Summary, ToolView::Code] {
            let mut args = args.clone();
            args["view"] = serde_json::to_value(view).unwrap();
            // function_summary's compact views add its callees and fit rather than refuse.
            let expected = if kind == ToolViewKind::FunctionSummary {
                rampage_api::project_function_summary(raw.clone(), view, rampage_api::SummaryPages::default())
            } else {
                project_tool_view(raw.clone(), kind, view)
            };
            match expected {
                Ok(expected) => assert_eq!(call(&project, name, args), expected, "{name}: {view:?}"),
                Err(_) => {
                    let (text, failed) = tools::call(&tools::tools(), &project, name, args);
                    assert!(failed, "{text}");
                    assert!(text.contains("view=code"), "{text}");
                }
            }
        }
    }
    assert_eq!(annotations(&project), before);
    assert_eq!(project.binary.file_bytes(), source);
}

#[test]
fn standalone_inspect_data_shares_view_schema_projection_and_metadata_code_rejection() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
    let before = std::fs::read(&path).unwrap();
    let image = Binary::open_image_metadata(&path, None, None).unwrap();
    let at = image.entry.unwrap();
    let raw = serde_json::to_value(
        rampage_api::inspect_native_data(&image, &rampage_api::DataQuery { address: at, size: 16, word_size: Some(8) })
            .unwrap(),
    )
    .unwrap();
    let registry = tools::file_tools();
    let tool = registry.iter().find(|tool| tool.name == "inspect_data").unwrap();
    assert!(tool.input_schema["properties"].get("view").is_some());
    for view in [ToolView::Full, ToolView::Summary, ToolView::Code] {
        let result = tool.call(
            &rampage_api::Packs::default(),
            json!({
                "path":path,"at":format!("{at:#x}"),"size":16,"word_size":8,"view":view
            }),
        );
        match project_tool_view(raw.clone(), ToolViewKind::InspectData, view) {
            Ok(expected) => assert_eq!(result.unwrap(), expected),
            Err(_) => assert!(result.unwrap_err().contains("view=code")),
        }
    }
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn oversized_full_result_refuses_instead_of_dispatch_plaintext_cutting() {
    let regions: Vec<_> = (0..1024)
        .map(|index| {
            json!({
                "name":format!("owned_{index}_{}","x".repeat(128)),"address":format!("{:#x}",0x1000+index*0x1000),
                "permissions":"r--","bytes":"00"
            })
        })
        .collect();
    let image = Binary::from_snapshot_bytes(serde_json::to_vec(&json!({
        "format":"rampage-snapshot-v1","arch":"x86_64","provenance":"owned oversized native metadata","regions":regions
    })).unwrap()).unwrap();
    let project = Project::new(image);
    let (text, failed) = tools::call(&tools::tools(), &project, "binary_info", json!({}));
    assert!(failed, "{text}");
    assert!(text.contains("view=summary") && text.contains("no strings were truncated"), "{text}");
    let summary = call(&project, "binary_info", json!({"view":"summary"}));
    assert_eq!(summary["segments_count"], 1024);
    assert_eq!(summary["sections_count"], 1024);
    assert!(!summary["view_projection"]["omissions"].as_array().unwrap().is_empty());
}

#[test]
fn heterogeneous_batch_validates_combined_candidate_resolves_prebatch_names_and_undoes_once() {
    let project = project();
    let before = annotations(&project);
    let source = project.binary.file_bytes().to_vec();
    let result = call(&project, "batch", json!({"entries":mixed_entries()}));
    assert_eq!(result["changed"], 5);
    assert_eq!(result["entries"][2]["address"], "0x1000");
    assert_eq!(project.resolve("reviewed_entry").unwrap(), 0x1000);
    assert_eq!(project.undo().unwrap().len(), 5);
    assert_eq!(annotations(&project), before);
    assert_eq!(project.binary.file_bytes(), source);
}

#[test]
fn rejected_batches_and_oversized_receipts_never_publish_partial_edits() {
    let project = project();
    let before = annotations(&project);
    for entries in [
        json!([{"operation":"rename","at":"sub_1000","value":"would_rename"},{"operation":"comment","at":"sub_1000"}]),
        json!([
            {"operation":"rename","at":"sub_1000","value":"would_rename"},
            {"operation":"signature","at":"sub_1000","value":"not a declaration"}
        ]),
        json!([{"operation":"comment","at":"sub_1000","value":"\"".repeat(30000)}]),
        json!([{"operation":"patch","at":"sub_1000","value":"90"}]),
    ] {
        let (text, failed) = tools::call(&tools::tools(), &project, "batch", json!({"entries":entries}));
        assert!(failed, "{text}");
        assert_eq!(annotations(&project), before);
        assert!(project.undo().unwrap().is_empty());
    }
}

#[test]
fn bound_assistant_retains_batch_outcome_but_does_not_invent_an_exclusive_transition_witness() {
    let mut project = Arc::new(project());
    let expected = project.annotation_revision().unwrap();
    let ((text, failed), revision) = tools::call_shared_bound_revision(
        &tools::tools(),
        &mut project,
        "batch",
        json!({"entries":[{"operation":"comment","at":"sub_1000","value":"committed without an attribution witness"}]}),
        Some(&expected),
    );
    assert!(!failed, "{text}");
    let result: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(result["result"]["changed"], 1);
    assert_eq!(result["post_commit_refresh"]["status"], "unavailable");
    assert_eq!(result["post_commit_refresh"]["rollback_performed"], false);
    assert!(revision.is_none());
    let mut unchanged = Arc::new(self::project());
    let expected = unchanged.annotation_revision().unwrap();
    let ((text, failed), revision) = tools::call_shared_bound_revision(
        &tools::tools(),
        &mut unchanged,
        "batch",
        json!({"entries":[{"operation":"comment","at":"sub_1000","value":null}]}),
        Some(&expected),
    );
    assert!(!failed, "{text}");
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap()["result"]["changed"], 0);
    assert!(revision.is_none());
}
