use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::{Project, SearchRequest, tools};
use rampage_loaders::{Binary, Import, ImportSlot, Symbol, SymbolKind};
use serde_json::{Value, json};

fn binary(regions: &[(u64, &str, &str)], seeds: &[u64]) -> Binary {
    Binary::from_snapshot_bytes(
        serde_json::to_vec(&json!({
            "format":"rampage-snapshot-v1", "arch":"x86_64",
            "provenance":"owned wrapper bytes, not a backing path /untrusted/module",
            "seeds":seeds.iter().map(|at|format!("{at:#x}")).collect::<Vec<_>>(),
            "regions":regions.iter().map(|(at, permissions, bytes)|json!({
                "name":"owned", "address":format!("{at:#x}"), "permissions":permissions, "bytes":bytes
            })).collect::<Vec<_>>()
        }))
        .unwrap(),
    )
    .unwrap()
}

fn request(value: Value) -> SearchRequest {
    SearchRequest::from_json(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn run(project: &Project, value: Value) -> Value {
    project.search_page(&request(value)).unwrap()
}

fn addresses(page: &Value) -> Vec<&str> {
    page["hits"].as_array().unwrap().iter().map(|row| row["address"].as_str().unwrap()).collect()
}

#[test]
fn bytes_context_defaults_on_and_named_half_open_ranges_resolve_without_writes() {
    let mut image = binary(&[(0x1000, "r-x", "b82a000000c3"), (0x2000, "r-x", "b82a000000c3")], &[0x1000, 0x2000]);
    image.symbols.push(Symbol { name: "entry_fn".into(), address: 0x1000, size: 6, kind: SymbolKind::Function });
    let project = Project::new(image);
    let args = json!({"mode":{"kind":"bytes","pattern":"B? 2? ?? 00 00"},
        "range":{"start":"entry_fn","end":"sub_2000"}});
    let page = run(&project, args);
    assert_eq!(addresses(&page), ["0x1000"]);
    assert_eq!(page["hits"][0]["function"]["name"], "entry_fn");
    assert_eq!(page["hits"][0]["function"]["symbol_source"], "loader_name");
    assert_eq!(page["hits"][0]["file_offset"], Value::Null);
    assert_eq!(page["source"]["backing_path"], Value::Null);
    assert_eq!(page["source"]["owned_image"], true);
    assert!(project.undo().unwrap().is_empty());
    let unknown = request(json!({"mode":{"kind":"references","target":"missing_label"}}));
    assert!(project.search_page(&unknown).unwrap_err().to_string().contains("no symbol or export"));
    let page = run(&project, json!({"mode":{"kind":"bytes","pattern":"B8"},"include_context":false}));
    assert!(page["hits"].as_array().unwrap().iter().all(|row| row["function"].is_null()));
}

#[test]
fn unicode_utf16_regex_and_ascii_queries_use_native_encoding_semantics() {
    let text = "Hello 世界 🦀";
    let le: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let be: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
    let project = Project::new(binary(
        &[
            (0x1000, "r--", &rampage_arch::hex::bytes(&le)),
            (0x2000, "r--", &rampage_arch::hex::bytes(&be)),
            (0x3000, "r--", "68656c6c6f"),
        ],
        &[],
    ));
    for (encoding, address) in [("utf16_le", "0x100c"), ("utf16_be", "0x200c")] {
        let page = run(&project, json!({"mode":{"kind":"text","encoding":encoding,"pattern":"世界.*🦀","regex":true}}));
        assert_eq!(addresses(&page), [address]);
        assert_eq!(page["total_is_exact"], true);
    }
    assert_eq!(
        addresses(&run(&project, json!({"mode":{"kind":"text","encoding":"ascii","pattern":"hello"}}))),
        ["0x3000"]
    );
    assert!(project.search_page(&request(json!({"mode":{"kind":"text","encoding":"ascii","pattern":"é"}}))).is_err());
    assert!(
        project
            .search_page(&request(json!({"mode":{"kind":"text","encoding":"utf16_le","pattern":"[","regex":true}})))
            .is_err()
    );
}

#[test]
fn numeric_immediates_width_displacements_globs_and_constant_references_are_not_address_resolution() {
    let project = Project::new(binary(
        &[
            (0x1000, "r-x", "b82a00000083f82a8b432a488d432aeb05b82a000000b8ffffffffc3"),
            (0x2000, "r-x", "b82a000000c3"),
            (0x3000, "r--", "b82a000000c3"),
        ],
        &[0x1000, 0x2000],
    ));
    let immediate = json!({"value":{"kind":"unsigned","value":42}});
    let page = run(&project, json!({"mode":{"kind":"immediate","immediate":immediate}}));
    assert_eq!(addresses(&page), ["0x1000", "0x1005", "0x2000"]);
    let expanded =
        json!({"value":{"kind":"unsigned","value":42},"include_displacements":true,"include_addresses":true});
    assert_eq!(run(&project, json!({"mode":{"kind":"immediate","immediate":expanded}}))["total"], 5);
    let signed = json!({"value":{"kind":"signed","value":-1},"width_bits":32});
    assert_eq!(addresses(&run(&project, json!({"mode":{"kind":"immediate","immediate":signed}}))), ["0x1016"]);
    assert_eq!(
        run(
            &project,
            json!({"mode":{"kind":"immediate","immediate":{"value":{"kind":"signed","value":-1},"width_bits":64}}})
        )["total"],
        0
    );
    let functions = run(
        &project,
        json!({"mode":{"kind":"functions_referencing","reference":{"kind":"constant","immediate":immediate}}}),
    );
    assert_eq!(addresses(&functions), ["0x1000", "0x2000"]);
    let instructions = run(&project, json!({"mode":{"kind":"instruction","mnemonic":"mov*","operands":"eax,*"}}));
    assert_eq!(addresses(&instructions), ["0x1000", "0x1008", "0x1016", "0x2000"]);
    assert!(
        SearchRequest::from_json(
            br#"{"mode":{"kind":"immediate","immediate":{"value":{"kind":"unsigned","value":"entry_fn"}}}}"#
        )
        .is_err()
    );
}

#[test]
fn exact_address_string_and_import_references_keep_native_context_and_identity() {
    let text = rampage_arch::hex::bytes("Hello 世界\0".as_bytes());
    let mut image = binary(
        &[
            (0x1000, "r-x", "488d05f91f0000488d0df21f0000c3"),
            (0x2000, "r-x", "488d05f90f0000c3"),
            (0x3000, "r--", &text),
        ],
        &[0x1000, 0x2000],
    );
    image.symbols.push(Symbol { name: "message".into(), address: 0x3000, size: 1, kind: SymbolKind::Data });
    let project = Project::new(image);
    let exact = run(&project, json!({"mode":{"kind":"references","target":"message"}}));
    assert_eq!(addresses(&exact), ["0x1000", "0x1007", "0x2000"]);
    for reference in
        [json!({"kind":"address","target":"message"}), json!({"kind":"string","text":"世界","encoding":"utf8"})]
    {
        assert_eq!(
            addresses(&run(&project, json!({"mode":{"kind":"functions_referencing","reference":reference}}))),
            ["0x1000", "0x2000"]
        );
    }
    let mut image = binary(
        &[
            (0x1000, "r-x", "e8fb0f0000c3"),
            (0x2000, "r-x", "ff25fa0f0000"),
            (0x3000, "rw-", "00000000000000000000000000000000"),
        ],
        &[0x1000],
    );
    image.imports.push(Import { name: "puts".into(), library: Some("owned-lib".into()) });
    image.import_slots.push(ImportSlot { address: 0x3000, name: "puts".into(), library: Some("owned-lib".into()) });
    image.symbols.push(Symbol { name: "puts".into(), address: 0x2000, size: 6, kind: SymbolKind::Function });
    let project = Project::new(image);
    let query = json!({"mode":{"kind":"functions_referencing","reference":{
        "kind":"import","name":"puts","library":"owned-lib"
    }}});
    assert_eq!(addresses(&run(&project, query)), ["0x1000"]);
    assert_eq!(
        run(
            &project,
            json!({"mode":{"kind":"functions_referencing","reference":{
                "kind":"import","name":"puts","library":"not-owned-lib"
            }}})
        )["total"],
        0
    );
}

#[test]
fn pagination_preserves_exact_and_lower_bound_totals_and_pages_byte_capped_rows() {
    let project = Project::new(binary(&[(0x1000, "r--", &"61".repeat(4096))], &[]));
    let first = run(&project, json!({"mode":{"kind":"bytes","pattern":"61"},"limit":1000}));
    let returned = first["returned"].as_u64().unwrap();
    assert!(returned > 0 && returned < 1000);
    assert!(first.to_string().len() <= 60000);
    assert_eq!(first["total"], 4096);
    assert_eq!(first["total_is_exact"], true);
    assert_eq!(first["byte_capped"], true);
    assert_eq!(first["next_offset"], returned);
    let next = run(&project, json!({"mode":{"kind":"bytes","pattern":"61"},"limit":1,"offset":returned}));
    assert_eq!(next["hits"][0]["address"], format!("{:#x}", 0x1000 + returned));
    for offset in [0, 1] {
        let page = run(
            &project,
            json!({"mode":{"kind":"bytes","pattern":"61"},"limit":1,"offset":offset,"budget":{"match_work":2}}),
        );
        assert_eq!(page["total"], 2);
        assert_eq!(page["total_is_exact"], false);
        assert_eq!(page["stop_reason"], "match_work_budget");
        assert_eq!(page["more"], offset == 0);
    }
    for offset in [0, 1] {
        let page = run(
            &project,
            json!({"mode":{"kind":"bytes","pattern":"61"},
            "limit":1,"offset":offset,"budget":{"results":2}}),
        );
        assert_eq!(page["total"], 3);
        assert_eq!(page["available_hits"], 2);
        assert_eq!(page["unavailable_observed_hits"], 1);
        assert_eq!(page["hits_omitted"], 2);
        assert_eq!(page["total_is_exact"], false);
        assert_eq!(page["stop_reason"], "result_cap");
        assert_eq!(page["more"], offset == 0);
    }
    for bad in [
        json!({"mode":{"kind":"bytes","pattern":"??"}}),
        json!({"mode":{"kind":"bytes","pattern":"61"},"budget":{"match_work":0}}),
        json!({"mode":{"kind":"instruction"}}),
    ] {
        assert!(project.search_page(&request(bad)).is_err());
    }
}

struct OwnedDirectory(PathBuf);
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
#[test]
fn request_files_refuse_links_special_files_and_oversize_and_core_tool_is_discoverable() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let owned = OwnedDirectory(std::env::temp_dir().join(format!(
        "rampage-search-request-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    std::fs::create_dir(&owned.0).unwrap();
    let path = owned.0.join("query.json");
    std::fs::write(&path, br#"{"mode":{"kind":"bytes","pattern":"61"}}"#).unwrap();
    assert!(SearchRequest::from_file(&path).is_ok());
    let link = owned.0.join("link.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(SearchRequest::from_file(&link).is_err());
    assert!(SearchRequest::from_file(std::path::Path::new("/dev/zero")).is_err());
    std::fs::OpenOptions::new().write(true).open(path).unwrap().set_len(1024 * 1024 + 1).unwrap();
    assert!(SearchRequest::from_file(&owned.0.join("query.json")).is_err());
    let registry = tools::tools();
    let search = registry.iter().find(|tool| tool.name == "search").unwrap();
    assert_eq!(search.group, tools::Group::Core);
    let project = Project::new(binary(&[(0x1000, "r--", "61")], &[]));
    let (text, failed) = tools::call(&registry, &project, "search", json!({"mode":{"kind":"bytes","pattern":"61"}}));
    assert!(!failed, "{text}");
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap()["total"], 1);
}
