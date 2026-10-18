use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::Command;
use predicates::str::contains;
use serde_json::{Value, json};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-cli-search-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let unicode: Vec<u8> = "世界 🦀".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let snapshot = json!({
            "format":"rampage-snapshot-v1", "arch":"x86_64", "provenance":"owned search CLI fixture /not/a/source/path",
            "seeds":["0x1000","0x2000"], "regions":[
                {"name":"code", "address":"0x1000", "permissions":"r-x", "bytes":"488d05f91f0000b82a000000c3"},
                {"name":"code", "address":"0x2000", "permissions":"r-x", "bytes":"b8ffffffffc3"},
                {"name":"data", "address":"0x3000", "permissions":"r--", "bytes":"48656c6c6f20776f726c6400"},
                {"name":"data", "address":"0x4000", "permissions":"r--", "bytes":rampage_arch::hex::bytes(&unicode)},
                {"name":"data", "address":"0x5000", "permissions":"r--", "bytes":"61616161"}
            ]
        });
        std::fs::write(path.join("owned.json"), serde_json::to_vec(&snapshot).unwrap()).unwrap();
        Self(path)
    }

    fn query(&self, request: Value, nested: bool) -> Value {
        let mut command = Command::cargo_bin("rampage").unwrap();
        if nested {
            command.arg("binary");
        }
        let result = command
            .arg("search")
            .arg(self.0.join("owned.json"))
            .arg("--query-json")
            .arg(request.to_string())
            .assert()
            .success();
        let bytes = &result.get_output().stdout;
        assert!(bytes.len() <= 60001);
        serde_json::from_slice(bytes).unwrap()
    }

    fn assert_unchanged(&self, source: &[u8]) {
        assert_eq!(std::fs::read(self.0.join("owned.json")).unwrap(), source);
        for entry in std::fs::read_dir(&self.0).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!name.ends_with(".jsonl") && !name.ends_with(".lock") && !name.ends_with(".rampage"), "{name}");
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn nested_and_compat_search_resolve_ranges_context_and_all_native_selectors() {
    let fixture = Fixture::new();
    let original = std::fs::read(fixture.0.join("owned.json")).unwrap();
    let bytes =
        json!({"mode":{"kind":"bytes","pattern":"B8 ?? ?? ?? ??"},"range":{"start":"sub_1000","end":"sub_2000"}});
    let nested = fixture.query(bytes.clone(), true);
    assert_eq!(nested, fixture.query(bytes, false));
    assert_eq!(nested["hits"][0]["address"], "0x1007");
    assert_eq!(nested["hits"][0]["function"]["name"], "sub_1000");
    assert_eq!(nested["hits"][0]["function"]["symbol_source"], "synthetic");
    assert_eq!(nested["source"]["backing_path"], Value::Null);
    assert_eq!(nested["hits"][0]["file_offset"], Value::Null);
    for mode in [
        json!({"kind":"text","encoding":"utf16_le","pattern":"世界.*🦀","regex":true}),
        json!({"kind":"text","encoding":"ascii","pattern":"Hello"}),
        json!({"kind":"immediate","immediate":{"value":{"kind":"unsigned","value":42}}}),
        json!({"kind":"immediate","immediate":{"value":{"kind":"signed","value":-1},"width_bits":32}}),
        json!({"kind":"instruction","mnemonic":"mov*","operands":"eax,*"}),
        json!({"kind":"references","target":"0x3000"}),
        json!({"kind":"functions_referencing","reference":{"kind":"address","target":"0x3000"}}),
        json!({"kind":"functions_referencing","reference":{"kind":"string","text":"Hello","encoding":"utf8"}}),
        json!({"kind":"functions_referencing","reference":{"kind":"constant",
            "immediate":{"value":{"kind":"unsigned","value":42}}}}),
    ] {
        let page = fixture.query(json!({"mode":mode}), true);
        assert!(page["total"].as_u64().unwrap() > 0, "{mode}: {page}");
    }
    let elf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
    let elf_bytes = std::fs::read(&elf).unwrap();
    let query = json!({"mode":{"kind":"functions_referencing","reference":{"kind":"import","name":"puts"}}});
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["binary", "search"])
        .arg(&elf)
        .arg("--query-json")
        .arg(query.to_string())
        .assert()
        .success();
    let imports: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert!(imports["total"].as_u64().unwrap() > 0, "{imports}");
    assert_eq!(std::fs::read(elf).unwrap(), elf_bytes);
    fixture.assert_unchanged(&original);
}

#[test]
fn explicit_query_files_preserve_lower_bound_paging_and_bad_requests_never_write() {
    let fixture = Fixture::new();
    let original = std::fs::read(fixture.0.join("owned.json")).unwrap();
    let query = fixture.0.join("query.json");
    let request = json!({"mode":{"kind":"bytes","pattern":"61"},
        "range":{"start":"0x5000","end":20484},"budget":{"match_work":2},"limit":1});
    std::fs::write(&query, request.to_string()).unwrap();
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["binary", "search"])
        .arg(fixture.0.join("owned.json"))
        .arg("--query")
        .arg(&query)
        .assert()
        .success();
    let page: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_eq!(page["total"], 2);
    assert_eq!(page["total_is_exact"], false);
    assert_eq!(page["more"], true);
    assert_eq!(page["next_offset"], 1);
    let mut next = request;
    next["offset"] = json!(1);
    assert_eq!(fixture.query(next, true)["hits"][0]["address"], "0x5001");
    for request in [
        json!({"mode":{"kind":"references","target":"not_a_label"}}),
        json!({"mode":{"kind":"bytes","pattern":"GG"}}),
        json!({"mode":{"kind":"bytes","pattern":"61"},"budget":{"match_work":0}}),
        json!({"mode":{"kind":"bytes","pattern":"61"},"include_context":true,"unknown":1}),
    ] {
        Command::cargo_bin("rampage")
            .unwrap()
            .args(["binary", "search"])
            .arg(fixture.0.join("owned.json"))
            .arg("--query-json")
            .arg(request.to_string())
            .assert()
            .failure();
    }
    #[cfg(unix)]
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["binary", "search"])
        .arg(fixture.0.join("owned.json"))
        .args(["--query", "/dev/zero"])
        .assert()
        .failure()
        .stderr(contains("regular"));
    fixture.assert_unchanged(&original);
}
