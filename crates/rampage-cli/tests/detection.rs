use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn rampage(args: &[&str], file: &str) -> assert_cmd::assert::Assert {
    Command::cargo_bin("rampage").unwrap().args(args).arg(fixture(file)).assert()
}

#[test]
fn user_databases_must_be_bounded_regular_files() {
    rampage(&["detect", "--peid", "/dev/zero"], "hello-x64.exe")
        .failure()
        .stderr(contains("cannot read PeID database /dev/zero: not a regular file"));
    rampage(&["identify", "--db", "/dev/zero"], "hello-x64.elf")
        .failure()
        .stderr(contains("cannot read signature database /dev/zero: not a regular file"));
    rampage(&["compare", "--reference", "/dev/zero"], "hello-x64.elf")
        .failure()
        .stderr(contains("cannot read comparison reference /dev/zero: not a regular file"));
}

fn json(args: &[&str], file: &str) -> serde_json::Value {
    let output = rampage(args, file).success().get_output().stdout.clone();
    serde_json::from_slice(&output).unwrap()
}

/// A scratch directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("rampage-cli-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn arg(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn detect_labels_kind_and_confidence_as_the_json_does() {
    rampage(&["detect"], "hello-x64.exe").success().stdout(contains("[runtime] MinGW-w64 (strong): "));
    let detections = json(&["--json", "detect"], "hello-x64.exe");
    let mingw =
        detections["detections"].as_array().unwrap().iter().find(|detection| detection["name"] == "MinGW-w64").unwrap();
    assert_eq!((mingw["kind"].as_str(), mingw["confidence"].as_str()), (Some("runtime"), Some("strong")));
}

#[test]
fn detect_prints_skipped_peid_entries_as_warnings() {
    let scratch = Scratch::new("peid");
    let peid = scratch.0.join("userdb.txt");
    let entries = "[Broken]\nsignature = ZZ ZZ\nep_only = true\n[Fine]\nsignature = 4D 5A\nep_only = false\n";
    std::fs::write(&peid, entries).unwrap();
    let peid = peid.to_str().unwrap();
    rampage(&["detect", "--peid", peid], "hello-x64.exe")
        .success()
        .stdout(contains("] Fine ("))
        .stdout(contains("warning: PeID database: ").and(contains("[Broken]")));
    let found = json(&["--json", "detect", "--peid", peid], "hello-x64.exe");
    assert_eq!(found["warnings"].as_array().unwrap().len(), 1, "{found}");
}

#[test]
fn yara_scans_a_rule_file_and_a_rule_directory() {
    let rules = Scratch::new("yara");
    std::fs::write(rules.0.join("pe.yar"), "rule pe_header : format { strings: $mz = \"MZ\" condition: $mz at 0 }")
        .unwrap();
    let file = rules.0.join("pe.yar");
    rampage(&["yara", "--rules", file.to_str().unwrap()], "hello-x64.exe")
        .success()
        .stdout(contains("pe_header [format] (1 string matches)"));
    rampage(&["yara", "--rules", rules.arg()], "hello-x64.elf").success().stdout(contains("no rules matched"));
    std::fs::write(rules.0.join("broken.yar"), "rule broken {").unwrap();
    rampage(&["yara", "--rules", rules.arg()], "hello-x64.exe").failure().stderr(contains("YARA rules"));
}

#[test]
fn capa_and_capabilities_render_alike() {
    let rules = Scratch::new("capa");
    std::fs::write(
        rules.0.join("console.yml"),
        "rule:\n  meta:\n    name: write output to console\n    namespace: host-interaction/console\n    \
         scopes:\n      static: file\n  features:\n    - or:\n      - import: puts\n      - import: printf\n",
    )
    .unwrap();
    rampage(&["capa", "--rules", rules.arg()], "hello-x64.exe")
        .success()
        .stdout(contains("[host-interaction] write output to console ("));
    rampage(&["capa", "--rules", rules.arg()], "musl-static-x86_64.elf")
        .success()
        .stdout(contains("no capa rules matched"));
    let capabilities = json(&["--json", "capabilities"], "hello-x64.exe");
    let first = &capabilities[0];
    let line = format!("[{}] {} (", first["category"].as_str().unwrap(), first["name"].as_str().unwrap());
    rampage(&["capabilities"], "hello-x64.exe").success().stdout(contains(line));
}

const ASSEMBLY: &str = "Microsoft.Bcl.HashCode.dll";

fn boxed_attribute_image() -> Vec<u8> {
    boxed_attribute_image_for_enum("Mode", None)
}

fn boxed_attribute_image_for_enum(mode_name: &str, enum_wire_name: Option<&str>) -> Vec<u8> {
    let mut strings = vec![0];
    let mut name = |text: &str| {
        let index = strings.len() as u16;
        strings.extend_from_slice(text.as_bytes());
        strings.push(0);
        index
    };
    let attribute = name("BoxedAttribute");
    let namespace = name("Demo");
    let ctor = name(".ctor");
    let enum_name = name("Enum");
    let system = name("System");
    let mode = name(mode_name);
    let value_field = name("value__");
    let all = name("All");
    let alias = name("Alias");
    let mscorlib = name("mscorlib");
    let mut value = vec![1, 0, 0x08, 42, 0, 0, 0, 2, 0, 0, 0, 0x0E, 2, b'4', b'2'];
    value.extend([0x1D, 0x08, 2, 0, 0, 0]);
    value.extend((-2i32).to_le_bytes());
    value.extend(7i32.to_le_bytes());
    value.extend([if enum_wire_name.is_some() { 3 } else { 2 }, 0, 0x54, 0x51, 5]);
    value.extend(b"Value");
    value.extend([0x50, 11]);
    value.extend(b"Demo.Target");
    value.extend([0x53, 0x1D, 0x51, 5]);
    value.extend(b"Items");
    value.extend([2, 0, 0, 0, 0x0E, 0xFF, 0x02, 1]);
    if let Some(enum_wire_name) = enum_wire_name {
        assert!(enum_wire_name.len() < 0x80);
        value.extend([0x53, 0x55, enum_wire_name.len() as u8]);
        value.extend(enum_wire_name.as_bytes());
        value.push(4);
        value.extend(b"Mode");
        value.extend(u64::MAX.to_le_bytes());
    }
    let mut blobs = vec![0, 6, 0x20, 2, 0x01, 0x1C, 0x1D, 0x1C];
    assert!(value.len() < 0x80);
    blobs.push(value.len() as u8);
    blobs.extend(value);
    let value_signature = blobs.len() as u16;
    blobs.extend([2, 0x06, 0x0B]);
    let literal_signature = blobs.len() as u16;
    blobs.extend([3, 0x06, 0x11, 4]);
    let constant_value = blobs.len() as u16;
    blobs.push(8);
    blobs.extend(u64::MAX.to_le_bytes());
    let present = [(1, 2u32), (2, 1), (4, 3), (10, 1), (11, 2), (12, 1), (35, 1)];
    let valid = present.iter().fold(0u64, |mask, &(table, _)| mask | (1 << table));
    let mut tables = vec![0, 0, 0, 0, 2, 0, 0, 1];
    tables.extend(valid.to_le_bytes());
    tables.extend(0u64.to_le_bytes());
    for &(_, rows) in &present {
        tables.extend(rows.to_le_bytes());
    }
    for row in [
        vec![0, attribute, namespace],
        vec![6, enum_name, system],
        vec![1, 0, mode, namespace, 9, 1, 1],
        vec![0x0606, value_field, value_signature],
        vec![0x8056, all, literal_signature],
        vec![0x8056, alias, literal_signature],
        vec![9, ctor, 1],
        vec![0x0B, 8, constant_value],
        vec![0x0B, 12, constant_value],
        vec![34, 11, 8],
        vec![4, 0, 0, 0, 0, 0, 0, mscorlib, 0, 0],
    ] {
        for column in row {
            tables.extend(column.to_le_bytes());
        }
    }
    let streams: [(&str, &[u8]); 3] = [("#~", &tables), ("#Strings", &strings), ("#Blob", &blobs)];
    let version = b"v4.0.30319\0\0";
    let mut root = b"BSJB\x01\0\x01\0\0\0\0\0".to_vec();
    root.extend((version.len() as u32).to_le_bytes());
    root.extend(version);
    root.extend([0, 0, 3, 0]);
    let mut offset =
        root.len() + streams.iter().map(|(name, _)| 8 + (name.len() + 1).next_multiple_of(4)).sum::<usize>();
    for (name, data) in streams {
        root.extend((offset as u32).to_le_bytes());
        root.extend((data.len() as u32).to_le_bytes());
        root.extend(name.as_bytes());
        root.push(0);
        root.resize(root.len().next_multiple_of(4), 0);
        offset += data.len().next_multiple_of(4);
    }
    for (_, data) in streams {
        root.extend(data);
        root.resize(root.len().next_multiple_of(4), 0);
    }
    let mut image = std::fs::read(fixture(ASSEMBLY)).unwrap();
    let metadata = rampage_loaders::dotnet::parse_image(&image).unwrap().unwrap();
    let start = image.windows(4).position(|bytes| bytes == b"BSJB").unwrap();
    assert!(root.len() <= metadata.cli.metadata_size as usize);
    image[start..start + root.len()].copy_from_slice(&root);
    image
}

#[test]
fn dotnet_renders_typed_boxed_fixed_and_named_values_in_text_and_json() {
    let scratch = Scratch::new("dotnet-boxed");
    let path = scratch.0.join("boxed.dll");
    std::fs::write(&path, boxed_attribute_image()).unwrap();
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["dotnet", "--list", "attributes"])
        .arg(&path)
        .assert()
        .success()
        .stdout(contains("[Demo.BoxedAttribute(box(int32, 42), [box(string, \"42\"), box(int32[], [-2, 7])])]"))
        .stdout(contains("property object \"Value\" = box(System.Type, typeof(Demo.Target))"))
        .stdout(contains("field object[] \"Items\" = [box(string, null), box(bool, true)]"))
        .stdout(contains("unreadable arguments:").not());
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "dotnet", "--list", "attributes"])
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["custom_attributes"]["total"], 1);
    let attribute = &json["custom_attributes"]["items"][0];
    assert_eq!(
        attribute["arguments"],
        serde_json::json!(["box(int32, 42)", "[box(string, \"42\"), box(int32[], [-2, 7])]"])
    );
    assert_eq!(attribute["named_arguments"][0]["argument_type"], "object");
    assert_eq!(attribute["named_arguments"][0]["value"], "box(System.Type, typeof(Demo.Target))");
    assert_eq!(attribute["named_arguments"][1]["value"], "[box(string, null), box(bool, true)]");
}

#[test]
fn dotnet_escaped_local_enum_names_keep_literal_identity_and_exact_values() {
    let scratch = Scratch::new("dotnet-escaped-enum");
    let path = scratch.0.join("escaped.dll");
    for (wire_name, accepted) in [(r"Demo.Mo\+de", true), ("Demo.Mo+de", false), (r"Demo.Mo\+de, Demo", false)] {
        std::fs::write(&path, boxed_attribute_image_for_enum("Mo+de", Some(wire_name))).unwrap();
        let output = Command::cargo_bin("rampage")
            .unwrap()
            .args(["--json", "managed", "inspect"])
            .arg(&path)
            .args(["--list", "attributes"])
            .assert()
            .success()
            .get_output()
            .clone();
        let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let attribute = &summary["custom_attributes"]["items"][0];
        assert_eq!(attribute["arguments"][0], "box(int32, 42)");
        if accepted {
            assert!(attribute["arguments_error"].is_null(), "{summary}");
            assert_eq!(attribute["named_arguments"][2]["argument_type"], r"Demo.Mo\+de");
            assert_eq!(attribute["named_arguments"][2]["value"], r"Demo.Mo\+de(18446744073709551615)");
        } else {
            assert!(attribute["arguments_error"].is_string(), "{summary}");
        }
    }
}

#[test]
fn dotnet_types_render_only_verified_enum_constant_metadata_and_exact_json() {
    let scratch = Scratch::new("dotnet-enum-constants");
    let path = scratch.0.join("enums.dll");
    std::fs::write(&path, boxed_attribute_image()).unwrap();
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["dotnet", "--list", "types", "--contains", "mode"])
        .arg(&path)
        .assert()
        .success()
        .stdout(contains("metadata enum constant All (token 0x04000002): uint64 18446744073709551615"))
        .stdout(contains("metadata enum constant Alias (token 0x04000003): uint64 18446744073709551615"))
        .stdout(contains("value__").not());
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "dotnet", "--list", "types"])
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let fields = &json["types"]["items"][0]["fields"];
    assert!(fields[0].get("enum_constant").is_none());
    assert_eq!(
        fields[1]["enum_constant"],
        serde_json::json!({
            "underlying_integral_type": "uint64", "value": "18446744073709551615"
        })
    );
    assert_eq!(fields[2]["enum_constant"], fields[1]["enum_constant"]);
}

#[test]
fn dotnet_pages_types_and_shows_the_module_and_entry_point() {
    rampage(&["dotnet", "--limit", "2"], ASSEMBLY)
        .success()
        .stdout(contains("assembly   Microsoft.Bcl.HashCode 1.0.0.0"))
        .stdout(contains("module     Microsoft.Bcl.HashCode.dll (mvid "))
        .stdout(contains("entry      none"))
        .stdout(contains(concat!(
            "11 types, 48 methods (48 IL, 0 native), 4 properties, 0 events, ",
            "0 P/Invoke imports, 76 attributes, "
        )))
        .stdout(contains("... 9 more types (page with --list types --offset 2, or filter with --contains)"))
        .stdout(contains("attribute  ").not());
    rampage(&["dotnet", "--limit", "0"], ASSEMBLY).failure().stderr(contains("--limit"));

    let first = json(&["--json", "dotnet", "--limit", "2"], ASSEMBLY);
    let next = json(&["--json", "dotnet", "--offset", "2", "--limit", "2"], ASSEMBLY);
    assert_eq!(next["types"]["offset"], 2);
    assert_eq!(next["types"]["items"].as_array().unwrap().len(), 2);
    assert_ne!(next["types"]["items"][0], first["types"]["items"][0]);
    rampage(&["dotnet", "--offset", "9", "--limit", "5"], ASSEMBLY).success().stdout(contains("more types").not());

    rampage(&["dotnet"], "hello-x64.exe").success().stdout(contains("not a .NET assembly"));
}

#[test]
fn dotnet_il_lists_a_method_a_page_at_a_time() {
    rampage(&["dotnet", "--il", "System.SR::GetResourceString", "--limit", "3"], ASSEMBLY)
        .success()
        .stdout(contains("method     System.SR::GetResourceString (token 0x06"))
        .stdout(contains(".locals init ([0] string V_0)"))
        .stdout(contains(".try IL_0010 to IL_001e catch System.Resources.MissingManifestResourceException"))
        .stdout(contains("IL_0000: call bool System.SR::UsingResourceKeys()\nIL_0005: brfalse.s IL_000e\n"))
        .stdout(contains("more instructions (page with --il System.SR::GetResourceString --offset 3)"));
    let page = json(&["--json", "dotnet", "--il", "0x0600000d", "--offset", "1", "--limit", "1"], ASSEMBLY);
    assert_eq!(page["instructions"]["items"][0]["opcode"], "box");
    assert_eq!(page["instructions"]["items"][0]["token"], 0x1B00_0001);
    rampage(&["dotnet", "--il", "0x0600000d", "--at", "IL_000c", "--limit", "1"], ASSEMBLY)
        .success()
        .stdout(contains("\nIL_000b: ldarga.s 0\n"))
        .stdout(contains("(page with --il 0x0600000d --offset 6)"));
    rampage(&["dotnet", "--il", "0x0600000d", "--at", "IL_000c", "--offset", "2"], ASSEMBLY).failure();
    rampage(&["dotnet", "--at", "0x42"], ASSEMBLY).failure();
    rampage(&["dotnet", "--il", "System.HashCode::Combine"], ASSEMBLY).failure().stderr(contains("0x0600000d"));
    rampage(&["dotnet", "--il", "Main", "--contains", "x"], ASSEMBLY).failure().stderr(contains("cannot be used"));
}

#[test]
fn dotnet_shows_signatures_and_attributes() {
    rampage(&["dotnet", "--contains", "hashcode"], ASSEMBLY)
        .success()
        .stdout(contains("  int32 Combine<T1>(T1)  [value1]  "));
    rampage(&["dotnet", "--list", "attributes", "--contains", "hashcode"], ASSEMBLY)
        .success()
        .stdout(contains("attribute  [System.Reflection.AssemblyTitleAttribute(\"Microsoft.Bcl.HashCode\")] on "))
        .stdout(contains("[System.Diagnostics.DebuggableAttribute (8 byte value, not decoded)]"))
        .stdout(contains("  int32 Combine").not());
    rampage(&["dotnet", "--list", "attributes", "--limit", "5"], ASSEMBLY)
        .success()
        .stdout(contains("... 71 more attributes (page with --list attributes --offset 5, or filter with --contains)"));
    let obsolete = json(&["--json", "dotnet", "--list", "attributes", "--contains", "Obsolete"], ASSEMBLY);
    assert_eq!(obsolete["custom_attributes"]["total"], 2);
    assert!(obsolete.get("types").is_none());
    let token = obsolete["custom_attributes"]["items"][0]["parent_token"].as_u64().unwrap();
    let on_parent =
        json(&["--json", "dotnet", "--list", "attributes", "--parent-token", &format!("{token:#x}")], ASSEMBLY);
    let items = on_parent["custom_attributes"]["items"].as_array().unwrap();
    assert!(!items.is_empty() && items.iter().all(|item| item["parent_token"] == token));
    rampage(&["dotnet", "--list", "pinvokes"], ASSEMBLY).success().stdout(contains("no P/Invoke imports match"));
    rampage(&["dotnet", "--list", "fields"], ASSEMBLY).failure().stderr(contains("unknown list"));
}

#[test]
fn dotnet_resources_selects_an_independent_metadata_only_page_and_preserves_native_empty_output() {
    let resources = json(&["--json", "dotnet", "--list", "resources", "--limit", "1"], ASSEMBLY);
    assert_eq!(resources["list"], "resources");
    assert!(resources.get("types").is_none());
    assert!(resources.get("pinvokes").is_none());
    assert!(resources.get("custom_attributes").is_none());
    let counts = &resources["resource_counts"];
    let items = resources["resources"]["items"].as_array().unwrap();
    assert!(items.len() <= 1);
    assert_eq!(counts["returned"], items.len());
    assert_eq!(counts["retained"], resources["counts"]["resources"]);
    assert_eq!(resources["resources"]["total"], counts["retained"]);
    assert!(counts["declared"].is_u64() && counts["readable"].is_u64() && counts["truncated"].is_boolean());
    assert_eq!(counts["declared_known"], true);
    let inventory = format!(
        "resource metadata: {} declared, {} readable rows, {} retained, {} returned",
        counts["declared"], counts["readable"], counts["retained"], counts["returned"]
    );
    rampage(&["dotnet", "--list", "resources", "--limit", "1"], ASSEMBLY)
        .success()
        .stdout(contains(inventory))
        .stdout(contains(format!(", {} resources", resources["counts"]["resources"])));
    for item in items {
        assert!(item.get("size").is_none() && item.get("payload").is_none());
        assert!(item["implementation"]["kind"].is_string());
        assert!(item["availability"]["kind"].is_string());
    }
    let filter = "rampage-definitely-absent-resource-name";
    let empty = json(&["--json", "dotnet", "--list", "resources", "--contains", filter], ASSEMBLY);
    assert_eq!(empty["resources"]["total"], 0);
    assert_eq!(empty["resource_counts"]["returned"], 0);
    assert_eq!(empty["counts"], resources["counts"]);
    rampage(&["dotnet", "--list", "resources", "--contains", filter], ASSEMBLY)
        .success()
        .stdout(contains("resource metadata:"))
        .stdout(contains("metadata links only"))
        .stdout(contains("resource lengths/payload extents not validated"))
        .stdout(contains("no retained resource rows on this page"));
    assert_eq!(json(&["--json", "dotnet", "--list", "resources"], "hello-x64.exe"), serde_json::Value::Null);
    rampage(&["dotnet", "--list", "resources"], "hello-x64.exe")
        .success()
        .stdout(contains("not a .NET assembly (no CLI header)"));
}

#[test]
fn identify_overlays_or_replaces_the_bundled_database() {
    rampage(&["identify", "--no-bundled"], "hello-x64.elf").failure().stderr(contains("needs a signature database"));
    let bundled = json(&["--json", "identify"], "hello-x64.elf");
    assert!(bundled["matched"].as_u64().unwrap() > 0, "{bundled}");
    rampage(&["identify"], "hello-x64.elf").success().stdout(contains(" matched, 0 applied"));

    let database = std::env::temp_dir().join(format!("rampage-cli-empty-db-{}.json", std::process::id()));
    std::fs::write(&database, r#"{"arch":"x86_64","scheme":2,"entries":{}}"#).unwrap();
    let database_arg = database.to_str().unwrap();
    let overlaid = json(&["--json", "identify", "--db", database_arg], "hello-x64.elf");
    let alone = json(&["--json", "identify", "--db", database_arg, "--no-bundled"], "hello-x64.elf");
    std::fs::remove_file(&database).unwrap();
    assert_eq!(overlaid["matched"], bundled["matched"]);
    assert_eq!(alone["matched"], 0, "{alone}");
}

#[test]
fn binary_build_info_prints_go_modules_and_rust_crates() {
    rampage(&["binary", "build-info"], "buildinfo-go-x64.exe")
        .success()
        .stdout(contains("path       example.com/buildinfo"))
        .stdout(contains("dep        example.com/greet v0.1.0 => ./greet (devel)"))
        .stdout(contains("build      GOOS=windows"))
        .stdout(contains("rust       not present"));
    rampage(&["binary", "build-info", "--offset", "1", "--limit", "1"], "auditable-x64.elf")
        .success()
        .stdout(contains("go         not present"))
        .stdout(contains("root       auditable-fixture 0.1.0"))
        .stdout(contains("crate      serde 1.0.210 crates.io runtime"))
        .stdout(contains("crates     1 shown from 1 of 4"))
        .stdout(contains("crate      cc").not());
    let info = json(&["--json", "binary", "build-info"], "auditable-x64.elf");
    assert_eq!(info["rust"]["packages"]["total"], 4);
    assert_eq!(info["go"], serde_json::Value::Null);
}
