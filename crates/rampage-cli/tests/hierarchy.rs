use std::path::PathBuf;
use std::process::Output;

use assert_cmd::Command;
use serde_json::Value;

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name).to_str().unwrap().to_owned()
}

fn snapshot() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data/runtime-arm64.snapshot.json")
        .to_str()
        .unwrap()
        .to_owned()
}

fn run(args: &[&str]) -> Output {
    Command::cargo_bin("rampage")
        .unwrap()
        .env_remove("RAMPAGE_PACKS")
        .env_remove("RAMPAGE_MCP_TOOLS")
        .env_remove("CLICOLOR_FORCE")
        .env("NO_COLOR", "1")
        .args(args)
        .write_stdin("")
        .output()
        .unwrap()
}

const MISSING: &str = "/nonexistent/rampage-hierarchy-input";
type Route = (&'static [&'static str], &'static [&'static str], &'static [&'static str]);

const ROUTES: &[Route] = &[
    (&["info"], &["binary", "inspect"], &[MISSING]),
    (&["triage"], &["binary", "triage"], &[MISSING]),
    (&["analyze"], &["binary", "analyze"], &[MISSING, "--workflow", "find-main", "--no-decompile", "--limit", "1"]),
    (&["detect"], &["binary", "detect"], &[MISSING, "--peid", MISSING]),
    (&["capabilities"], &["binary", "capabilities"], &[MISSING]),
    (&["audit"], &["binary", "audit"], &[MISSING, "--include-discovery"]),
    (&["carve"], &["binary", "carve"], &[MISSING, "--max-candidates", "2"]),
    (&["inventory"], &["binary", "inventory"], &[MISSING]),
    (&["imports"], &["binary", "list-imports"], &[MISSING, "--contains", "puts"]),
    (&["exports"], &["binary", "list-exports"], &[MISSING, "--contains", "add"]),
    (&["yara"], &["binary", "scan-yara"], &[MISSING, "--rules", MISSING]),
    (&["capa"], &["binary", "scan-capa"], &[MISSING, "--rules", MISSING]),
    (&["funcs"], &["function", "list"], &[MISSING, "--symbols-only", "--name", "add"]),
    (&["disasm"], &["function", "disassemble"], &[MISSING, "--at", "main", "--count", "2"]),
    (&["decompile"], &["function", "decompile"], &[MISSING, "--at", "main", "--compiler", "gcc"]),
    (&["summarize"], &["function", "summarize"], &[MISSING, "--at", "main"]),
    (&["pseudocode"], &["function", "pseudocode"], &[MISSING, "--at", "0x1000", "--structured"]),
    (&["xrefs"], &["function", "xrefs"], &[MISSING, "--to", "puts"]),
    (&["identify"], &["function", "identify"], &[MISSING, "--db", MISSING, "--no-bundled", "--apply"]),
    (&["signatures"], &["function", "build-signatures"], &[MISSING, "--output", MISSING]),
    (&["compare"], &["function", "compare"], &[MISSING, "--reference", MISSING]),
    (
        &["jump-table"],
        &["function", "inspect-table"],
        &[MISSING, "--at", "0x3000", "--count", "2", "--relative-base", "0x1000"],
    ),
    (&["strings"], &["string", "list"], &[MISSING, "--min-len", "3", "--contains", "hello"]),
    (&["metadata"], &["language", "inspect"], &[MISSING]),
    (
        &["dotnet"],
        &["managed", "inspect"],
        &[MISSING, "--list", "attributes", "--parent-token", "0x2000001", "--offset", "1", "--limit", "2"],
    ),
    (&["dotnet"], &["managed", "disassemble"], &[MISSING, "--il", "0x0600000d", "--at", "IL_000c", "--limit", "1"]),
    (&["annotations"], &["annotation", "list"], &[MISSING]),
    (&["rename"], &["annotation", "rename"], &[MISSING, "main", "entry_name"]),
    (&["comment"], &["annotation", "comment"], &[MISSING, "main", "entry comment"]),
    (&["annotate-batch"], &["annotation", "apply-batch"], &[MISSING, MISSING]),
    (&["check-names"], &["annotation", "check-names"], &[MISSING, "entry_name", "0x1000"]),
    (&["debug-types"], &["type", "import-debug"], &[MISSING, "--apply"]),
    (&["observe-pointer"], &["runtime", "pointer", "observe"], &[MISSING, "--at", "0x3000"]),
    (
        &["compare-pointers"],
        &["runtime", "pointer", "compare"],
        &[MISSING, "--other", MISSING, "--at", "0x3000", "--other-at", "0x1000"],
    ),
    (
        &["observe-indirect-branch"],
        &["runtime", "branch", "inspect"],
        &[MISSING, "--start", "0x1000", "--at", "0x1008"],
    ),
    (
        &["compare-runtime"],
        &["runtime", "bytes", "compare"],
        &[MISSING, "--original", MISSING, "--module", "fixture", "--range", "0x1000:4", "--range", "0x2000:4"],
    ),
    (
        &["correlate"],
        &["runtime", "module", "correlate"],
        &[MISSING, "--original", MISSING, "--module", "fixture", "--at", "0x1000"],
    ),
    (&["packs", "list"], &["pack", "list"], &[]),
    (&["packs", "check"], &["pack", "check"], &[MISSING]),
    (&["report"], &["workflow", "run"], &["find-main", MISSING, "--no-decompile", "--limit", "1"]),
    (&["mcp"], &["server", "serve"], &["--all-tools"]),
];

#[test]
fn every_primary_route_shares_its_legacy_schema_and_normalizes_to_the_same_action() {
    for &(legacy, primary, arguments) in ROUTES {
        let legacy_args: Vec<_> = legacy.iter().copied().chain(arguments.iter().copied()).collect();
        let primary_args: Vec<_> = primary.iter().copied().chain(arguments.iter().copied()).collect();
        assert_same(&legacy_args, &primary_args, legacy == ["packs", "list"]);
        let invalid: Vec<_> =
            primary.iter().copied().chain(["--not-an-option"]).chain(arguments.iter().copied()).collect();
        assert_eq!(run(&invalid).status.code(), Some(2), "{invalid:?}");
        if legacy != ["packs", "list"] && legacy != ["mcp"] {
            assert_eq!(run(primary).status.code(), Some(2), "{primary:?}");
            assert_eq!(run(legacy).status.code(), Some(2), "{legacy:?}");
        }
        let help_args: Vec<_> = primary.iter().copied().chain(["--help"]).collect();
        let help = run(&help_args);
        assert!(help.status.success(), "{help_args:?}");
        let legacy_help: Vec<_> = legacy.iter().copied().chain(["--help"]).collect();
        let legacy_help = String::from_utf8(run(&legacy_help).stdout).unwrap();
        let primary_help = String::from_utf8(help.stdout).unwrap();
        assert_eq!(primary_help.split("Options:\n").nth(1), legacy_help.split("Options:\n").nth(1), "{primary:?}");
    }
}

#[test]
fn every_primary_route_accepts_split_globals_and_applies_normalized_image_restrictions() {
    let first = "/nonexistent/rampage-schema-first-pack";
    let second = "/nonexistent/rampage-schema-second-pack";
    let third = "/nonexistent/rampage-schema-third-pack";
    let globals = [
        "--json",
        "--arch",
        "x86_64",
        "--image-offset",
        "0",
        "--image-length",
        "0",
        "--pack",
        first,
        "--pack",
        second,
        "--pack",
        third,
    ];
    for &(legacy, primary, arguments) in ROUTES {
        let expected_args: Vec<_> =
            globals.into_iter().chain(legacy.iter().copied()).chain(arguments.iter().copied()).collect();
        let expected = run(&expected_args);
        let args: Vec<_> = ["--json", "--image-length", "0", "--pack", first]
            .into_iter()
            .chain([primary[0], "--arch", "x86_64", "--pack", second])
            .chain(primary[1..].iter().copied())
            .chain(["--image-offset", "0", "--pack", third])
            .chain(arguments.iter().copied())
            .collect();
        let actual = run(&args);
        assert_eq!(expected.status.code(), Some(1), "{expected_args:?}");
        assert_eq!(actual.status.code(), expected.status.code(), "{args:?}");
        assert_eq!(actual.stderr, expected.stderr, "{args:?}");
        if legacy == ["analyze"] {
            let mut expected: Value = serde_json::from_slice(&expected.stdout).unwrap();
            let mut actual: Value = serde_json::from_slice(&actual.stdout).unwrap();
            clear_elapsed_times(&mut expected);
            clear_elapsed_times(&mut actual);
            assert_eq!(actual, expected, "{args:?}");
        } else {
            assert_eq!(actual.stdout, expected.stdout, "{args:?}");
        }
    }
}

#[test]
fn new_required_and_conflicting_options_keep_clap_validation() {
    let cases: &[(&[&str], &[&str])] = &[
        (&["summarize"], &[MISSING]),
        (&["pseudocode"], &[MISSING]),
        (&["xrefs"], &[MISSING]),
        (&["xrefs"], &[MISSING, "--to", "puts", "--from", "main"]),
        (&["compare"], &[MISSING]),
        (&["jump-table"], &[MISSING, "--at", "0x3000"]),
        (&["jump-table"], &[MISSING, "--count", "2"]),
        (&["rename"], &[MISSING, "main"]),
        (&["rename"], &[MISSING, "main", "entry_name", "--clear"]),
        (&["comment"], &[MISSING, "main"]),
        (&["comment"], &[MISSING, "main", "entry comment", "--clear"]),
        (&["annotate-batch"], &[MISSING]),
        (&["check-names"], &[MISSING]),
        (&["observe-pointer"], &[MISSING]),
        (&["observe-indirect-branch"], &[MISSING, "--at", "0x1008"]),
        (&["observe-indirect-branch"], &[MISSING, "--start", "0x1000"]),
        (&["compare-runtime"], &[MISSING, "--original", MISSING, "--module", "fixture"]),
        (&["compare-runtime"], &[MISSING, "--module", "fixture", "--range", "0x1000:4"]),
        (&["compare-runtime"], &[MISSING, "--original", MISSING, "--range", "0x1000:4"]),
        (&["correlate"], &[MISSING, "--original", MISSING, "--module", "fixture"]),
        (&["correlate"], &[MISSING, "--original", MISSING, "--at", "0x1000"]),
        (&["correlate"], &[MISSING, "--module", "fixture", "--at", "0x1000"]),
        (&["carve"], &[MISSING, "--max-candidates", "0"]),
        (&["carve"], &[MISSING, "--max-candidates", "4097"]),
    ];
    for &(legacy, arguments) in cases {
        let primary = ROUTES.iter().find(|(route, _, _)| *route == legacy).unwrap().1;
        for route in [legacy, primary] {
            let args: Vec<_> = route.iter().copied().chain(arguments.iter().copied()).collect();
            let output = run(&args);
            assert_eq!(output.status.code(), Some(2), "{args:?}: {}", String::from_utf8_lossy(&output.stderr));
            assert!(output.stdout.is_empty(), "{args:?}");
        }
    }
}

#[test]
fn managed_disassembly_requires_il_before_io_and_keeps_legacy_il_filters_and_paging() {
    let output = run(&["managed", "disassemble", MISSING, "--contains", "x"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires --il"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("cannot open"));
    let assembly = fixture("Microsoft.Bcl.HashCode.dll");
    for paging in [&["--offset", "1"][..], &["--at", "IL_000c"][..]] {
        let arguments: Vec<_> = [&assembly, "--json", "--il", "0x0600000d", "--limit", "1"]
            .into_iter()
            .chain(paging.iter().copied())
            .collect();
        let legacy: Vec<_> = ["dotnet"].into_iter().chain(arguments.iter().copied()).collect();
        let primary: Vec<_> = ["managed", "disassemble"].into_iter().chain(arguments.iter().copied()).collect();
        assert_same(&legacy, &primary, true);
    }
    for options in [
        &["--list", "types"][..],
        &["--contains", "x"][..],
        &["--parent-token", "0x2000001"][..],
        &["--at", "0", "--offset", "0"][..],
    ] {
        let args: Vec<_> =
            ["managed", "disassemble", MISSING, "--il", "Main"].into_iter().chain(options.iter().copied()).collect();
        assert_eq!(run(&args).status.code(), Some(2), "{args:?}");
    }
}

struct FixtureDirectory(PathBuf);

impl FixtureDirectory {
    fn new(name: &str) -> Self {
        let directory = std::env::temp_dir().join(format!("rampage-cli-hierarchy-{name}-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        Self(directory)
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn scaled_read_only_routes_preserve_successful_text_and_json_results() {
    let elf = fixture("hello-x64.elf");
    let exe = fixture("hello-x64.exe");
    let universal = fixture("hello-universal.macho");
    let debug = fixture("debug-x64.elf");
    let capture = snapshot();
    let table = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-jumptable.snapshot.json");
    let table = table.to_str().unwrap();
    let inventory = FixtureDirectory::new("inventory");
    std::fs::copy(&elf, inventory.0.join("fixture.elf")).unwrap();
    let reference = inventory.0.join("reference.json");
    let project = rampage_api::Project::new(rampage_loaders::Binary::open(&elf).unwrap());
    let export = serde_json::json!({
        "tool": "hierarchy-fixture", "version": "1", "arch": "x86_64",
        "image_sha256": project.triage().image_hashes.sha256,
        "functions": [format!("{:#x}", project.resolve("add").unwrap())]
    });
    std::fs::write(&reference, serde_json::to_vec(&export).unwrap()).unwrap();
    let reference = reference.to_str().unwrap();
    let directory = inventory.0.to_str().unwrap();
    let cases: &[(&str, &str, &[&str])] = &[
        ("triage", &elf, &[]),
        ("detect", &exe, &[]),
        ("capabilities", &exe, &[]),
        ("audit", &elf, &["--include-discovery"]),
        ("carve", &universal, &["--max-candidates", "2"]),
        ("inventory", directory, &[]),
        ("imports", &elf, &["--contains", "puts"]),
        ("exports", &exe, &["--contains", "add"]),
        ("funcs", &elf, &["--symbols-only", "--name", "add"]),
        ("disasm", &elf, &["--at", "main", "--count", "2"]),
        ("summarize", &elf, &["--at", "add"]),
        ("pseudocode", &capture, &["--at", "0x1000", "--structured"]),
        ("xrefs", &elf, &["--to", "puts"]),
        ("xrefs", &elf, &["--from", "main"]),
        ("identify", &elf, &[]),
        ("signatures", &elf, &[]),
        ("compare", &elf, &["--reference", reference]),
        ("jump-table", table, &["--at", "0x3000", "--count", "2"]),
        ("strings", &elf, &["--min-len", "3", "--contains", "greeting"]),
        ("metadata", &elf, &[]),
        ("annotations", &elf, &[]),
        ("check-names", &elf, &["entry_name", "main", "0x1000"]),
        ("debug-types", &debug, &[]),
        ("observe-pointer", &capture, &["--at", "0x3000"]),
        ("observe-indirect-branch", &capture, &["--start", "0x1000", "--at", "0x1008"]),
    ];
    for &(legacy, file, arguments) in cases {
        let primary = ROUTES.iter().find(|(route, _, _)| *route == [legacy]).unwrap().1;
        for globals in [&[][..], &["--json"][..]] {
            let legacy_args: Vec<_> =
                globals.iter().copied().chain([legacy, file]).chain(arguments.iter().copied()).collect();
            let primary_args: Vec<_> = globals
                .iter()
                .copied()
                .chain(primary.iter().copied())
                .chain([file])
                .chain(arguments.iter().copied())
                .collect();
            assert_same(&legacy_args, &primary_args, true);
        }
    }
}

#[test]
fn renamed_scan_routes_preserve_explicit_rules() {
    let root = FixtureDirectory::new("scans");
    let yara = root.0.join("pe.yar");
    std::fs::write(&yara, "rule hierarchy_pe { strings: $mz = \"MZ\" condition: $mz at 0 }").unwrap();
    let capa = root.0.join("capa");
    std::fs::create_dir(&capa).unwrap();
    std::fs::write(
        capa.join("console.yml"),
        concat!(
            "rule:\n  meta:\n    name: hierarchy console\n    namespace: host-interaction/console\n",
            "    scopes:\n      static: file\n  features:\n    - or:\n",
            "      - import: puts\n      - import: printf\n"
        ),
    )
    .unwrap();
    let exe = fixture("hello-x64.exe");
    for (legacy, primary, rules) in [("yara", "scan-yara", yara), ("capa", "scan-capa", capa)] {
        let rules = rules.to_str().unwrap();
        for globals in [&[][..], &["--json"][..]] {
            let legacy_args: Vec<_> = globals.iter().copied().chain([legacy, &exe, "--rules", rules]).collect();
            let primary_args: Vec<_> = ["binary"]
                .into_iter()
                .chain(globals.iter().copied())
                .chain([primary, &exe, "--rules", rules])
                .collect();
            let output = assert_same(&legacy_args, &primary_args, true);
            assert!(String::from_utf8_lossy(&output.stdout).contains("hierarchy"));
        }
    }
}

#[test]
fn runtime_module_and_byte_routes_preserve_uuid_matching_and_repeatable_ranges() {
    let root = FixtureDirectory::new("runtime");
    let original_path = fixture("hello-arm64.macho");
    let original = rampage_loaders::Binary::open(&original_path).unwrap();
    let rampage_loaders::Details::MachO(details) = &original.details else { panic!("not Mach-O") };
    let uuid = details.uuid.as_deref().unwrap();
    let image_base =
        original.segments.iter().find(|segment| segment.file_offset == 0 && segment.file_size > 0).unwrap().address;
    let path = root.0.join("snapshot.json");
    let snapshot = serde_json::json!({
        "format": "rampage-snapshot-v1", "arch": "aarch64", "entry": null,
        "provenance": "controlled hierarchy comparison",
        "regions": [{"name": "selected", "address": "0x1000", "permissions": "r--", "bytes": "cffaedfe"}],
        "modules": [{"name": "fixture", "path": "/never/opened", "uuid": uuid,
            "image_base": format!("{image_base:#x}"), "runtime_base": "0x1000"}]
    });
    std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let path = path.to_str().unwrap();
    for (legacy, primary, selection) in [
        (&["correlate"][..], &["runtime", "module", "correlate"][..], &["--at", "0x1000"][..]),
        (
            &["compare-runtime"][..],
            &["runtime", "bytes", "compare"][..],
            &["--range", "0x1000:2", "--range", "0x1002:2"][..],
        ),
    ] {
        let arguments: Vec<_> = [path, "--original", &original_path, "--module", uuid]
            .into_iter()
            .chain(selection.iter().copied())
            .collect();
        for globals in [&[][..], &["--json"][..]] {
            let expected: Vec<_> =
                globals.iter().copied().chain(legacy.iter().copied()).chain(arguments.iter().copied()).collect();
            let actual: Vec<_> = [primary[0], primary[1]]
                .into_iter()
                .chain(globals.iter().copied())
                .chain([primary[2]])
                .chain(arguments.iter().copied())
                .collect();
            assert_same(&expected, &actual, true);
        }
    }
}

#[test]
fn pack_aliases_merge_split_flags_and_keep_check_exit_behavior() {
    let root = FixtureDirectory::new("packs");
    std::fs::write(
        root.0.join("rampage-pack.toml"),
        concat!(
            "name = \"hierarchy-fixture\"\nversion = \"1\"\nlicense = \"CC0-1.0\"\n",
            "source = \"https://example.com/fixture\"\ndescription = \"CLI fixture\"\n",
            "[[contents]]\nkind = \"yara\"\npath = \"pe.yar\"\n"
        ),
    )
    .unwrap();
    std::fs::write(root.0.join("pe.yar"), "rule hierarchy_pe { strings: $mz = \"MZ\" condition: $mz at 0 }").unwrap();
    let directory = root.0.to_str().unwrap();
    assert_same(&["packs", "check", directory], &["pack", "check", directory], true);
    let first = "/nonexistent/rampage-pack-first";
    let second = "/nonexistent/rampage-pack-second";
    assert_same(
        &["--json", "packs", "list", "--pack", first, "--pack", directory, "--pack", second],
        &["--pack", first, "pack", "--pack", directory, "list", "--json", "--pack", second],
        true,
    );
    assert_same(&["packs", "check", first], &["pack", "check", first], false);
}

fn clear_elapsed_times(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove("elapsed_ms");
            for value in object.values_mut() {
                clear_elapsed_times(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                clear_elapsed_times(value);
            }
        }
        _ => {}
    }
}

#[test]
fn binary_analyze_shares_parent_arguments_and_preserves_batch_results() {
    let universal = fixture("hello-universal.macho");
    let arguments =
        [&universal, "--workflow", "find-main", "--workflow", "network-surface", "--no-decompile", "--limit", "1"];
    let legacy: Vec<_> = ["--json", "--arch", "aarch64", "analyze"].into_iter().chain(arguments).collect();
    let primary: Vec<_> = ["--json", "binary", "--arch", "aarch64", "analyze"].into_iter().chain(arguments).collect();
    let legacy = run(&legacy);
    let primary = run(&primary);
    assert!(legacy.status.success(), "{}", String::from_utf8_lossy(&legacy.stderr));
    assert_eq!(primary.status.code(), legacy.status.code());
    assert_eq!(primary.stderr, legacy.stderr);
    let mut legacy: Value = serde_json::from_slice(&legacy.stdout).unwrap();
    let mut primary: Value = serde_json::from_slice(&primary.stdout).unwrap();
    clear_elapsed_times(&mut legacy);
    clear_elapsed_times(&mut primary);
    assert_eq!(primary, legacy);
    assert_eq!(primary["completed_tasks"], 2);
    assert_eq!(primary["targets"][0]["arch"], "aarch64");
    for arguments in [
        &["--workflow", "unknown-workflow"][..],
        &["--decompile-timeout-ms", "0"][..],
        &["--other-image-length", "1"][..],
    ] {
        for route in [&["analyze"][..], &["binary", "analyze"][..]] {
            let args: Vec<_> = route.iter().copied().chain([MISSING]).chain(arguments.iter().copied()).collect();
            assert_eq!(run(&args).status.code(), Some(2), "{args:?}");
        }
    }
}

#[test]
fn explicit_annotation_and_debug_apply_flags_preserve_side_effects() {
    let root = FixtureDirectory::new("edits");
    let file = root.0.join("fixture.elf");
    std::fs::copy(fixture("debug-x64.elf"), &file).unwrap();
    let file = file.to_str().unwrap();
    let annotations = root.0.join("fixture.elf.rampage");
    let entries = root.0.join("entries.json");
    std::fs::write(&entries, r#"[{"at":"main","name":"entry_name","comment":"entry comment"}]"#).unwrap();
    let entries = entries.to_str().unwrap();
    let cases: &[(&str, &[&str])] = &[
        ("rename", &["main", "entry_name"]),
        ("comment", &["main", "entry comment"]),
        ("rename", &["main", "--clear"]),
        ("comment", &["main", "--clear"]),
        ("annotate-batch", &[entries]),
        ("debug-types", &["--apply"]),
    ];
    for &(legacy, arguments) in cases {
        let primary = ROUTES.iter().find(|(route, _, _)| *route == [legacy]).unwrap().1;
        for globals in [&[][..], &["--json"][..]] {
            let execute = |route: &[&str]| {
                if arguments.contains(&"--clear") {
                    let seed = if legacy == "rename" { "rename" } else { "comment" };
                    let value = if legacy == "rename" { "seed_name" } else { "seed comment" };
                    assert!(run(&[seed, file, "main", value]).status.success());
                }
                let args: Vec<_> = globals
                    .iter()
                    .copied()
                    .chain(route.iter().copied())
                    .chain([file])
                    .chain(arguments.iter().copied())
                    .collect();
                let result = run(&args);
                assert!(result.status.success(), "{args:?}: {}", String::from_utf8_lossy(&result.stderr));
                result
            };
            let expected = execute(&[legacy]);
            std::fs::remove_file(&annotations).unwrap();
            let actual = execute(primary);
            assert_eq!(actual.stdout, expected.stdout, "{primary:?}");
            assert_eq!(actual.stderr, expected.stderr, "{primary:?}");
            assert_same(&["annotations", file], &["annotation", "list", file], true);
            std::fs::remove_file(&annotations).unwrap();
        }
    }
}

fn assert_same(legacy: &[&str], hierarchy: &[&str], success: bool) -> Output {
    let expected = run(legacy);
    let actual = run(hierarchy);
    assert_eq!(expected.status.success(), success, "{legacy:?}: {}", String::from_utf8_lossy(&expected.stderr));
    assert_eq!(actual.status.code(), expected.status.code(), "{hierarchy:?}");
    assert_eq!(actual.stdout, expected.stdout, "{hierarchy:?}");
    assert_eq!(actual.stderr, expected.stderr, "{hierarchy:?}");
    actual
}

#[test]
fn five_routes_preserve_text_and_json_outputs() {
    let elf = fixture("hello-x64.elf");
    let assembly = fixture("Microsoft.Bcl.HashCode.dll");
    let capture = snapshot();
    let routes: [(&[&str], &[&str]); 5] = [
        (&["info", &elf], &["binary", "inspect", &elf]),
        (
            &["decompile", &elf, "--at", "add", "--compiler", "gcc"],
            &["function", "decompile", &elf, "--at", "add", "--compiler", "gcc"],
        ),
        (
            &["compare-pointers", &capture, "--other", &capture, "--at", "0x3000", "--other-at", "0x1000"],
            &["runtime", "pointer", "compare", &capture, "--other", &capture, "--at", "0x3000", "--other-at", "0x1000"],
        ),
        (
            &["report", "find-main", &elf, "--no-decompile", "--limit", "1"],
            &["workflow", "run", "find-main", &elf, "--no-decompile", "--limit", "1"],
        ),
        (&["dotnet", &assembly, "--limit", "2"], &["managed", "inspect", &assembly, "--limit", "2"]),
    ];
    for (legacy, hierarchy) in routes {
        assert_same(legacy, hierarchy, true);
        let legacy_json: Vec<_> = ["--json"].into_iter().chain(legacy.iter().copied()).collect();
        let hierarchy_json: Vec<_> = ["--json"].into_iter().chain(hierarchy.iter().copied()).collect();
        let output = assert_same(&legacy_json, &hierarchy_json, true);
        serde_json::from_slice::<Value>(&output.stdout).unwrap();
    }
}

#[test]
fn five_routes_preserve_file_open_errors() {
    let missing = "/nonexistent/rampage-hierarchy-binary";
    let routes: [(&[&str], &[&str]); 5] = [
        (&["info", missing], &["binary", "inspect", missing]),
        (&["decompile", missing, "--at", "main"], &["function", "decompile", missing, "--at", "main"]),
        (
            &["compare-pointers", missing, "--other", missing, "--at", "0", "--other-at", "0"],
            &["runtime", "pointer", "compare", missing, "--other", missing, "--at", "0", "--other-at", "0"],
        ),
        (&["report", "find-main", missing], &["workflow", "run", "find-main", missing]),
        (&["dotnet", missing], &["managed", "inspect", missing]),
    ];
    for (legacy, hierarchy) in routes {
        let output = assert_same(legacy, hierarchy, false);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains(missing));
    }
}

#[test]
fn decompile_keeps_isolated_worker_selection_and_compiler_errors() {
    let elf = fixture("hello-x64.elf");
    let arguments = [&elf, "--at", "add", "--compiler", "gcc", "--isolated"];
    let invoke = |route: &[&str]| {
        Command::cargo_bin("rampage")
            .unwrap()
            .env_remove("RAMPAGE_PACKS")
            .env("RAMPAGE_WORKER", "/nonexistent/rampage-worker")
            .args(route)
            .args(arguments)
            .output()
            .unwrap()
    };
    let legacy = invoke(&["decompile"]);
    let hierarchy = invoke(&["function", "decompile"]);
    assert_eq!(legacy.status.code(), Some(1));
    assert_eq!(hierarchy.status.code(), legacy.status.code());
    assert_eq!(hierarchy.stdout, legacy.stdout);
    assert_eq!(hierarchy.stderr, legacy.stderr);
    assert!(String::from_utf8_lossy(&hierarchy.stderr).contains("worker"));
    assert_same(
        &["decompile", &elf, "--at", "add", "--compiler", "no-such-compiler"],
        &["function", "decompile", &elf, "--at", "add", "--compiler", "no-such-compiler"],
        false,
    );
}

#[test]
fn managed_inspection_preserves_metadata_filters_and_paging() {
    let assembly = fixture("Microsoft.Bcl.HashCode.dll");
    let filters: [&[&str]; 4] = [
        &["--contains", "hashcode", "--offset", "1", "--limit", "2"],
        &["--list", "attributes", "--contains", "Obsolete", "--limit", "1"],
        &["--list", "pinvokes", "--contains", "hashcode"],
        &["--list", "attributes", "--parent-token", "0x2000001", "--offset", "1", "--limit", "2"],
    ];
    for filters in filters {
        let legacy: Vec<_> = ["--json", "dotnet", &assembly].into_iter().chain(filters.iter().copied()).collect();
        let hierarchy: Vec<_> =
            ["managed", "inspect", &assembly, "--json"].into_iter().chain(filters.iter().copied()).collect();
        assert_same(&legacy, &hierarchy, true);
    }
    let output = run(&["managed", "inspect", &assembly, "--json", "--contains", "hashcode", "--limit", "1"]);
    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(metadata["types"]["items"].as_array().unwrap().len(), 1);
    assert!(metadata["types"]["items"][0].to_string().to_lowercase().contains("hashcode"));
}

#[test]
fn managed_inspect_rejects_il_before_opening_or_loading_packs() {
    let output = run(&[
        "managed",
        "--pack",
        "/nonexistent/rampage-pack",
        "inspect",
        "/nonexistent/rampage-binary",
        "--il",
        "0x0600000d",
        "--image-offset",
        "17",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("managed inspect does not accept --il"), "{error}");
    assert!(!error.contains("cannot open"), "{error}");
    assert!(!error.contains("warning"), "{error}");
}

#[test]
fn legacy_dotnet_retains_il_mode_and_instruction_paging() {
    let assembly = fixture("Microsoft.Bcl.HashCode.dll");
    for paging in [&["--offset", "1"][..], &["--at", "IL_000c"][..]] {
        let args: Vec<_> = ["dotnet", &assembly, "--json", "--il", "0x0600000d", "--limit", "1"]
            .into_iter()
            .chain(paging.iter().copied())
            .collect();
        let output = run(&args);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let il: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(il["instructions"]["items"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn required_arguments_are_still_checked_by_clap() {
    let missing = "/nonexistent/rampage-binary";
    let cases: &[&[&str]] = &[
        &["binary", "inspect"],
        &["info"],
        &["function", "decompile", missing],
        &["decompile", missing],
        &["managed", "inspect"],
        &["dotnet"],
        &["workflow", "run"],
        &["workflow", "run", "find-main"],
        &["report", "find-main"],
        &["runtime", "pointer", "compare", missing, "--at", "0", "--other-at", "0"],
        &["runtime", "pointer", "compare", missing, "--other", missing, "--other-at", "0"],
        &["runtime", "pointer", "compare", missing, "--other", missing, "--at", "0"],
        &["runtime", "pointer", "compare", "--other", missing, "--at", "0", "--other-at", "0"],
        &["compare-pointers", missing, "--at", "0", "--other-at", "0"],
        &["compare-pointers", missing, "--other", missing, "--other-at", "0"],
        &["compare-pointers", missing, "--other", missing, "--at", "0"],
    ];
    for args in cases {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {}", String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stderr).contains("required"), "{args:?}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn managed_and_workflow_option_constraints_remain_clap_errors() {
    let missing = "/nonexistent/rampage-binary";
    let managed_options: &[&[&str]] = &[
        &["--il", "Main", "--list", "types"],
        &["--il", "Main", "--contains", "x"],
        &["--il", "Main", "--parent-token", "0x2000001"],
        &["--il", "Main", "--at", "IL_0000", "--offset", "0"],
        &["--at", "0x42"],
        &["--limit", "0"],
        &["--list", "fields"],
        &["--parent-token", "invalid"],
    ];
    for route in [&["dotnet"][..], &["managed", "inspect"][..]] {
        for options in managed_options {
            let args: Vec<_> = route.iter().copied().chain([missing]).chain(options.iter().copied()).collect();
            let output = run(&args);
            assert_eq!(output.status.code(), Some(2), "{args:?}: {}", String::from_utf8_lossy(&output.stderr));
        }
    }
    for route in [&["report"][..], &["workflow", "run"][..]] {
        for options in [&["--other-image-offset", "1"][..], &["--other", missing, "--other-image-length", "2"][..]] {
            let args: Vec<_> =
                route.iter().copied().chain(["diff-builds", missing]).chain(options.iter().copied()).collect();
            assert_eq!(run(&args).status.code(), Some(2), "{args:?}");
        }
    }
    for args in [
        vec!["binary", "--image-length", "10", "inspect", missing],
        vec!["info", missing, "--image-length", "10"],
        vec!["runtime", "pointer", "--arch", "invalid", "compare", missing],
    ] {
        assert_eq!(run(&args).status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn workflow_validation_precedes_opening_the_binary() {
    let missing = "/nonexistent/rampage-binary";
    for arguments in [&["diff-builds", missing][..], &["triage-report", missing, "--other", missing][..]] {
        let legacy: Vec<_> = ["report"].into_iter().chain(arguments.iter().copied()).collect();
        let hierarchy: Vec<_> = ["workflow", "run"].into_iter().chain(arguments.iter().copied()).collect();
        let output = assert_same(&legacy, &hierarchy, false);
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--other"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("cannot open"));
    }
    assert_eq!(run(&["workflow", "run", "unknown-workflow", missing]).status.code(), Some(2));
}

#[test]
fn global_json_and_architecture_options_work_at_each_nesting_level() {
    let universal = fixture("hello-universal.macho");
    let capture = snapshot();
    let routes: &[&[&str]] = &[
        &["binary", "inspect", &universal],
        &["function", "decompile", &universal, "--at", "_add"],
        &["workflow", "run", "find-main", &universal, "--no-decompile", "--limit", "1"],
        &["managed", "inspect", &universal],
        &["runtime", "pointer", "compare", &capture, "--other", &capture, "--at", "0x3000", "--other-at", "0x1000"],
    ];
    for route in routes {
        let globals = ["--json", "--arch", "aarch64"];
        let prefix: Vec<_> = globals.into_iter().chain(route.iter().copied()).collect();
        let expected = run(&prefix);
        assert!(expected.status.success(), "{prefix:?}: {}", String::from_utf8_lossy(&expected.stderr));
        if route[0] == "binary" {
            let value: Value = serde_json::from_slice(&expected.stdout).unwrap();
            assert_eq!(value["arch"], "aarch64");
        }
        let depth = if route[0] == "runtime" { 3 } else { 2 };
        for position in (1..=depth).chain([route.len()]) {
            let args: Vec<_> =
                route[..position].iter().copied().chain(globals).chain(route[position..].iter().copied()).collect();
            let output = run(&args);
            assert_eq!(output.status.code(), expected.status.code(), "{args:?}");
            assert_eq!(output.stdout, expected.stdout, "{args:?}");
            assert_eq!(output.stderr, expected.stderr, "{args:?}");
        }
    }
}

#[test]
fn embedded_image_flags_propagate_after_normalization() {
    let universal = fixture("hello-universal.macho");
    let globals = ["--json", "--arch", "x86_64", "--image-offset", "0x1000", "--image-length", "0x2110"];
    let routes: [(&[&str], &[&str]); 3] = [
        (&["info", &universal], &["binary", "inspect", &universal]),
        (&["decompile", &universal, "--at", "_add"], &["function", "decompile", &universal, "--at", "_add"]),
        (
            &["report", "diff-builds", &universal, "--other", &universal, "--other-image-offset", "0x1000"],
            &["workflow", "run", "diff-builds", &universal, "--other", &universal, "--other-image-offset", "0x1000"],
        ),
    ];
    for (legacy, hierarchy) in routes {
        let legacy: Vec<_> = globals.into_iter().chain(legacy.iter().copied()).collect();
        for position in 0..=2 {
            let args: Vec<_> = hierarchy[..position]
                .iter()
                .copied()
                .chain(globals)
                .chain(hierarchy[position..].iter().copied())
                .collect();
            assert_same(&legacy, &args, true);
        }
    }
}

#[test]
fn global_image_dependencies_are_validated_after_values_from_all_levels_propagate() {
    let universal = fixture("hello-universal.macho");
    let expected =
        ["info", &universal, "--json", "--image-offset", "0x1000", "--image-length", "0x2110", "--arch", "x86_64"];
    for args in [
        vec![
            "--json",
            "binary",
            "--image-length",
            "0x2110",
            "inspect",
            &universal,
            "--image-offset",
            "0x1000",
            "--arch",
            "x86_64",
        ],
        vec![
            "--json",
            "--image-length",
            "0x2110",
            "binary",
            "--arch",
            "x86_64",
            "inspect",
            &universal,
            "--image-offset",
            "0x1000",
        ],
        vec![
            "--image-offset",
            "0x1000",
            "binary",
            "--json",
            "inspect",
            &universal,
            "--image-length",
            "0x2110",
            "--arch",
            "x86_64",
        ],
        vec!["--image-length", "0x2110", "info", &universal, "--image-offset", "0x1000", "--arch", "x86_64", "--json"],
    ] {
        assert_same(&expected, &args, true);
    }
    let output = assert_same(
        &["info", &universal, "--json", "--image-offset", "0", "--image-length", "0xc2b0", "--arch", "x86_64"],
        &[
            "--json",
            "binary",
            "--image-length",
            "0xc2b0",
            "inspect",
            &universal,
            "--image-offset",
            "0",
            "--arch",
            "x86_64",
        ],
        true,
    );
    assert_eq!(serde_json::from_slice::<Value>(&output.stdout).unwrap()["arch"], "x86_64");
}

#[test]
fn missing_global_image_dependencies_and_conflicts_remain_parse_errors_before_opening() {
    let missing = "/nonexistent/rampage-binary";
    for args in [
        vec!["binary", "--image-length", "0", "inspect", missing],
        vec!["--json", "binary", "inspect", missing, "--image-length", "1"],
        vec!["--image-length", "0", "info", missing],
        vec!["info", missing, "--image-length", "0"],
        vec![
            "runtime",
            "--image-length",
            "0",
            "pointer",
            "compare",
            missing,
            "--other",
            missing,
            "--at",
            "0",
            "--other-at",
            "0",
        ],
        vec!["--json", "managed", "--arch", "x86_64", "inspect", missing, "--il", "Main", "--list", "types"],
        vec!["binary", "inspect", missing, "--image-offset", "0", "--image-offset", "1"],
        vec!["--json", "--json", "binary", "inspect", missing],
        vec!["--json", "managed", "inspect", missing, "--il", "Main", "--at", "0", "--offset", "0"],
        vec!["--image-length", "0", "managed", "inspect", missing, "--il", "Main"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {}", String::from_utf8_lossy(&output.stderr));
        assert!(output.stdout.is_empty(), "{args:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(!error.contains("cannot open"), "{args:?}: {error}");
        assert!(!error.contains("--image-offset does not apply"), "{args:?}: {error}");
    }
    let output = run(&["--image-length", "0", "binary", "inspect", missing, "--image-offset", "0"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains(missing));
}

#[test]
fn managed_inspection_opens_the_selected_embedded_assembly() {
    use std::io::Write;

    struct EmbeddedAssembly(PathBuf);

    impl Drop for EmbeddedAssembly {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).unwrap();
        }
    }

    let assembly = fixture("Microsoft.Bcl.HashCode.dll");
    let path = std::env::temp_dir().join(format!("rampage-cli-hierarchy-managed-{}.bin", std::process::id()));
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
    let embedded = EmbeddedAssembly(path);
    let bytes = std::fs::read(&assembly).unwrap();
    file.write_all(&[0; 37]).unwrap();
    file.write_all(&bytes).unwrap();
    drop(file);
    let path = embedded.0.to_str().unwrap();
    let length = bytes.len().to_string();
    let expected = run(&["dotnet", &assembly, "--json", "--contains", "hashcode", "--limit", "1"]);
    assert!(expected.status.success());
    for position in 0..=3 {
        let route = ["managed", "inspect", path, "--contains", "hashcode", "--limit", "1"];
        let globals = ["--json", "--image-offset", "37", "--image-length", &length];
        let args: Vec<_> =
            route[..position].iter().copied().chain(globals).chain(route[position..].iter().copied()).collect();
        let output = run(&args);
        assert_eq!(output.status.code(), expected.status.code(), "{args:?}");
        assert_eq!(output.stdout, expected.stdout, "{args:?}");
        assert_eq!(output.stderr, expected.stderr, "{args:?}");
    }
}

#[test]
fn runtime_image_restrictions_apply_to_the_normalized_action() {
    let missing = "/nonexistent/rampage-capture";
    let options = [missing, "--other", missing, "--at", "0", "--other-at", "0"];
    let legacy: Vec<_> = ["--image-offset", "16", "compare-pointers"].into_iter().chain(options).collect();
    let route: Vec<_> = ["runtime", "pointer", "compare"].into_iter().chain(options).collect();
    for position in (0..=3).chain([route.len()]) {
        let hierarchy: Vec<_> = route[..position]
            .iter()
            .copied()
            .chain(["--image-offset", "16"])
            .chain(route[position..].iter().copied())
            .collect();
        let output = assert_same(&legacy, &hierarchy, false);
        assert!(String::from_utf8_lossy(&output.stderr).contains("--image-offset does not apply to compare-pointers"));
    }
}

#[test]
fn pack_flags_reach_workflows_and_keep_lazy_loading_for_inspection() {
    let elf = fixture("hello-x64.elf");
    let pack = "/nonexistent/rampage-hierarchy-pack";
    let expected = run(&["--json", "--pack", pack, "report", "triage-report", &elf]);
    assert!(expected.status.success());
    assert!(String::from_utf8_lossy(&expected.stderr).contains("rampage: warning: pack"));
    for args in [
        vec!["--pack", pack, "workflow", "run", "triage-report", &elf, "--json"],
        vec!["workflow", "--pack", pack, "run", "triage-report", &elf, "--json"],
        vec!["workflow", "run", "--pack", pack, "triage-report", &elf, "--json"],
        vec!["workflow", "run", "triage-report", &elf, "--json", "--pack", pack],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), expected.status.code(), "{args:?}");
        assert_eq!(output.stdout, expected.stdout, "{args:?}");
        assert_eq!(output.stderr, expected.stderr, "{args:?}");
    }
    let output = assert_same(&["info", &elf, "--pack", pack], &["binary", "--pack", pack, "inspect", &elf], true);
    assert!(output.stderr.is_empty());
}

#[test]
fn repeatable_packs_merge_in_argument_order_across_command_levels() {
    let elf = fixture("hello-x64.elf");
    let first = "/nonexistent/rampage-hierarchy-first-pack";
    let second = "/nonexistent/rampage-hierarchy-second-pack";
    let third = "/nonexistent/rampage-hierarchy-third-pack";
    let expected = ["report", "--pack", first, "--pack", second, "triage-report", &elf, "--limit", "1"];
    let output = assert_same(
        &expected,
        &["workflow", "--pack", first, "run", "--pack", second, "triage-report", &elf, "--limit", "1"],
        true,
    );
    let warnings = String::from_utf8(output.stderr).unwrap();
    assert!(warnings.find(first).unwrap() < warnings.find(second).unwrap());
    assert_same(&expected, &["--pack", first, "report", "--pack", second, "triage-report", &elf, "--limit", "1"], true);
    let expected =
        ["report", "--pack", first, "--pack", second, "--pack", third, "triage-report", &elf, "--json", "--limit", "1"];
    for args in [
        vec![
            "--json",
            "--pack",
            first,
            "workflow",
            "--pack",
            second,
            "run",
            "--pack",
            third,
            "triage-report",
            &elf,
            "--limit",
            "1",
        ],
        vec![
            "workflow",
            "--pack",
            first,
            "--pack",
            second,
            "run",
            "triage-report",
            &elf,
            "--pack",
            third,
            "--json",
            "--limit",
            "1",
        ],
    ] {
        let output = assert_same(&expected, &args, true);
        let warnings = String::from_utf8(output.stderr).unwrap();
        assert!(warnings.find(first).unwrap() < warnings.find(second).unwrap());
        assert!(warnings.find(second).unwrap() < warnings.find(third).unwrap());
    }
}

#[test]
fn server_and_legacy_mcp_keep_accepted_global_flags_and_stdio_output() {
    let requests = [
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": { "name": "hierarchy-test", "version": "0" }
            }
        })
        .to_string(),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_owned(),
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#.to_owned(),
    ]
    .join("\n")
        + "\n";
    let serve = |args: &[&str]| {
        Command::cargo_bin("rampage")
            .unwrap()
            .env_remove("RAMPAGE_PACKS")
            .env_remove("RAMPAGE_MCP_TOOLS")
            .args(args)
            .write_stdin(requests.as_str())
            .timeout(std::time::Duration::from_secs(10))
            .output()
            .unwrap()
    };
    let legacy = serve(&["mcp"]);
    assert!(legacy.status.success(), "{}", String::from_utf8_lossy(&legacy.stderr));
    for args in [
        &["--json", "--arch", "aarch64", "mcp"][..],
        &["mcp", "--json", "--arch", "aarch64"][..],
        &["server", "serve"][..],
        &["--json", "server", "--arch", "aarch64", "serve"][..],
    ] {
        let output = serve(args);
        assert_eq!(output.status.code(), legacy.status.code());
        assert_eq!(output.stdout, legacy.stdout);
        assert_eq!(output.stderr, legacy.stderr);
    }
    let stdout = String::from_utf8(legacy.stdout).unwrap();
    let responses: Vec<Value> = stdout.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert!(responses.iter().any(|response| response["id"] == 2 && response["result"]["tools"].is_array()));
}

#[test]
fn primary_help_lists_only_nouns_and_all_legacy_forms_remain_accepted() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    let commands = help.split("Commands:\n").nth(1).unwrap().split("\nOptions:").next().unwrap();
    let names: Vec<_> = commands.lines().filter_map(|line| line.split_whitespace().next()).collect();
    assert_eq!(
        names,
        [
            "binary",
            "function",
            "string",
            "language",
            "managed",
            "annotation",
            "type",
            "runtime",
            "pack",
            "workflow",
            "server",
            "help"
        ]
    );
    for name in [
        "binary",
        "function",
        "string",
        "language",
        "managed",
        "annotation",
        "type",
        "runtime",
        "pack",
        "workflow",
        "server",
    ] {
        assert!(help.lines().any(|line| line.split_whitespace().next() == Some(name)), "{name}: {help}");
    }
    for name in ["info", "decompile", "compare-pointers", "report", "dotnet", "export-cfg"] {
        assert!(!help.lines().any(|line| line.split_whitespace().next() == Some(name)), "{name}: {help}");
    }
    for name in [
        "analyze",
        "info",
        "disasm",
        "strings",
        "funcs",
        "triage",
        "capabilities",
        "dotnet",
        "detect",
        "yara",
        "capa",
        "packs",
        "audit",
        "metadata",
        "inventory",
        "carve",
        "summarize",
        "decompile",
        "pseudocode",
        "compare",
        "signatures",
        "identify",
        "jump-table",
        "correlate",
        "compare-runtime",
        "observe-pointer",
        "compare-pointers",
        "observe-indirect-branch",
        "imports",
        "exports",
        "rename",
        "comment",
        "annotate-batch",
        "check-names",
        "annotations",
        "debug-types",
        "report",
        "mcp",
        "xrefs",
        "export-cfg",
    ] {
        assert!(!help.lines().any(|line| line.split_whitespace().next() == Some(name)), "{name}: {help}");
        assert!(run(&[name, "--help"]).status.success(), "{name}");
    }
    for (route, verb) in [
        (&["binary"][..], "inspect"),
        (&["function"][..], "decompile"),
        (&["runtime", "pointer"][..], "compare"),
        (&["workflow"][..], "run"),
        (&["managed"][..], "inspect"),
    ] {
        let args: Vec<_> = route.iter().copied().chain(["--help"]).collect();
        let help = String::from_utf8(run(&args).stdout).unwrap();
        assert!(help.lines().any(|line| line.split_whitespace().next() == Some(verb)), "{args:?}: {help}");
    }
}
