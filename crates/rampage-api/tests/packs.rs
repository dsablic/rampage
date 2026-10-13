use std::path::PathBuf;
use std::sync::Arc;

use rampage_api::{ContentStatus, MAX_PEID_BYTES, PackInfo, Packs, Session};
use rampage_arch::Arch;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

/// A temporary directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("rampage-packs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn manifest(name: &str, contents: &str) -> String {
    format!(
        "name = \"{name}\"\nversion = \"1.0.0\"\nlicense = \"MIT OR Apache-2.0\"\n\
         source = \"https://example.com/{name}\"\ndescription = \"Test pack\"\n{contents}"
    )
}

/// The bundled x86-64 musl database with every name prefixed, so matches show which database named a function.
fn renamed_signatures(prefix: &str) -> String {
    let database = rampage_signatures::bundled(Arch::X86_64).unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&database.to_json()).unwrap();
    for field in ["entries", "exact", "calls"] {
        if let Some(map) = json.get_mut(field).and_then(|value| value.as_object_mut()) {
            for name in map.values_mut() {
                *name = serde_json::Value::String(format!("{prefix}{}", name.as_str().unwrap()));
            }
        }
    }
    json.to_string()
}

const CAPA_RULE: &str = "rule:\n  meta:\n    name: pack console output\n    namespace: host-interaction/console\n    \
                         scopes:\n      static: file\n  features:\n    - or:\n      - import: puts\n      \
                         - import: printf\n";
const YARA_RULE: &str = "rule pack_pe_header : format { strings: $mz = \"MZ\" condition: $mz at 0 }";
const PEID: &str = "[Pack DOS Header]\nsignature = 4D 5A 78 00 01 00 00 00 04\nep_only = false\n";

fn statuses(pack: &PackInfo) -> Vec<(&str, ContentStatus)> {
    pack.contents.iter().map(|content| (content.kind, content.status)).collect()
}

fn session(packs: Packs) -> Session {
    Session::default().with_packs(Arc::new(packs))
}

#[test]
fn a_valid_pack_takes_effect_in_identify_detect_yara_and_capa() {
    let pack = Scratch::new("valid");
    pack.write("sigs/x86_64.json", &renamed_signatures("pack_"));
    pack.write("userdb.txt", PEID);
    pack.write("yara/pe.yar", YARA_RULE);
    pack.write("capa/nested/console.yml", CAPA_RULE);
    pack.write(
        "rampage-pack.toml",
        &manifest(
            "valid",
            "[[contents]]\nkind = \"signatures\"\npath = \"sigs/x86_64.json\"\narch = \"x86_64\"\n\
             [[contents]]\nkind = \"peid\"\npath = \"userdb.txt\"\n\
             [[contents]]\nkind = \"yara\"\npath = \"yara\"\n\
             [[contents]]\nkind = \"capa\"\npath = \"capa\"\n",
        ),
    );
    let packs = Packs::load(std::slice::from_ref(&pack.0));
    assert!(packs.problems().is_empty(), "{:?}", packs.problems());
    let listing = packs.listing();
    assert_eq!(listing.len(), 2);
    // Precedence order: the packs, then the built-in databases they layer over.
    let builtin = &listing[1];
    assert!(builtin.builtin);
    let manifest = builtin.manifest.as_ref().unwrap();
    assert_eq!((manifest.name.as_str(), manifest.license.as_str()), ("rampage-builtin", "Apache-2.0"));
    assert!(builtin.contents.iter().any(|content| content.kind == "signatures"));
    let loaded = &listing[0];
    assert_eq!(loaded.manifest.as_ref().unwrap().license, "MIT OR Apache-2.0");
    assert_eq!(
        statuses(loaded),
        [
            ("signatures", ContentStatus::Loaded),
            ("peid", ContentStatus::Loaded),
            ("yara", ContentStatus::Loaded),
            ("capa", ContentStatus::Loaded)
        ]
    );
    let json = serde_json::to_value(loaded).unwrap();
    assert_eq!(json["name"], "valid");
    assert_eq!(json["source"], "https://example.com/valid");
    assert_eq!(json["contents"][0]["status"], "loaded");

    let session = session(packs);
    let musl = session.open(&fixture("musl-static-x86_64.elf"), None).unwrap();
    let identified = musl.identify_functions(None, true, false).unwrap();
    let names: Vec<String> = identified.matches.into_iter().map(|m| m.name).collect();
    assert!(names.iter().any(|name| name == "pack_vfprintf"), "{names:?}");
    assert!(!names.iter().any(|name| name == "vfprintf"), "the pack layers before the bundled database: {names:?}");
    // A pack database stands in for a user one when the bundled database is left out.
    assert!(musl.identify_functions(None, false, false).unwrap().matched > 0);

    let exe = session.open(&fixture("hello-x64.exe"), None).unwrap();
    let detections = exe.detect_tools(None).unwrap().detections;
    assert!(detections.iter().any(|detection| detection.name == "Pack DOS Header"), "{detections:?}");

    let matches = exe.yara_scan_packs().unwrap();
    assert_eq!(matches.len(), 1, "{matches:?}");
    assert_eq!((matches[0].identifier.as_str(), matches[0].namespace.as_str()), ("pack_pe_header", "valid"));
    let user = "rule user_rule { strings: $mz = \"MZ\" condition: $mz at 0 }";
    let both: Vec<String> = exe.yara_scan(user).unwrap().into_iter().map(|m| m.identifier).collect();
    assert_eq!(both, ["user_rule", "pack_pe_header"]);

    let capabilities = exe.detect_capa_packs().unwrap();
    assert!(capabilities.iter().any(|capability| capability.name == "pack console output"), "{capabilities:?}");
}

#[test]
fn without_packs_the_pack_only_scans_ask_for_rules() {
    let project = Session::default().open(&fixture("hello-x64.exe"), None).unwrap();
    assert!(project.yara_scan_packs().unwrap_err().to_string().contains("no YARA rules"));
    assert!(project.detect_capa_packs().unwrap_err().to_string().contains("no capa rules"));
    assert!(project.identify_functions(None, false, false).is_err());
}

#[test]
fn earlier_packs_take_precedence_for_signatures() {
    let first = Scratch::new("first");
    let second = Scratch::new("second");
    for (pack, prefix) in [(&first, "first_"), (&second, "second_")] {
        pack.write("x86_64.json", &renamed_signatures(prefix));
        let name = prefix.trim_end_matches('_');
        pack.write(
            "rampage-pack.toml",
            &manifest(name, "[[contents]]\nkind = \"signatures\"\npath = \"x86_64.json\"\n"),
        );
    }
    let named = |order: &[&Scratch]| {
        let directories: Vec<PathBuf> = order.iter().map(|pack| pack.0.clone()).collect();
        let project = session(Packs::load(&directories)).open(&fixture("musl-static-x86_64.elf"), None).unwrap();
        let result = project.identify_functions(None, true, false).unwrap();
        result.matches.into_iter().find(|m| m.name.ends_with("vfprintf")).unwrap().name
    };
    assert_eq!(named(&[&first, &second]), "first_vfprintf");
    assert_eq!(named(&[&second, &first]), "second_vfprintf");
}

#[test]
fn a_pack_given_twice_loads_once() {
    let pack = Scratch::new("twice");
    pack.write("userdb.txt", PEID);
    pack.write("rampage-pack.toml", &manifest("twice", "[[contents]]\nkind = \"peid\"\npath = \"userdb.txt\"\n"));
    let packs = Packs::load(&[pack.0.clone(), pack.0.join("."), pack.0.clone()]);
    assert!(packs.problems().is_empty(), "{:?}", packs.problems());
    assert_eq!(packs.loaded().len(), 1);
    assert_eq!(packs.loaded()[0].directory.as_deref(), Some(pack.0.as_path()));
}

fn rejected(name: &str, contents: &str) -> String {
    let pack = Scratch::new(name);
    pack.write("db.json", "{}");
    pack.write("rampage-pack.toml", contents);
    let info = Packs::check(&pack.0);
    assert!(info.manifest.is_none() && info.contents.is_empty(), "{info:?}");
    info.error.unwrap()
}

#[test]
fn manifests_are_validated_strictly() {
    let error = rejected("kind", &manifest("kind", "[[contents]]\nkind = \"plugins\"\npath = \"db.json\"\n"));
    assert!(error.contains("unknown variant"), "{error}");
    let peid = "[[contents]]\nkind = \"peid\"\npath = \"db.json\"\n";
    let error = rejected("field", &manifest("field", &format!("homepage = \"x\"\n{peid}")));
    assert!(error.contains("unknown field"), "{error}");
    let error = rejected("content-field", &manifest("content-field", &format!("{peid}run = 1\n")));
    assert!(error.contains("unknown field"), "{error}");
    let error = rejected("dotdot", &manifest("dotdot", "[[contents]]\nkind = \"peid\"\npath = \"../db.json\"\n"));
    assert!(error.contains("without `.`, `..` or a root"), "{error}");
    let error = rejected("absolute", &manifest("absolute", "[[contents]]\nkind = \"peid\"\npath = \"/etc/passwd\"\n"));
    assert!(error.contains("without `.`, `..` or a root"), "{error}");
    let error =
        rejected("arch", &manifest("arch", "[[contents]]\nkind = \"yara\"\npath = \"db.json\"\narch = \"x86_64\"\n"));
    assert!(error.contains("`arch` applies only to signatures"), "{error}");
    let error = rejected("empty", &manifest("empty", "contents = []\n"));
    assert!(error.contains("`contents` is empty"), "{error}");
    let error = rejected("missing", "name = \"missing\"\ncontents = []\n");
    assert!(error.contains("missing field"), "{error}");
    let error = rejected("badname", &manifest("bad name", "[[contents]]\nkind = \"peid\"\npath = \"db.json\"\n"));
    assert!(error.contains("`name` contains ' '"), "{error}");
    let error =
        rejected("builtin", &manifest("rampage-builtin", "[[contents]]\nkind = \"peid\"\npath = \"db.json\"\n"));
    assert!(error.contains("already taken"), "{error}");
    let error = rejected("default", &manifest("default", "[[contents]]\nkind = \"peid\"\npath = \"db.json\"\n"));
    assert!(error.contains("\"default\" is reserved"), "{error}");

    let missing = Scratch::new("no-manifest");
    assert!(Packs::check(&missing.0).error.unwrap().contains("rampage-pack.toml"));
}

#[cfg(unix)]
#[test]
fn symbolic_links_cannot_escape_the_pack() {
    let outside = Scratch::new("outside");
    let secret = outside.write("userdb.txt", PEID);
    outside.write("rules/escape.yar", YARA_RULE);
    let pack = Scratch::new("links");
    std::os::unix::fs::symlink(&secret, pack.0.join("linked.txt")).unwrap();
    std::fs::create_dir_all(pack.0.join("yara")).unwrap();
    std::os::unix::fs::symlink(outside.0.join("rules/escape.yar"), pack.0.join("yara/escape.yar")).unwrap();
    pack.write("inside.txt", PEID);
    std::os::unix::fs::symlink(pack.0.join("inside.txt"), pack.0.join("alias.txt")).unwrap();
    pack.write(
        "rampage-pack.toml",
        &manifest(
            "links",
            "[[contents]]\nkind = \"peid\"\npath = \"linked.txt\"\n\
             [[contents]]\nkind = \"yara\"\npath = \"yara\"\n\
             [[contents]]\nkind = \"peid\"\npath = \"alias.txt\"\n",
        ),
    );
    let info = Packs::check(&pack.0);
    assert_eq!(
        statuses(&info),
        [("peid", ContentStatus::Error), ("yara", ContentStatus::Error), ("peid", ContentStatus::Loaded)]
    );
    assert!(info.contents[0].detail.contains("resolves outside the pack directory"), "{info:?}");
    assert!(info.contents[1].detail.contains("links outside the pack directory"), "{info:?}");

    // A manifest that is itself a link out of the pack is refused too.
    let linked = Scratch::new("linked-manifest");
    let linked_manifest = manifest("linked", "[[contents]]\nkind = \"peid\"\npath = \"a\"\n");
    let target = outside.write("rampage-pack.toml", &linked_manifest);
    std::os::unix::fs::symlink(target, linked.0.join("rampage-pack.toml")).unwrap();
    assert!(Packs::check(&linked.0).error.unwrap().contains("resolves outside the pack directory"));
}

#[test]
fn pack_yara_rules_cannot_include_files() {
    let outside = Scratch::new("include-outside");
    let hidden = outside.write("hidden.yar", "rule outside_secret_line { condition: true }");
    let pack = Scratch::new("include");
    pack.write("yara/include.yar", &format!("include \"{}\"\n{YARA_RULE}", hidden.display()));
    pack.write("yara/zero.yar", &format!("include \"/dev/zero\"\n{YARA_RULE}"));
    pack.write("rampage-pack.toml", &manifest("include", "[[contents]]\nkind = \"yara\"\npath = \"yara\"\n"));
    let packs = Packs::load(std::slice::from_ref(&pack.0));
    let info = &packs.loaded()[0];
    assert_eq!(statuses(info), [("yara", ContentStatus::Error)]);
    assert!(info.contents[0].detail.contains("include"), "{info:?}");
    assert!(!format!("{:?}", packs.problems()).contains("outside_secret_line"), "{:?}", packs.problems());
}

#[test]
fn oversized_files_are_rejected() {
    let pack = Scratch::new("oversized");
    let file = std::fs::File::create(pack.0.join("userdb.txt")).unwrap();
    // Sparse, so the test writes almost nothing to disk.
    file.set_len(MAX_PEID_BYTES + 1).unwrap();
    pack.write("ok.txt", PEID);
    pack.write(
        "rampage-pack.toml",
        &manifest(
            "oversized",
            "[[contents]]\nkind = \"peid\"\npath = \"userdb.txt\"\n[[contents]]\nkind = \"peid\"\npath = \"ok.txt\"\n",
        ),
    );
    let info = Packs::check(&pack.0);
    assert_eq!(statuses(&info), [("peid", ContentStatus::Error), ("peid", ContentStatus::Loaded)]);
    assert!(info.contents[0].detail.contains("larger than 16 MiB"), "{info:?}");

    let big = Scratch::new("big-manifest");
    let manifest = std::fs::File::create(big.0.join("rampage-pack.toml")).unwrap();
    manifest.set_len(rampage_api::MAX_PACK_MANIFEST_BYTES + 1).unwrap();
    assert!(Packs::check(&big.0).error.unwrap().contains("larger than 1 MiB"));
}

#[test]
fn a_file_named_by_several_contents_is_read_once() {
    let pack = Scratch::new("duplicate");
    pack.write("userdb.txt", PEID);
    let content = "[[contents]]\nkind = \"peid\"\npath = \"userdb.txt\"\n";
    pack.write("rampage-pack.toml", &manifest("duplicate", &content.repeat(3)));
    let info = Packs::check(&pack.0);
    assert_eq!(
        statuses(&info),
        [("peid", ContentStatus::Loaded), ("peid", ContentStatus::Error), ("peid", ContentStatus::Error)]
    );
    assert!(info.contents[1].detail.contains("already read"), "{info:?}");
}

#[test]
fn rule_files_over_the_pack_budget_are_refused_before_any_is_read() {
    let pack = Scratch::new("budget");
    std::fs::create_dir_all(pack.0.join("yara")).unwrap();
    // Sparse files just under the per-file cap, together over the per-pack read budget.
    for index in 0..40 {
        let file = std::fs::File::create(pack.0.join(format!("yara/{index:02}.yar"))).unwrap();
        file.set_len(rampage_api::MAX_RULE_FILE_BYTES - 1).unwrap();
    }
    pack.write("rampage-pack.toml", &manifest("budget", "[[contents]]\nkind = \"yara\"\npath = \"yara\"\n"));
    let started = std::time::Instant::now();
    let info = Packs::check(&pack.0);
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(statuses(&info), [("yara", ContentStatus::Error)]);
    assert!(info.contents[0].detail.contains("read budget of one pack"), "{info:?}");
}

#[test]
fn packs_past_the_cap_are_reported_without_being_read() {
    let directories: Vec<PathBuf> = (0..70).map(|index| PathBuf::from(format!("/nonexistent/pack-{index}"))).collect();
    let packs = Packs::load(&directories);
    assert_eq!(packs.loaded().len(), 70);
    assert!(packs.loaded()[63].error.as_ref().unwrap().contains("cannot open pack directory"));
    assert!(packs.loaded()[64].error.as_ref().unwrap().contains("more than 64 packs"));
}

#[test]
fn lazy_packs_load_only_when_a_heuristic_database_is_consulted() {
    let pack = Scratch::new("lazy");
    pack.write("userdb.txt", PEID);
    pack.write("rampage-pack.toml", &manifest("lazy", "[[contents]]\nkind = \"peid\"\npath = \"userdb.txt\"\n"));
    let packs = Arc::new(Packs::lazy(std::slice::from_ref(&pack.0)));
    assert!(packs.configured() && !packs.is_loaded());
    let session = Session::default().with_packs(Arc::clone(&packs));
    let project = session.open(&fixture("hello-x64.exe"), None).unwrap();
    project.summary();
    project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    assert!(!packs.is_loaded());
    let detections = project.detect_tools(None).unwrap().detections;
    assert!(packs.is_loaded());
    assert!(detections.iter().any(|detection| detection.name == "Pack DOS Header"), "{detections:?}");
}

#[test]
fn a_broken_content_does_not_block_the_others() {
    let pack = Scratch::new("broken");
    pack.write("yara/broken.yar", "rule broken {");
    pack.write("capa/console.yml", CAPA_RULE);
    pack.write("arm.json", &rampage_signatures::bundled(Arch::Aarch64).unwrap().to_json());
    pack.write("garbage.json", "not json");
    pack.write("constants.bin", "");
    pack.write(
        "rampage-pack.toml",
        &manifest(
            "broken",
            "[[contents]]\nkind = \"yara\"\npath = \"yara\"\n\
             [[contents]]\nkind = \"signatures\"\npath = \"arm.json\"\narch = \"x86_64\"\n\
             [[contents]]\nkind = \"signatures\"\npath = \"garbage.json\"\n\
             [[contents]]\nkind = \"peid\"\npath = \"missing.txt\"\n\
             [[contents]]\nkind = \"constants\"\npath = \"constants.bin\"\n\
             [[contents]]\nkind = \"capa\"\npath = \"capa\"\n",
        ),
    );
    let packs = Packs::load(std::slice::from_ref(&pack.0));
    let info = &packs.loaded()[0];
    assert_eq!(
        statuses(info),
        [
            ("yara", ContentStatus::Error),
            ("signatures", ContentStatus::Error),
            ("signatures", ContentStatus::Error),
            ("peid", ContentStatus::Error),
            ("constants", ContentStatus::Unsupported),
            ("capa", ContentStatus::Loaded)
        ]
    );
    assert!(info.contents[0].detail.starts_with("YARA rules:"), "{info:?}");
    assert!(info.contents[1].detail.contains("declared for x86_64, but the database is for aarch64"), "{info:?}");
    assert_eq!(packs.problems().len(), 5, "{:?}", packs.problems());

    let project = session(packs).open(&fixture("hello-x64.exe"), None).unwrap();
    assert!(project.yara_scan_packs().is_err());
    let capabilities = project.detect_capa_packs().unwrap();
    assert!(capabilities.iter().any(|capability| capability.name == "pack console output"), "{capabilities:?}");
}
