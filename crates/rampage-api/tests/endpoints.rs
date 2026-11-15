//! endpoint_inventory and endpoint_blocklist on the endpoints fixture (tests/fixtures/endpoints.c) and on a small
//! firmware tree: classification precision against the noise strings, xref and networking-code evidence, decoded
//! strings, grouping, paging under the file and time budgets, the blocklist formats (golden files) and the output
//! path rules.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::{BlocklistQuery, InventoryQuery, endpoint_blocklist, endpoint_inventory};
use serde_json::Value;

fn local_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A fresh directory under the canonical temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn query(path: &Path) -> InventoryQuery {
    InventoryQuery {
        path: path.to_path_buf(),
        cursor: None,
        max_files: None,
        timeout_ms: None,
        xrefs: None,
        decode: false,
        kinds: None,
        limit: Some(500),
    }
}

fn inventory(query: &InventoryQuery) -> Value {
    let value = endpoint_inventory(query).unwrap();
    assert!(value.to_string().len() <= 60_000);
    value
}

fn rows(value: &Value) -> &Vec<Value> {
    value["endpoints"].as_array().unwrap()
}

fn row<'v>(value: &'v Value, endpoint: &str) -> &'v Value {
    rows(value).iter().find(|row| row["value"] == endpoint).unwrap_or_else(|| panic!("no {endpoint}: {value:#}"))
}

fn kinds_and_values(value: &Value) -> BTreeSet<(String, String)> {
    rows(value)
        .iter()
        .map(|row| (row["kind"].as_str().unwrap().to_owned(), row["value"].as_str().unwrap().to_owned()))
        .collect()
}

const SUBJECT: &str = "O=Invented Device Maker, CN=device-ca.vendor-cloud.example";
const PIN: &str = "sha256/DYZYMp8/e065XzTsuXKwdXrutL9ps0MnN5ZfB4jjjIs=";

/// Every finding in the fixture, and nothing else: the noise strings are counted as noise, never reported.
#[test]
fn binary_findings_are_exactly_the_endpoints_and_the_noise_is_counted() {
    for name in ["endpoints-x64.elf", "endpoints-arm64.elf"] {
        let value = inventory(&query(&local_fixture(name)));
        let expected: BTreeSet<(String, String)> = [
            ("local", "https://telemetry.vendor-cloud.example/v2/events"),
            ("local", "updates.vendor-cloud.example"),
            ("local", "203.0.113.45"),
            ("local", "2001:db8:10::25"),
            ("local", "http://198.51.100.20/status"),
            ("local", "http://localhost:8080/debug"),
            ("local", "192.168.1.1"),
            ("local", "fe80::1"),
            ("pin", PIN),
            ("certificate", SUBJECT),
            ("package", "com.example.app"),
        ]
        .into_iter()
        .map(|(kind, value)| (kind.to_owned(), value.to_owned()))
        .collect();
        assert_eq!(kinds_and_values(&value), expected, "{name}");
        let noise = &value["noise"];
        for (reason, count) in [("version", 1), ("netmask", 1), ("namespace", 2), ("identifier", 1)] {
            assert_eq!(noise[reason]["count"], count, "{name} {reason}: {noise:#}");
        }
        // libfoo.so.1 and config.json, plus the C library and dynamic loader names.
        assert_eq!(noise["filename"]["count"], 4, "{name}: {noise:#}");
        let examples = noise["namespace"]["examples"].to_string();
        assert!(examples.contains("www.w3.org") && examples.contains("schemas.android.com"), "{examples}");
        assert_eq!(row(&value, "updates.vendor-cloud.example")["reason"], "documentation name (RFC 2606)");
        assert_eq!(row(&value, "192.168.1.1")["reason"], "private address (RFC 1918)");
        assert_eq!(row(&value, "http://localhost:8080/debug")["form"], "url");
        assert_eq!(value["counts"]["local"], 8, "{name}");
    }
}

#[test]
fn findings_name_their_string_referencing_functions_and_networking_callers() {
    for name in ["endpoints-x64.elf", "endpoints-arm64.elf"] {
        let value = inventory(&query(&local_fixture(name)));
        let updates = row(&value, "updates.vendor-cloud.example");
        assert_eq!(updates["signal"], "network_code", "{name}: {updates:#}");
        let evidence = &updates["evidence"][0];
        assert_eq!((evidence["origin"].as_str(), evidence["encoding"].as_str()), (Some("string"), Some("ascii")));
        assert!(evidence["address"].as_str().unwrap().starts_with("0x"));
        assert!(evidence["functions"][0].as_str().unwrap().starts_with("send_telemetry@0x"), "{evidence:#}");
        assert_eq!(evidence["network_apis"], serde_json::json!(["send"]), "{name}");
        let v6 = &row(&value, "2001:db8:10::25")["evidence"][0];
        assert_eq!(v6["network_apis"], serde_json::json!(["connect", "inet_pton", "socket"]), "{name}");
        let status = row(&value, "http://198.51.100.20/status");
        assert_eq!(status["signal"], "referenced", "{name}");
        assert!(status["evidence"][0]["functions"][0].as_str().unwrap().starts_with("show_trust@"));
        assert!(status["evidence"][0].get("network_apis").is_none());

        // Without references the same findings are not traced.
        let untraced = inventory(&InventoryQuery { xrefs: Some(false), ..query(&local_fixture(name)) });
        assert_eq!(row(&untraced, "updates.vendor-cloud.example")["signal"], "not_traced");
        assert_eq!(kinds_and_values(&untraced), kinds_and_values(&value));
    }
}

#[test]
fn pins_and_certificates_link_up() {
    let value = inventory(&query(&local_fixture("endpoints-x64.elf")));
    let pin = row(&value, PIN);
    assert_eq!(pin["pins_certificate"], SUBJECT);
    let certificate = row(&value, SUBJECT);
    assert_eq!(certificate["occurrences"], 2, "the PEM and the DER copy: {certificate:#}");
    let encodings: BTreeSet<&str> =
        certificate["evidence"].as_array().unwrap().iter().map(|item| item["encoding"].as_str().unwrap()).collect();
    assert_eq!(encodings, BTreeSet::from(["der", "pem"]));
    let details = &certificate["certificate"];
    assert_eq!(details["common_name"], "device-ca.vendor-cloud.example");
    assert_eq!(details["alt_names"], serde_json::json!(["telemetry.vendor-cloud.example", "*.vendor-cloud.example"]));
    assert_eq!((&details["self_signed"], &details["ca"]), (&Value::Bool(true), &Value::Bool(true)));
    assert_eq!(details["spki_pin"], PIN);
    assert_eq!(details["not_after"], "Jan  1 00:00:00 2036 +00:00");
    // The PEM is referenced from show_trust; the DNS names inside the DER are not reported again as hosts.
    assert_eq!(certificate["signal"], "referenced");
    assert!(rows(&value).iter().all(|row| row["value"] != "telemetry.vendor-cloud.example"));
}

#[test]
fn decoded_strings_add_endpoints_with_their_decoder() {
    for name in ["endpoints-x64.elf", "endpoints-arm64.elf"] {
        let plain = inventory(&query(&local_fixture(name)));
        assert!(rows(&plain).iter().all(|row| !row["value"].as_str().unwrap().starts_with("mqtts://")));
        let value = inventory(&InventoryQuery { decode: true, ..query(&local_fixture(name)) });
        for url in ["mqtts://broker.vendor-cloud.example:8883", "wss://push.vendor-cloud.example/socket"] {
            let decoded = row(&value, url);
            assert_eq!(decoded["kind"], "local", "{name}");
            let evidence = &decoded["evidence"][0];
            assert_eq!(evidence["origin"], "decoded", "{name}: {decoded:#}");
            assert!(evidence["decoded_by"].as_str().unwrap().starts_with("decode@0x"), "{name}: {decoded:#}");
            assert!(evidence["functions"][0].as_str().unwrap().starts_with("main@0x"), "{name}: {decoded:#}");
        }
        let group = value["domains"]
            .as_array()
            .unwrap()
            .iter()
            .find(|group| group["domain"] == "vendor-cloud.example")
            .unwrap();
        assert_eq!(
            group["hosts"],
            serde_json::json!([
                "broker.vendor-cloud.example",
                "push.vendor-cloud.example",
                "telemetry.vendor-cloud.example",
                "updates.vendor-cloud.example"
            ]),
            "{name}"
        );
        assert_eq!(group["network_code"], true);
    }
}

/// A small extracted firmware tree: two executables, a boot script, configuration and documentation, a symlink.
fn firmware_tree(scratch: &Scratch) -> PathBuf {
    let root = scratch.0.join("rootfs");
    for directory in ["bin", "usr/bin", "etc/init.d", "usr/share/doc"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    std::fs::copy(local_fixture("endpoints-x64.elf"), root.join("bin/telemetryd")).unwrap();
    std::fs::copy(local_fixture("endpoints-arm64.elf"), root.join("usr/bin/updater")).unwrap();
    std::fs::write(
        root.join("etc/init.d/S50telemetry"),
        "#!/bin/sh\n# start the uploader\ncurl -s https://upload.vendor-cloud.example/api/v1/boot\nntpd -p time.vendor-cloud.example\n",
    )
    .unwrap();
    std::fs::write(
        root.join("etc/cloud.json"),
        "{\n  \"endpoint\": \"wss://push.vendor-cloud.example/socket\",\n  \"backup\": \"198.51.100.77\",\n  \"schema\": \"config.json\"\n}\n",
    )
    .unwrap();
    std::fs::write(
        root.join("etc/app.xml"),
        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"com.example.tv\"/>\n",
    )
    .unwrap();
    std::fs::write(
        root.join("etc/build.prop"),
        "ro.build.version=4.2.1.0\nro.vendor.server=api.vendor-cloud.example\n",
    )
    .unwrap();
    std::fs::write(root.join("usr/share/doc/readme.txt"), "See https://docs.vendor-cloud.example/manual\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("telemetryd", root.join("bin/sh")).unwrap();
    root
}

#[test]
fn a_tree_groups_endpoints_by_domain_and_component() {
    let scratch = Scratch::new("endpoint-tree");
    let root = firmware_tree(&scratch);
    let value = inventory(&query(&root));
    let scanned = &value["scanned"];
    assert_eq!((&scanned["executables"], &scanned["text_files"]), (&2.into(), &4.into()), "{scanned:#}");
    assert_eq!((&scanned["ignored"], &scanned["symlinks"]), (&1.into(), &1.into()), "{scanned:#}");
    assert_eq!(value["next_cursor"], Value::Null);
    let domains = value["domains"].as_array().unwrap();
    // The vendor domain is named by every component but app.xml, so it leads.
    let vendor = &domains[0];
    assert_eq!(vendor["domain"], "vendor-cloud.example", "{domains:#?}");
    assert_eq!(
        vendor["components"],
        serde_json::json!([
            "bin/telemetryd",
            "etc/build.prop",
            "etc/cloud.json",
            "etc/init.d/S50telemetry",
            "usr/bin/updater"
        ])
    );
    assert_eq!(vendor["hosts_total"], 6, "{vendor:#}");
    let components = value["components"].as_array().unwrap();
    let script = components.iter().find(|component| component["path"] == "etc/init.d/S50telemetry").unwrap();
    assert_eq!(script["format"], "text");
    let telemetryd = components.iter().find(|component| component["path"] == "bin/telemetryd").unwrap();
    assert_eq!(telemetryd["format"], "elf");
    // Text lines are evidence by line number; references are off by default in a tree.
    let upload = row(&value, "https://upload.vendor-cloud.example/api/v1/boot");
    assert_eq!((&upload["evidence"][0]["origin"], &upload["evidence"][0]["line"]), (&"text".into(), &3.into()));
    assert_eq!(upload["signal"], "not_traced");
    assert_eq!(row(&value, "updates.vendor-cloud.example")["signal"], "not_traced");
    assert_eq!(row(&value, "com.example.tv")["kind"], "package");
    // Noise from the text files: the version in build.prop, the namespace in app.xml, config.json in cloud.json.
    assert_eq!(value["noise"]["version"]["examples"], serde_json::json!(["1.2.3.4", "4.2.1.0"]));
    assert!(rows(&value).iter().all(|row| row["component"] != "usr/share/doc/readme.txt"));
}

#[test]
fn a_tree_pages_by_cursor_under_the_file_budget() {
    let scratch = Scratch::new("endpoint-pages");
    let root = firmware_tree(&scratch);
    let whole = inventory(&query(&root));
    // A list, not a set: a finding on two pages would show up twice.
    let mut seen = Vec::new();
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let page = inventory(&InventoryQuery { cursor: cursor.clone(), max_files: Some(2), ..query(&root) });
        pages += 1;
        assert!(page["scanned"]["files"].as_u64().unwrap() <= 2);
        for row in rows(&page) {
            seen.push((row["component"].to_string(), row["kind"].to_string(), row["value"].to_string()));
        }
        match page["next_cursor"].as_str() {
            Some(next) => {
                assert_eq!(page["stopped"], "max_files");
                assert!(cursor.as_deref().is_none_or(|previous| previous < next), "the cursor moves forward");
                cursor = Some(next.to_owned());
            }
            None => break,
        }
    }
    assert_eq!(pages, 3);
    let mut all: Vec<_> = rows(&whole)
        .iter()
        .map(|row| (row["component"].to_string(), row["kind"].to_string(), row["value"].to_string()))
        .collect();
    seen.sort();
    all.sort();
    assert_eq!(seen, all, "the pages together hold every finding exactly once");
}

#[test]
fn a_tree_stops_on_the_time_budget_after_at_least_one_file() {
    let scratch = Scratch::new("endpoint-time");
    let root = firmware_tree(&scratch);
    let page = inventory(&InventoryQuery { timeout_ms: Some(1), xrefs: Some(true), ..query(&root) });
    assert_eq!(page["scanned"]["files"], 1, "{page:#}");
    assert_eq!(page["stopped"], "timeout_ms");
    assert_eq!(page["next_cursor"], "etc/app.xml");
    let error = endpoint_inventory(&InventoryQuery { timeout_ms: Some(0), ..query(&root) }).unwrap_err();
    assert!(error.contains("timeout_ms"), "{error}");
    let error = endpoint_inventory(&InventoryQuery { cursor: Some("x".into()), ..query(&local_fixture("decode.c")) })
        .unwrap_err();
    assert!(error.contains("directory"), "{error}");
}

#[test]
fn an_extracted_squashfs_image_is_inventoried() {
    let scratch = Scratch::new("endpoint-sqfs");
    let image = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/fsimages/squashfs-xz.img");
    let output = scratch.0.join("rootfs");
    let extracted = rampage_api::fs_extract(&rampage_api::FsExtractQuery {
        path: image,
        at: rampage_unpack::At { offset: 0, length: None },
        inner: Vec::new(),
        output_dir: output.clone(),
        paths: Vec::new(),
        max_bytes: None,
        max_files: None,
        max_file_bytes: None,
        max_ratio: None,
    })
    .unwrap();
    assert_eq!(extracted["executables_total"], 1);
    let value = inventory(&query(&output));
    assert_eq!(value["scanned"]["executables"], 1, "bin/hello: {value:#}");
    let upload = row(&value, "https://telemetry.example.invalid/collect");
    assert_eq!((&upload["kind"], &upload["component"]), (&"local".into(), &"etc/device.conf".into()));
    assert_eq!(upload["evidence"][0]["line"], 2);
}

fn blocklist(path: Option<&Path>, output: &Path, format: &str) -> BlocklistQuery {
    BlocklistQuery {
        path: path.map(Path::to_path_buf),
        entries: None,
        output: output.to_path_buf(),
        format: format.to_owned(),
        level: None,
        allow: Vec::new(),
        deny: Vec::new(),
        include_local: true,
        overwrite: false,
        decode: false,
        max_files: None,
        timeout_ms: None,
    }
}

/// Each format against its golden file in tests/fixtures/endpoint-blocklists (rewritten with
/// `RAMPAGE_UPDATE_GOLDEN=1`).
#[test]
fn blocklists_match_their_golden_files() {
    let scratch = Scratch::new("endpoint-golden");
    let root = firmware_tree(&scratch);
    let goldens = local_fixture("endpoint-blocklists");
    for (format, level) in [
        ("hosts", "domain"),
        ("hosts", "host"),
        ("dnsmasq", "domain"),
        ("dnsmasq_server", "domain"),
        ("unbound", "domain"),
        ("domains", "host"),
        ("ips", "host"),
    ] {
        let output = scratch.0.join(format!("{format}-{level}.txt"));
        let mut request = blocklist(Some(&root), &output, format);
        request.level = Some(level.to_owned());
        let result = endpoint_blocklist(&request).unwrap();
        assert_eq!(result["output"], output.to_str().unwrap());
        let written = std::fs::read_to_string(&output).unwrap();
        let golden = goldens.join(format!("{format}-{level}.txt"));
        if std::env::var_os("RAMPAGE_UPDATE_GOLDEN").is_some() {
            std::fs::create_dir_all(&goldens).unwrap();
            std::fs::write(&golden, &written).unwrap();
        }
        assert_eq!(written, std::fs::read_to_string(&golden).unwrap(), "{format} {level}");
        let lines = written.lines().filter(|line| !line.starts_with(['#', ':']) && *line != "server:").count();
        assert_eq!(result["entries"].as_u64().unwrap() as usize, lines, "{format} {level}");
    }
}

/// Domain level widens a host only to the registrable domain the Public Suffix List gives, never to a public or
/// shared suffix: hosts under shared cloud and CDN domains, and names that are suffixes themselves, stay as they are.
#[test]
fn domain_level_never_widens_to_a_public_or_shared_suffix() {
    let scratch = Scratch::new("endpoint-suffixes");
    let goldens = local_fixture("endpoint-blocklists");
    let output = scratch.0.join("suffixes.txt");
    let mut request = blocklist(None, &output, "dnsmasq");
    request.entries = Some(
        [
            "https://s3.amazonaws.com/bucket/object",
            "abc-ats.iot.us-east-1.amazonaws.com",
            "device.azure-devices.net",
            "api.vendor-cloud.co.uk",
            "upload.vendor-cloud.co.uk",
            "docs.example-project.github.io",
            "status.example-project.herokuapp.com",
            // blogspot.com is in the list's private section and not shared infrastructure here: the blog's own name
            // is the registrable domain.
            "feed.example-blog.blogspot.com",
            "co.uk",
        ]
        .map(str::to_owned)
        .to_vec(),
    );
    let result = endpoint_blocklist(&request).unwrap();
    let written = std::fs::read_to_string(&output).unwrap();
    let golden = goldens.join("dnsmasq-suffixes.txt");
    if std::env::var_os("RAMPAGE_UPDATE_GOLDEN").is_some() {
        std::fs::write(&golden, &written).unwrap();
    }
    assert_eq!(written, std::fs::read_to_string(&golden).unwrap());
    for line in ["/amazonaws.com/", "/iot.us-east-1.amazonaws.com/", "/azure-devices.net/", "=/github.io/", "/uk/"] {
        assert!(!written.contains(line), "{line} in {written}");
    }
    assert!(written.contains("address=/vendor-cloud.co.uk/0.0.0.0\n"), "{written}");
    let kept = result["kept_at_host_level"].as_array().unwrap();
    let reason = |domain: &str| {
        kept.iter().find(|kept| kept["domain"] == domain).map(|kept| kept["reason"].as_str().unwrap().to_owned())
    };
    assert!(reason("amazonaws.com").unwrap().starts_with("shared"), "{kept:?}");
    assert!(reason("azure-devices.net").unwrap().starts_with("shared"), "{kept:?}");
    // Names that are public suffixes themselves are never written: blocking one blocks every domain under it.
    assert_eq!(result["left_out"]["public_suffix"], 2, "co.uk and s3.amazonaws.com: {result:#}");
    assert!(!written.contains("/co.uk/") && !written.contains("/s3.amazonaws.com/"), "{written}");
}

/// A deny pattern naming hosts keeps their domain at host level; one covering the domain widens to it.
#[test]
fn deny_narrows_domain_level_to_the_hosts_it_names() {
    let scratch = Scratch::new("endpoint-deny");
    let output = scratch.0.join("deny.txt");
    let mut request = blocklist(None, &output, "domains");
    request.entries = Some(vec!["telemetry.vendor.com".into(), "updater.vendor.com".into()]);
    request.deny = vec!["telemetry.vendor.com".into()];
    let result = endpoint_blocklist(&request).unwrap();
    assert_eq!(std::fs::read_to_string(&output).unwrap().lines().skip(1).collect::<Vec<_>>(), ["telemetry.vendor.com"]);
    assert_eq!(result["kept_at_host_level"][0]["domain"], "vendor.com");
    request.deny = vec!["vendor.com".into()];
    endpoint_blocklist(&request).unwrap();
    assert_eq!(std::fs::read_to_string(&output).unwrap().lines().skip(1).collect::<Vec<_>>(), ["vendor.com"]);
}

#[cfg(unix)]
#[test]
fn replacing_keeps_the_mode_and_refuses_files_this_tool_did_not_write() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new("endpoint-replace");
    let output = scratch.0.join("list.txt");
    let mut request = blocklist(None, &output, "hosts");
    request.entries = Some(vec!["telemetry.vendor-cloud.example".into()]);
    request.level = Some("host".into());
    endpoint_blocklist(&request).unwrap();
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o640)).unwrap();
    let result = endpoint_blocklist(&request).unwrap();
    assert_eq!(result["replaced"], true);
    assert_eq!(std::fs::metadata(&output).unwrap().permissions().mode() & 0o7777, 0o640);
    assert_eq!(
        std::fs::read_to_string(&output).unwrap().lines().skip(1).collect::<Vec<_>>(),
        ["0.0.0.0 telemetry.vendor-cloud.example", ":: telemetry.vendor-cloud.example"]
    );

    let other = scratch.0.join("hosts");
    std::fs::write(&other, "127.0.0.1 localhost\n").unwrap();
    let mut refused = blocklist(None, &other, "hosts");
    refused.entries = request.entries.clone();
    let error = endpoint_blocklist(&refused).unwrap_err();
    assert!(error.contains("overwrite: true"), "{error}");
    assert_eq!(std::fs::read_to_string(&other).unwrap(), "127.0.0.1 localhost\n");
    refused.overwrite = true;
    endpoint_blocklist(&refused).unwrap();
    assert!(std::fs::read_to_string(&other).unwrap().starts_with("# rampage endpoint blocklist"));
}

/// A symlink in the output's directory path is resolved once; the list lands in the real directory and the result
/// names the canonical path.
#[cfg(unix)]
#[test]
fn a_symlinked_parent_directory_is_resolved_once() {
    let scratch = Scratch::new("endpoint-parent");
    let real = scratch.0.join("real");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, scratch.0.join("link")).unwrap();
    let mut request = blocklist(None, &scratch.0.join("link/list.txt"), "domains");
    request.entries = Some(vec!["telemetry.vendor-cloud.example".into()]);
    let result = endpoint_blocklist(&request).unwrap();
    assert_eq!(result["output"], real.join("list.txt").to_str().unwrap());
    assert!(real.join("list.txt").is_file());
    let names: Vec<_> = std::fs::read_dir(&real).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    assert_eq!(names.len(), 1, "no temporary file is left: {names:?}");
}

#[test]
fn blocklists_leave_out_local_findings_unless_asked_and_honour_allow_and_deny() {
    let scratch = Scratch::new("endpoint-filters");
    let binary = local_fixture("endpoints-x64.elf");
    let output = scratch.0.join("list.txt");
    let error =
        endpoint_blocklist(&BlocklistQuery { include_local: false, ..blocklist(Some(&binary), &output, "domains") })
            .unwrap_err();
    assert!(error.contains("nothing to write") && error.contains("5 local"), "{error}");
    // localhost, 192.168.1.1 and fe80::1 are never written, include_local or not.
    assert!(error.contains("3 never_blocked"), "{error}");
    assert!(!output.exists());

    // Allowing one host keeps its domain at host level, so the host stays reachable.
    let mut request = blocklist(Some(&binary), &output, "dnsmasq");
    request.allow = vec!["updates.vendor-cloud.example".to_owned()];
    let result = endpoint_blocklist(&request).unwrap();
    assert_eq!(result["kept_at_host_level"][0]["domain"], "vendor-cloud.example");
    assert_eq!(result["kept_at_host_level"][0]["reason"], "allow keeps a name under it reachable");
    let written = std::fs::read_to_string(&output).unwrap();
    assert!(written.contains("address=/telemetry.vendor-cloud.example/0.0.0.0\n"), "{written}");
    assert!(!written.contains("updates.") && !written.contains("address=/vendor-cloud.example/"), "{written}");
    assert_eq!(result["left_out"]["allowed"], 1);

    // Deny keeps only what it matches; an existing regular file is replaced.
    let mut request = blocklist(Some(&binary), &output, "ips");
    request.deny = vec!["198.51.100.0/24".to_owned(), "2001:db8::/32".to_owned()];
    let result = endpoint_blocklist(&request).unwrap();
    assert_eq!(result["entries"], 2);
    let written = std::fs::read_to_string(&output).unwrap();
    assert_eq!(written.lines().skip(1).collect::<Vec<_>>(), ["198.51.100.20", "2001:db8:10::25"]);

    // Explicit entries need no scan and are taken as given.
    let mut request = blocklist(None, &output, "unbound");
    request.include_local = false;
    request.entries = Some(vec!["https://collector.vendor-cloud.example/v1".into(), "203.0.113.9".into()]);
    request.level = Some("host".into());
    let result = endpoint_blocklist(&request).unwrap();
    assert_eq!(result["left_out"]["addresses_in_dns_format"], 1);
    assert_eq!(
        std::fs::read_to_string(&output).unwrap().lines().skip(1).collect::<Vec<_>>(),
        ["server:", "    local-zone: \"collector.vendor-cloud.example\" always_nxdomain"]
    );
}

#[test]
fn blocklist_output_paths_are_checked() {
    let scratch = Scratch::new("endpoint-paths");
    let binary = local_fixture("endpoints-x64.elf");
    let refused = |output: &Path| endpoint_blocklist(&blocklist(Some(&binary), output, "hosts")).unwrap_err();
    assert!(refused(Path::new("relative/list.txt")).contains("absolute"));
    assert!(refused(&scratch.0).contains("not a regular file"));
    assert!(refused(&scratch.0.join("missing/list.txt")).contains("does not exist"));
    #[cfg(unix)]
    {
        let target = scratch.0.join("target.txt");
        std::fs::write(&target, "keep\n").unwrap();
        let link = scratch.0.join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(refused(&link).contains("symlink"));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep\n");
    }
    let tree = firmware_tree(&scratch);
    let mut request = blocklist(Some(&tree), &scratch.0.join("tree.txt"), "hosts");
    request.max_files = Some(1);
    let error = endpoint_blocklist(&request).unwrap_err();
    assert!(error.contains("stopped at") && error.contains("nothing was written"), "{error}");
    let mut request = blocklist(None, &scratch.0.join("both.txt"), "hosts");
    for entry in ["not a host", "foo bar.com", "a.vendor-cloud.example\nb.vendor-cloud.example", "localhost"] {
        request.entries = Some(vec![entry.into()]);
        let error = endpoint_blocklist(&request).unwrap_err();
        assert!(error.contains("not one host") || error.contains("single_label"), "{entry}: {error}");
    }
    assert!(
        endpoint_blocklist(&blocklist(None, &scratch.0.join("none.txt"), "hosts")).unwrap_err().contains("exactly one")
    );
    assert!(
        endpoint_blocklist(&blocklist(Some(&binary), &scratch.0.join("x.txt"), "pf"))
            .unwrap_err()
            .contains("unknown format")
    );
    // Nothing but the refusal notes was written into the scratch directory.
    let left: Vec<_> = std::fs::read_dir(&scratch.0).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    assert!(left.iter().all(|name| !name.to_string_lossy().ends_with(".tmp")), "{left:?}");
}

#[test]
fn the_blocklist_tool_writes_files_and_the_inventory_does_not() {
    let tools = rampage_api::tools::file_tools();
    let effect = |name: &str| tools.iter().find(|tool| tool.name == name).unwrap().effect;
    assert_eq!(effect("endpoint_blocklist"), rampage_api::tools::Effect::FileWrite);
    assert_eq!(effect("endpoint_inventory"), rampage_api::tools::Effect::None);
}
