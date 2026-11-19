//! fs_list and fs_extract over MCP: carve-gated, paged, nested, safe extraction, and the hint a filesystem image
//! gets when opened as a binary.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use rampage_api::tools::Group;
use rampage_mcp::RampageServer;
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Value, json};

type Client = RunningService<RoleClient, ()>;

async fn connect(server: RampageServer) -> Client {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        server.serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    ().serve(client_transport).await.unwrap()
}

async fn call(client: &Client, name: &str, arguments: Value) -> CallToolResult {
    client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(arguments.as_object().unwrap().clone()))
        .await
        .unwrap()
}

fn text(result: &CallToolResult) -> &str {
    result.content.first().unwrap().as_text().unwrap().text.as_str()
}

fn json_of(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{}", text(result));
    assert!(text(result).len() <= 60_000);
    serde_json::from_str(text(result)).unwrap()
}

pub(crate) fn fsimage(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/fsimages").join(name)
}

/// A new directory path (not created) under the system temporary directory, removed on drop.
pub(crate) struct Output(pub(crate) PathBuf);

impl Output {
    pub(crate) fn new() -> Self {
        static SERIAL: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::temp_dir().join(format!(
            "rampage-mcp-fs-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        Self(base)
    }

    pub(crate) fn dir(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn fs_tools_are_carve_gated_and_list_pages() {
    let client = connect(RampageServer::default()).await;
    let refused = call(&client, "fs_list", json!({ "path": fsimage("squashfs-xz.img") })).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(text(&refused).contains("`carve` group"));
    json_of(&call(&client, "enable_tools", json!({ "groups": ["carve"] })).await);
    let tools = client.list_all_tools().await.unwrap();
    let extract = tools.iter().find(|tool| tool.name == "fs_extract").unwrap();
    assert_eq!(extract.annotations.as_ref().unwrap().read_only_hint, Some(false));
    assert_eq!(extract.annotations.as_ref().unwrap().destructive_hint, Some(false));

    let first = json_of(&call(&client, "fs_list", json!({ "path": fsimage("squashfs-xz.img"), "limit": 3 })).await);
    assert_eq!(first["layers"][0]["format"], "squashfs");
    assert_eq!(first["entries"].as_array().unwrap().len(), 3);
    assert_eq!(first["next_offset"], 3);
    assert_eq!(first["counts"]["symlink"], 2);
    let total = first["total"].as_u64().unwrap();
    let rest = json_of(&call(&client, "fs_list", json!({ "path": fsimage("squashfs-xz.img"), "offset": 3 })).await);
    assert_eq!(rest["entries"].as_array().unwrap().len() as u64, total - 3);
    assert!(rest["next_offset"].is_null());
    let prefixed = json_of(
        &call(&client, "fs_list", json!({ "path": fsimage("ext4.img"), "prefix": "/usr/share/demo/nested" })).await,
    );
    let paths: Vec<&str> =
        prefixed["entries"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["usr/share/demo/nested", "usr/share/demo/nested/deep.txt"]);
    let hello = rest["entries"]
        .as_array()
        .unwrap()
        .iter()
        .chain(first["entries"].as_array().unwrap())
        .find(|e| e["path"] == "bin/hello")
        .unwrap();
    assert_eq!(hello["type"], "file");
    assert_eq!(hello["mode"], 0o4755);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn fs_extract_writes_a_nested_partition_and_returns_openable_executables() {
    let client = connect(RampageServer::with_groups(Group::ALL)).await;
    let payload = fsimage("payload.bin");
    let partitions = json_of(&call(&client, "fs_list", json!({ "path": payload })).await);
    assert_eq!(partitions["layers"][0]["format"], "ota_payload");
    assert!(partitions["hint"].as_str().unwrap().contains("inner"));
    let nested = json_of(&call(&client, "fs_list", json!({ "path": payload, "inner": ["vendor.img"] })).await);
    assert_eq!(nested["layers"][1]["format"], "squashfs");
    assert_eq!(nested["layers"][1]["entry"], "vendor.img");

    let output = Output::new();
    let out = output.dir("system");
    let report = json_of(
        &call(&client, "fs_extract", json!({ "path": payload, "inner": ["system.img"], "output_dir": out })).await,
    );
    assert_eq!(report["layers"][1]["format"], "ext");
    let elf = report["executables"][0]["path"].as_str().unwrap();
    assert_eq!(report["executables"][0]["format"], "elf");
    assert!(report["skipped"].as_array().unwrap().iter().any(|skip| skip["path"] == "dev/console"));
    // An extracted executable opens as an analysis target by its path.
    let info = json_of(&call(&client, "binary_info", json!({ "path": elf })).await);
    assert_eq!(info["format"], "elf", "{info}");
    assert_eq!(info["arch"], "mips", "{info}");

    // The output directory must be new or empty, and a refusal says so.
    let again =
        call(&client, "fs_extract", json!({ "path": payload, "inner": ["system.img"], "output_dir": out })).await;
    assert_eq!(again.is_error, Some(true));
    assert!(text(&again).contains("new or empty"), "{}", text(&again));
    let relative = call(&client, "fs_extract", json!({ "path": payload, "output_dir": "relative/out" })).await;
    assert!(text(&relative).contains("absolute"), "{}", text(&relative));
    #[cfg(unix)]
    {
        let real = output.dir("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, output.dir("link")).unwrap();
        let linked = call(&client, "fs_extract", json!({ "path": payload, "output_dir": output.dir("link") })).await;
        assert!(text(&linked).contains("output_dir is a symlink"), "{}", text(&linked));
        assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
    }
    let delta =
        call(&client, "fs_extract", json!({ "path": fsimage("delta.bin"), "output_dir": output.dir("d") })).await;
    assert_eq!(delta.is_error, Some(true));
    assert!(text(&delta).contains("only full payloads"), "{}", text(&delta));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn ubi_volumes_open_as_nested_images() {
    let client = connect(RampageServer::with_groups(Group::ALL)).await;
    let ubi = fsimage("ubi.img");
    let volumes = json_of(&call(&client, "fs_list", json!({ "path": ubi })).await);
    assert_eq!(volumes["layers"][0]["format"], "ubi");
    assert_eq!(volumes["entries"][0]["path"], "rootfs.img");
    assert_eq!(volumes["entries"][0]["type"], "image");
    assert!(volumes["hint"].as_str().unwrap().contains("volumes"), "{volumes}");
    let files =
        json_of(&call(&client, "fs_list", json!({ "path": ubi, "inner": ["rootfs.img"], "prefix": "bin" })).await);
    assert_eq!(files["layers"][1]["format"], "ubifs");
    assert_eq!(files["layers"][1]["entry"], "rootfs.img");
    assert!(files["entries"].as_array().unwrap().iter().any(|entry| entry["path"] == "bin/hello"), "{files}");
    let output = Output::new();
    let report = json_of(
        &call(&client, "fs_extract", json!({ "path": ubi, "inner": ["rootfs.img"], "output_dir": output.dir("root") }))
            .await,
    );
    assert_eq!(report["executables"][0]["format"], "elf", "{report}");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn opening_a_filesystem_image_as_a_binary_points_at_fs_list() {
    let client = connect(RampageServer::default()).await;
    for name in ["squashfs-gzip.img", "ext4.img", "payload.bin", "ext4.simg", "ubi.img", "ubifs-lzo.ubifs"] {
        let result = call(&client, "triage_report", json!({ "path": fsimage(name) })).await;
        assert_eq!(result.is_error, Some(true), "{name}");
        assert!(text(&result).contains("fs_list"), "{name}: {}", text(&result));
    }
    client.cancel().await.unwrap();
}

/// The owner's flow over MCP: extract a filesystem image, inventory the endpoints of the tree, write a blocklist.
#[tokio::test]
async fn endpoints_of_an_extracted_tree_become_a_blocklist() {
    let client = connect(RampageServer::default()).await;
    let refused = call(&client, "endpoint_inventory", json!({ "path": fsimage("squashfs-xz.img") })).await;
    assert!(text(&refused).contains("`carve` group"), "{}", text(&refused));
    json_of(&call(&client, "enable_tools", json!({ "groups": ["carve"] })).await);
    let tools = client.list_all_tools().await.unwrap();
    let blocklist = tools.iter().find(|tool| tool.name == "endpoint_blocklist").unwrap();
    let annotations = blocklist.annotations.as_ref().unwrap();
    assert_eq!((annotations.read_only_hint, annotations.destructive_hint), (Some(false), Some(true)));
    assert_eq!(annotations.idempotent_hint, Some(true));
    // The carve group's and core's file tools that only read say so; the writers above and fs_extract do not.
    for name in [
        "endpoint_inventory",
        "archive_inventory",
        "fs_list",
        "carve",
        "list_dir",
        "decode_file_range",
        "file_layout",
        "probe_compression",
        "inspect_data",
        "inspect_raw_code",
        "inspect_sleigh",
    ] {
        let tool = tools.iter().find(|tool| tool.name == name).unwrap_or_else(|| panic!("{name} is listed"));
        let hints = tool.annotations.as_ref().unwrap_or_else(|| panic!("{name} is annotated"));
        assert_eq!((hints.read_only_hint, hints.open_world_hint), (Some(true), Some(false)), "{name}");
    }
    for name in ["fs_extract", "write_decoded_range", "endpoint_blocklist"] {
        let tool = tools.iter().find(|tool| tool.name == name).unwrap();
        assert_eq!(tool.annotations.as_ref().unwrap().read_only_hint, Some(false), "{name}");
    }

    let output = Output::new();
    let root = output.dir("rootfs");
    json_of(&call(&client, "fs_extract", json!({ "path": fsimage("squashfs-xz.img"), "output_dir": root })).await);
    let found = json_of(&call(&client, "endpoint_inventory", json!({ "path": root })).await);
    assert_eq!(found["scanned"]["executables"], 1, "{found}");
    let group = &found["domains"][0];
    assert_eq!(group["domain"], "example.invalid", "{found}");
    assert_eq!(group["components"], json!(["etc/device.conf"]));

    let list = output.dir("blocklist.conf");
    let written = json_of(
        &call(
            &client,
            "endpoint_blocklist",
            json!({ "path": root, "output": list, "format": "dnsmasq", "include_local": true }),
        )
        .await,
    );
    assert_eq!(written["entries"], 1, "{written}");
    assert_eq!(
        std::fs::read_to_string(&list).unwrap(),
        "# rampage endpoint blocklist (dnsmasq format, domain level): 1 entry\naddress=/example.invalid/0.0.0.0\n"
    );
    let relative = call(
        &client,
        "endpoint_blocklist",
        json!({ "entries": ["a.example.com"], "output": "x.conf", "format": "hosts" }),
    )
    .await;
    assert_eq!(relative.is_error, Some(true));
    assert!(text(&relative).contains("absolute"), "{}", text(&relative));
    client.cancel().await.unwrap();
}
