//! `list_dir`: an agent given only a folder lists it from the default tool set, with each entry's kind, size and
//! sniffed format, symlinks named but never followed, and pages by cursor.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

#[derive(Default)]
struct Client;
impl ClientHandler for Client {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

struct Folder(PathBuf);

impl Folder {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-mcp-list-dir-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn connect() -> RunningService<RoleClient, Client> {
    let (server, transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server).await.unwrap().waiting().await.unwrap();
    });
    Client.serve(transport).await.unwrap()
}

async fn call(client: &RunningService<RoleClient, Client>, arguments: Value) -> Result<Value, String> {
    let request =
        CallToolRequestParams::new("list_dir".to_owned()).with_arguments(arguments.as_object().unwrap().clone());
    let result = client.call_tool(request).await.unwrap();
    let text = result.content[0].as_text().unwrap().text.clone();
    if result.is_error == Some(true) { Err(text) } else { Ok(serde_json::from_str(&text).unwrap()) }
}

#[tokio::test]
async fn a_folder_lists_kinds_sizes_and_formats_from_the_default_tools() {
    let folder = Folder::new();
    let root = &folder.0;
    let elf = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m.elf"));
    std::fs::write(root.join("app.elf"), elf.unwrap()).unwrap();
    std::fs::write(root.join("update.bin"), [0xa5; 300]).unwrap();
    std::fs::write(root.join("notes.txt"), "release notes\n").unwrap();
    std::fs::write(root.join("image.hex"), ":10000000000102030405060708090A0B0C0D0E0F78\n:00000001FF\n").unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    std::os::unix::fs::symlink("/etc/hosts", root.join("link")).unwrap();

    let client = connect().await;
    let tools = client.list_all_tools().await.unwrap();
    assert!(tools.iter().any(|tool| tool.name == "list_dir"), "list_dir is in the default tool set");
    let listing = call(&client, json!({ "path": root })).await.unwrap();
    assert_eq!(listing["total"], 6);
    let entries = listing["entries"].as_array().unwrap();
    let shape: Vec<(&str, &str, Option<&str>)> = entries
        .iter()
        .map(|entry| (entry["name"].as_str().unwrap(), entry["kind"].as_str().unwrap(), entry["format"].as_str()))
        .collect();
    assert_eq!(
        shape,
        [
            ("app.elf", "file", Some("elf")),
            ("image.hex", "file", Some("ihex")),
            ("link", "symlink", None),
            ("notes.txt", "file", Some("text")),
            ("sub", "dir", None),
            ("update.bin", "file", Some("unknown")),
        ]
    );
    assert_eq!(entries[5]["size"], 300);
    assert_eq!(entries[2]["link"], "/etc/hosts");
    assert!(entries[2].get("size").is_none());

    // Pages resume at the cursor; a symlink or a file is refused as the directory.
    let first = call(&client, json!({ "path": root, "limit": 4 })).await.unwrap();
    assert_eq!(first["next_cursor"], "sub");
    let rest = call(&client, json!({ "path": root, "limit": 4, "cursor": first["next_cursor"] })).await.unwrap();
    assert_eq!(rest["entries"].as_array().unwrap().len(), 2);
    assert!(rest.get("next_cursor").is_none());
    std::os::unix::fs::symlink(root, root.join("sub/back")).unwrap();
    assert!(call(&client, json!({ "path": root.join("sub/back") })).await.unwrap_err().contains("symlink"));
    assert!(call(&client, json!({ "path": root.join("notes.txt") })).await.unwrap_err().contains("not a directory"));
    assert!(call(&client, json!({ "path": root, "limit": 501 })).await.is_err());
    let text = call(&client, json!({ "path": root, "cursor": "a\\q" })).await.unwrap_err();
    assert!(text.contains("cursor"), "{text}");
    client.cancel().await.unwrap();
}

/// A symlink loop as the listed path is refused, a FIFO is listed without opening it (no read blocks), and a name
/// with a backslash pages in escaped order.
#[tokio::test]
async fn loops_fifos_and_odd_names_neither_hang_nor_loop() {
    use std::os::unix::ffi::OsStrExt;
    let folder = Folder::new();
    let root = &folder.0;
    std::os::unix::fs::symlink(root.join("loop"), root.join("loop")).unwrap();
    let status = std::process::Command::new("mkfifo").arg(root.join("pipe")).status().unwrap();
    assert!(status.success());
    // APFS refuses names that are not UTF-8; the unit test covers their escaped order.
    for name in [&b"a"[..], b"b", b"\\"] {
        std::fs::write(root.join(std::ffi::OsStr::from_bytes(name)), b"x").unwrap();
    }
    let client = connect().await;
    let text = call(&client, json!({ "path": root.join("loop") })).await.unwrap_err();
    assert!(text.contains("symlink"), "{text}");
    let mut names = Vec::new();
    let mut cursor = Value::Null;
    for _ in 0..10 {
        let page = call(&client, json!({ "path": root, "limit": 1, "cursor": cursor })).await.unwrap();
        let entry = &page["entries"][0];
        if entry["name"] == "pipe" {
            assert_eq!((entry["kind"].as_str(), entry.get("format")), (Some("other"), None), "{entry}");
        }
        names.push(entry["name"].as_str().unwrap().to_owned());
        match page.get("next_cursor") {
            Some(next) => cursor = next.clone(),
            None => break,
        }
    }
    assert_eq!(names, ["\\\\", "a", "b", "loop", "pipe"]);
    client.cancel().await.unwrap();
}
