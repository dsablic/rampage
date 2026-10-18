//! One owned x86-64 static patch/export investigation over real MCP. Never executes the fixture.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rampage_api::Project;
use rampage_api::tools::Group;
use rampage_loaders::Binary;
use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const SELF_SOURCE: &str = "crates/rampage-eval/examples/patch_roundtrip.rs";
const ARTIFACT_ROOT: &str = "target/phase3-2-roundtrip-first";
const FIXTURE: &str = "tests/fixtures/bin/hello-x64.elf";
const FIXTURE_SHA: &str = "dd13c0fedd703a5a7ddd995e1a729ea42443ab23ec6e163c7c683263a1c62742";
const SOURCE_SHA: &str = "3f06109c966ca8c3d6cf5c87a031aab612be8f871f42c704f37a41b16ca1ecf7";
const BASELINE: &str = "target/parity/phase0-completion/accepted-scorecard.json";
const BASELINE_SHA: &str = "28fdbdcc2077b906db0f4676550b08a4752a7b3498945923a5276d7f81a4ce90";
const MAX_FILE: u64 = 32 * 1024 * 1024;
const MAX_JSON: usize = 2 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(90);
const REQUIRED: [&str; 9] = [
    "decompile",
    "assemble",
    "patch_bytes",
    "list_patches",
    "disassemble",
    "undo",
    "redo",
    "export_patched",
    "list_annotations",
];

fn digest(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > limit {
        return Err(format!("not a bounded regular file: {}", path.display()).into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("read exceeded bound".into());
    }
    Ok(bytes)
}

fn write_bytes_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_new(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() > MAX_JSON {
        return Err("JSON receipt exceeds bound".into());
    }
    bytes.push(b'\n');
    write_bytes_new(path, &bytes)
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    if !output.status.success() || output.stdout.len() > MAX_JSON {
        return Err("git provenance query failed or exceeded bound".into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn source_snapshot(root: &Path) -> Result<Value> {
    let listed = git(
        root,
        &["ls-files", "--cached", "--others", "--exclude-standard", "--", "crates", "Cargo.toml", "Cargo.lock"],
    )?;
    let mut paths: BTreeSet<String> = listed
        .lines()
        .filter(|name| {
            matches!(
                Path::new(name).extension().and_then(|part| part.to_str()),
                Some("rs" | "toml" | "lock" | "c" | "cc" | "cpp" | "h" | "hh" | "hpp" | "inc" | "s" | "S")
            )
        })
        .map(str::to_owned)
        .collect();
    paths.extend([SELF_SOURCE, "tests/fixtures/src/hello.c", "tests/fixtures/build.sh"].map(str::to_owned));
    if paths.len() > 10_000 {
        return Err("source count exceeds 10000 files".into());
    }
    let mut total = 0_usize;
    let mut sources = Vec::new();
    for name in paths {
        let path = Path::new(&name);
        if !path.components().all(|part| matches!(part, Component::Normal(_))) {
            return Err("source inventory path is not repository-relative".into());
        }
        let joined = root.join(path);
        if fs::symlink_metadata(&joined)?.file_type().is_symlink() {
            return Err("source inventory symlink refused".into());
        }
        let bytes = read(&joined, MAX_FILE)?;
        total += bytes.len();
        if total > 512 * 1024 * 1024 {
            return Err("source inventory exceeds 512 MiB".into());
        }
        sources.push(json!({"path":name,"bytes":bytes.len(),"sha256":digest(&bytes)}));
    }
    Ok(json!({"sources":sources,"total_bytes":total}))
}

fn independent_truth(root: &Path) -> Result<Value> {
    let original = read(&root.join(FIXTURE), MAX_FILE)?;
    let project = Project::new(Binary::open(root.join(FIXTURE))?);
    let main = project.resolve("main")?;
    let listing = project.function_listing(main)?;
    let lines: Vec<_> = listing.blocks.iter().flatten().collect();
    let instruction = lines
        .iter()
        .find(|line| line.address == 0x100191e)
        .ok_or("expected return-value instruction absent from original native listing")?;
    if main != 0x1001910
        || listing.name != "main"
        || instruction.bytes != "b805000000"
        || instruction.text != "mov eax, 5"
        || original.get(0x91e..0x923) != Some(&[0xb8, 5, 0, 0, 0])
        || project.binary.read(0x100191e, 5) != Some(&[0xb8, 5, 0, 0, 0])
    {
        return Err("original function/address/preimage truth mismatch".into());
    }
    if !lines.iter().any(|line| line.text == "ret" && line.address > instruction.address) {
        return Err("native listing lacks the expected return after the constant assignment".into());
    }
    Ok(json!({"method":"Original file bytes plus separate native function_listing before MCP calls",
        "main":"0x1001910","patch_address":"0x100191e","file_offset":2334,
        "original_hex":"b805000000","desired_replacement_hex":"b807000000",
        "baseline_return":5,"desired_return":7,"listing":listing,
        "limitations":["Static decoding only; the native decoder is shared with the analysis tools.",
            "Decompiler C is checked for one literal return statement, not target execution or a general semantic proof."]}))
}

fn fixture_inventory(directory: &Path) -> Result<Value> {
    let mut paths: Vec<_> =
        fs::read_dir(directory)?.map(|entry| entry.map(|entry| entry.path())).collect::<std::io::Result<_>>()?;
    paths.sort();
    if paths.len() > 32 {
        return Err("fixture directory exceeds 32 entries".into());
    }
    let mut files = Vec::new();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("unexpected directory, staging residue or symlink in fixture directory".into());
        }
        let bytes = read(&path, MAX_FILE)?;
        files.push(
            json!({"name":path.file_name().and_then(|name|name.to_str()).ok_or("fixture filename is not UTF-8")?,
            "bytes":bytes.len(),"sha256":digest(&bytes)}),
        );
    }
    Ok(json!(files))
}

#[derive(Default)]
struct Client;
impl ClientHandler for Client {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

struct Connection {
    client: RunningService<RoleClient, Client>,
    server: tokio::task::JoinHandle<std::result::Result<(), String>>,
}

impl Connection {
    async fn open(traces: &mut Traces, label: &str) -> Result<Self> {
        let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            rampage_mcp::RampageServer::with_groups([Group::Core])
                .serve(server_transport)
                .await
                .map_err(|error| error.to_string())?
                .waiting()
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        });
        let client = timeout(TIMEOUT, Client.serve(client_transport)).await??;
        let connection = Self { client, server };
        let catalog = timeout(TIMEOUT, connection.client.list_all_tools()).await??;
        let selected: Vec<_> = catalog.iter().filter(|tool| REQUIRED.contains(&tool.name.as_ref())).collect();
        write_new(
            &traces.directory.join(format!("catalog-{label}.json")),
            &json!({
                "transport":"actual_rmcp_in_memory_duplex","tools":selected,
                "required":REQUIRED,"fresh_server_and_session":true,
            }),
        )?;
        if !REQUIRED.iter().all(|name| catalog.iter().any(|tool| tool.name.as_ref() == *name)) {
            return Err("required round-trip tool absent from actual MCP catalog".into());
        }
        Ok(connection)
    }

    async fn close(self) -> Result<()> {
        timeout(TIMEOUT, self.client.cancel()).await??;
        timeout(TIMEOUT, self.server).await??.map_err(Into::into)
    }
}

struct Traces {
    directory: PathBuf,
    calls: Vec<Value>,
}

impl Traces {
    async fn call(
        &mut self,
        connection: &Connection,
        step: &str,
        name: &str,
        input: Value,
        expected_error: bool,
    ) -> Result<Value> {
        let started = Instant::now();
        let response = timeout(
            TIMEOUT,
            connection.client.call_tool(
                CallToolRequestParams::new(name.to_owned())
                    .with_arguments(input.as_object().ok_or("MCP input is not an object")?.clone()),
            ),
        )
        .await;
        let elapsed_us = started.elapsed().as_micros();
        let index = self.calls.len();
        let mut receipt = json!({"index":index,"step":step,"name":name,"input":input,
            "expected_error":expected_error,"elapsed_us":elapsed_us,
            "transport":"actual_rmcp_in_memory_duplex"});
        let body = match response {
            Err(error) => {
                receipt["timeout_error"] = json!(error.to_string());
                Err("MCP request timed out".into())
            }
            Ok(Err(error)) => {
                receipt["transport_error"] = json!(error.to_string());
                Err("MCP transport request failed".into())
            }
            Ok(Ok(result)) => {
                let text = result.content.first().and_then(|block| block.as_text()).map(|block| &block.text);
                let size = serde_json::to_vec(&result)?.len();
                receipt["serialized_response_bytes"] = json!(size);
                receipt["is_error"] = json!(result.is_error == Some(true));
                if size > 65_536 || text.is_some_and(|text| text.len() > 60_000) {
                    receipt["output_rejected"] = json!("response exceeds complete JSON/text output bound");
                    Err("MCP output exceeds bound; no truncated evidence accepted".into())
                } else {
                    receipt["result"] = serde_json::to_value(&result)?;
                    if result.content.len() != 1 || text.is_none() || (result.is_error == Some(true)) != expected_error
                    {
                        Err("MCP error disposition/content shape differs from this step's contract".into())
                    } else if expected_error {
                        Ok(json!({"rejected":true,"reason":text}))
                    } else {
                        serde_json::from_str(text.ok_or("MCP text missing")?).map_err(Into::into)
                    }
                }
            }
        };
        write_new(&self.directory.join(format!("call-{index:03}.json")), &receipt)?;
        self.calls.push(receipt);
        body
    }

    async fn review(&mut self, connection: &Connection, source: &Path, step: &str) -> Result<Value> {
        let page =
            self.call(connection, step, "list_patches", json!({"path":source,"offset":0,"limit":100}), false).await?;
        let patches = page["patches"].as_array().ok_or("patch page missing records")?;
        if page["offset"] != 0
            || !page["next_offset"].is_null()
            || page["total"].as_u64() != Some(patches.len() as u64)
            || page["receipt"]["source_sha256"] != FIXTURE_SHA
        {
            return Err("patch review is incomplete or not bound to the owned original".into());
        }
        Ok(page)
    }

    async fn annotations(&mut self, connection: &Connection, source: &Path, step: &str) -> Result<Value> {
        self.call(connection, step, "list_annotations", json!({"path":source}), false).await
    }

    async fn returns(&mut self, connection: &Connection, source: &Path, step: &str, expected: u8) -> Result<Value> {
        let result =
            self.call(connection, step, "decompile", json!({"path":source,"at":"main","view":"code"}), false).await?;
        let code = result["code"].as_str().ok_or("decompile response missing C")?;
        let compact = code.split_whitespace().collect::<Vec<_>>().join(" ");
        let expected_return = format!("return {expected};");
        if result["name"] != "main"
            || result["address"] != "0x1001910"
            || compact.matches("return ").count() != 1
            || !compact.contains(&expected_return)
        {
            return Err(format!("{step}: native C does not show exactly one expected literal return").into());
        }
        Ok(json!({"step":step,"return_value":expected,"code_sha256":digest(code.as_bytes()),
            "check_method":"exact single literal return statement in native C; static evidence only",
            "response":result}))
    }

    async fn rejection(
        &mut self,
        connection: &Connection,
        source: &Path,
        directory: &Path,
        label: &str,
        name: &str,
        make_input: impl FnOnce(&Value) -> Value,
    ) -> Result<Value> {
        let before = self.review(connection, source, &format!("{label}-review-before")).await?;
        let annotations_before = self.annotations(connection, source, &format!("{label}-annotations-before")).await?;
        let files_before = fixture_inventory(directory)?;
        let result = self.call(connection, label, name, make_input(&before["receipt"]), true).await?;
        let after = self.review(connection, source, &format!("{label}-review-after")).await?;
        let annotations_after = self.annotations(connection, source, &format!("{label}-annotations-after")).await?;
        let files_after = fixture_inventory(directory)?;
        let unchanged = before == after && annotations_before == annotations_after && files_before == files_after;
        let check = json!({"step":label,"result":result,"unchanged":unchanged,
            "patch_review_before":before,"patch_review_after":after,
            "annotations_before":annotations_before,"annotations_after":annotations_after,
            "files_before":files_before,"files_after":files_after});
        write_new(&self.directory.join(format!("rejection-{label}.json")), &check)?;
        if !unchanged {
            return Err(format!("{label}: rejection changed patches, annotations, source or directory contents").into());
        }
        Ok(check)
    }
}

fn patch_input(source: &Path, truth: &Value, proposal: &Value, receipt: &Value) -> Value {
    json!({"path":source,"at":truth["patch_address"],"original_hex":truth["original_hex"],
        "replacement_hex":proposal["bytes_hex"],"allow_data":false,
        "source_sha256":receipt["source_sha256"],"expected_revision":receipt["revision_sha256"]})
}

fn corrupt_token(token: &Value) -> Result<Value> {
    let text = token.as_str().ok_or("review token missing")?;
    if text.len() < 2 {
        return Err("review token too short".into());
    }
    Ok(json!(format!("{}{}", if text.starts_with('0') { '1' } else { '0' }, &text[1..])))
}

async fn workflow(root: &Path, run: &Path, truth: &Value, traces: &mut Traces) -> Result<Value> {
    let directory = run.join("fixture");
    fs::create_dir(&directory)?;
    let source = directory.join("source.elf");
    let original = read(&root.join(FIXTURE), MAX_FILE)?;
    write_bytes_new(&source, &original)?;
    let connection = Connection::open(traces, "original").await?;
    let mut returns = vec![traces.returns(&connection, &source, "baseline", 5).await?];
    let baseline = traces.review(&connection, &source, "baseline-review").await?;
    if baseline["total"] != 0 || baseline["receipt"]["effective_sha256"] != FIXTURE_SHA {
        return Err("fresh fixture already has patches".into());
    }
    let annotations_before = traces.annotations(&connection, &source, "assembly-annotations-before").await?;
    let files_before = fixture_inventory(&directory)?;
    let proposal = traces
        .call(
            &connection,
            "assembly-proposal",
            "assemble",
            json!({"path":source,"at":truth["patch_address"],"source":"mov eax, 7"}),
            false,
        )
        .await?;
    if proposal["bytes_hex"] != truth["desired_replacement_hex"]
        || proposal["instruction_count"] != 1
        || proposal["read_only"] != true
        || proposal["execution_verified"] != false
        || proposal["address"] != truth["patch_address"]
        || proposal["architecture"] != "x86_64"
    {
        return Err("assembly proposal differs from the independently reviewed x64 instruction".into());
    }
    let reviewed = traces.review(&connection, &source, "post-assembly-review").await?;
    let annotations_after = traces.annotations(&connection, &source, "assembly-annotations-after").await?;
    if reviewed != baseline || annotations_after != annotations_before || fixture_inventory(&directory)? != files_before
    {
        return Err("read-only assembly proposal changed image, patch receipt or annotations".into());
    }
    let patched = traces
        .call(
            &connection,
            "apply-reviewed-patch",
            "patch_bytes",
            patch_input(&source, truth, &proposal, &reviewed["receipt"]),
            false,
        )
        .await?;
    if patched["changed"] != true
        || patched["receipt"]["active_ranges"] != 1
        || patched["receipt"]["changed_bytes"] != 5
        || patched["receipt"]["source_sha256"] != FIXTURE_SHA
    {
        return Err("patch did not return the expected changed-range receipt".into());
    }
    let listing = traces
        .call(
            &connection,
            "patched-native-listing",
            "disassemble",
            json!({"path":source,"at":truth["patch_address"],"count":1}),
            false,
        )
        .await?;
    if listing.as_array().is_none_or(|rows| rows.len() != 1)
        || listing[0]["bytes"] != proposal["bytes_hex"]
        || listing[0]["address"] != truth["patch_address"]
    {
        return Err("effective native listing does not contain proposed bytes".into());
    }
    returns.push(traces.returns(&connection, &source, "patched", 7).await?);
    let mut rejections = vec![
        traces
            .rejection(&connection, &source, &directory, "stale-patch-review", "patch_bytes", |fresh| {
                let mut input = patch_input(&source, truth, &proposal, fresh);
                input["expected_revision"] = baseline["receipt"]["revision_sha256"].clone();
                input
            })
            .await?,
    ];
    rejections.push(
        traces
            .rejection(&connection, &source, &directory, "wrong-original-preimage", "patch_bytes", |fresh| {
                let mut input = patch_input(&source, truth, &proposal, fresh);
                input["original_hex"] = json!("b806000000");
                input
            })
            .await?,
    );
    let wrong_source = corrupt_token(&baseline["receipt"]["source_sha256"])?;
    rejections.push(
        traces
            .rejection(&connection, &source, &directory, "wrong-source-review", "patch_bytes", |fresh| {
                let mut input = patch_input(&source, truth, &proposal, fresh);
                input["source_sha256"] = wrong_source;
                input
            })
            .await?,
    );
    let undone = traces.call(&connection, "undo-patch", "undo", json!({"path":source}), false).await?;
    if undone.as_array().is_none_or(|edits| edits.len() != 1) || undone[0]["field"] != "patch" {
        return Err("undo did not return exactly one patch edit".into());
    }
    returns.push(traces.returns(&connection, &source, "undone", 5).await?);
    let undone_review = traces.review(&connection, &source, "undone-review").await?;
    if undone_review["total"] != 0 || undone_review["receipt"]["effective_sha256"] != FIXTURE_SHA {
        return Err("undo did not restore original effective bytes".into());
    }
    let redone = traces.call(&connection, "redo-patch", "redo", json!({"path":source}), false).await?;
    if redone.as_array().is_none_or(|edits| edits.len() != 1) || redone[0]["field"] != "patch" {
        return Err("redo did not return exactly one patch edit".into());
    }
    returns.push(traces.returns(&connection, &source, "redone", 7).await?);
    let destination = directory.join("export.elf");
    let rejected_destination = directory.join("rejected-stale.elf");
    rejections.push(
        traces
            .rejection(&connection, &source, &directory, "stale-export-review", "export_patched", |fresh| {
                json!({"path":source,"destination":rejected_destination,
            "source_sha256":fresh["source_sha256"],"expected_revision":baseline["receipt"]["revision_sha256"]})
            })
            .await?,
    );
    if rejected_destination.exists() || destination.exists() {
        return Err("rejected export created an output or destination already exists".into());
    }
    let review = traces.review(&connection, &source, "export-review").await?;
    let exported = traces
        .call(
            &connection,
            "export-create-new",
            "export_patched",
            json!({"path":source,"destination":destination,"source_sha256":review["receipt"]["source_sha256"],
            "expected_revision":review["receipt"]["revision_sha256"]}),
            false,
        )
        .await?;
    let output = read(&destination, MAX_FILE)?;
    let mut expected_output = original.clone();
    expected_output[0x91e..0x923].copy_from_slice(&[0xb8, 7, 0, 0, 0]);
    if output != expected_output
        || digest(&output) != review["receipt"]["effective_sha256"]
        || exported["receipt"] != review["receipt"]
    {
        return Err("export bytes/receipt do not equal the reviewed effective image".into());
    }
    rejections.push(
        traces
            .rejection(&connection, &source, &directory, "existing-export-destination", "export_patched", |fresh| {
                json!({"path":source,"destination":destination,
            "source_sha256":fresh["source_sha256"],"expected_revision":fresh["revision_sha256"]})
            })
            .await?,
    );
    connection.close().await?;
    let reopened = Connection::open(traces, "export-new-session").await?;
    let export_patches = traces
        .call(
            &reopened,
            "reopened-export-no-patches",
            "list_patches",
            json!({"path":destination,"offset":0,"limit":100}),
            false,
        )
        .await?;
    if export_patches["total"] != 0
        || export_patches["patches"] != json!([])
        || export_patches["receipt"]["source_sha256"] != digest(&output)
        || export_patches["receipt"]["effective_sha256"] != digest(&output)
    {
        return Err("new export session depends on a patch overlay".into());
    }
    returns.push(traces.returns(&reopened, &destination, "export-reopened-new-session", 7).await?);
    reopened.close().await?;
    let no_export_sidecar =
        !directory.join("export.elf.rampage").exists() && !directory.join("export.elf.rampage.lock").exists();
    if !no_export_sidecar
        || read(&source, MAX_FILE)? != original
        || read(&root.join(FIXTURE), MAX_FILE)? != original
        || read(&destination, MAX_FILE)? != output
    {
        return Err("original bytes changed, export changed or export acquired a patch sidecar".into());
    }
    Ok(json!({"profile":"owned-existing-x64-static-elf","returns":returns,"assembly_proposal":proposal,
        "assembly_read_only_verified":true,"patched_native_listing":listing,"rejections":rejections,
        "export_receipt":exported,"export_sha256":digest(&output),"export_bytes_equal_reviewed_effective_image":true,
        "export_new_session_patch_review":export_patches,"export_has_no_patch_sidecar":no_export_sidecar,
        "original_file_sha256":digest(&original),"original_fixture_and_copy_unchanged":true,
        "aarch64_mcp_measured":false,"fixture_files_after":fixture_inventory(&directory)?}))
}

async fn run() -> Result<bool> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3
        || args[1].is_empty()
        || !args[1].bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("usage: patch_roundtrip RUN-ID BUILD-RECEIPT.json (receipt under owned artifact root)".into());
    }
    if std::env::var_os("RAMPAGE_WORKER").is_some()
        || std::env::current_exe()?.with_file_name("rampage-worker").exists()
    {
        return Err(
            "this collector requires embedded host decompilation: no RAMPAGE_WORKER override or sibling worker".into(),
        );
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize()?;
    let artifacts = root.join(ARTIFACT_ROOT).canonicalize()?;
    let receipt_path = Path::new(&args[2]).canonicalize()?;
    if !receipt_path.starts_with(&artifacts) {
        return Err("build receipt outside the owned artifact root".into());
    }
    let receipt_bytes = read(&receipt_path, MAX_JSON as u64)?;
    let build: Value = serde_json::from_slice(&receipt_bytes)?;
    let sources_before = source_snapshot(&root)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let executable_sha = digest(&read(&executable, 256 * 1024 * 1024)?);
    if build["success"] != true
        || build["source_snapshot_before"] != sources_before
        || build["source_snapshot_after"] != sources_before
        || build["executable_sha256"] != executable_sha
        || build["argv"].as_array().is_none_or(Vec::is_empty)
    {
        return Err("build receipt does not bind stable source inputs and this host executable".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&executable)?.permissions().mode() & 0o222 != 0 {
            return Err("collector executable must be frozen read-only before measurement".into());
        }
    }
    let self_bytes = read(&root.join(SELF_SOURCE), MAX_FILE)?;
    if self_bytes != include_bytes!("patch_roundtrip.rs")
        || digest(&read(&root.join(FIXTURE), MAX_FILE)?) != FIXTURE_SHA
        || digest(&read(&root.join("tests/fixtures/src/hello.c"), MAX_FILE)?) != SOURCE_SHA
        || digest(&read(&root.join(BASELINE), 64 * 1024 * 1024)?) != BASELINE_SHA
    {
        return Err("consumer source, fixture, owned source or frozen baseline digest mismatch".into());
    }
    let run = artifacts.join(&args[1]);
    fs::create_dir(&run)?;
    let trace_directory = run.join("traces");
    fs::create_dir(&trace_directory)?;
    let before = json!({"argv":args,"consumer_source":{"path":SELF_SOURCE,"sha256":digest(&self_bytes)},
        "executable":{"path":executable,"sha256":executable_sha,"read_only_before_run":true},
        "build_receipt":{"path":receipt_path,"sha256":digest(&receipt_bytes),"argv":build["argv"]},
        "source_snapshot":sources_before,"source_snapshot_sha256":digest(&serde_json::to_vec(&sources_before)?),
        "git_head":git(&root,&["rev-parse","HEAD"])?.trim(),
        "git_status":git(&root,&["status","--porcelain=v1","--untracked-files=all"])?,
        "fixture":{"path":FIXTURE,"sha256":FIXTURE_SHA,"source_sha256":SOURCE_SHA},
        "phase0_reference":{"path":BASELINE,"sha256":BASELINE_SHA,"regraded":false,"comparison_denominator":false},
        "decompiler":"embedded native host collector; no external worker or target execution",
        "started_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()});
    write_new(&run.join("before.json"), &before)?;
    let truth = independent_truth(&root)?;
    write_new(&run.join("independent-truth.json"), &truth)?;
    let mut traces = Traces { directory: trace_directory, calls: Vec::new() };
    let started = Instant::now();
    let result = match timeout(Duration::from_secs(240), workflow(&root, &run, &truth, &mut traces)).await {
        Ok(result) => result,
        Err(_) => Err("whole round-trip workflow exceeded 240 seconds".into()),
    };
    let elapsed_us = started.elapsed().as_micros();
    let sources_unchanged = source_snapshot(&root)? == sources_before;
    let executable_unchanged = digest(&read(&executable, 256 * 1024 * 1024)?) == executable_sha;
    let fixture_unchanged = digest(&read(&root.join(FIXTURE), MAX_FILE)?) == FIXTURE_SHA;
    let complete = result.is_ok() && sources_unchanged && executable_unchanged && fixture_unchanged;
    let report = json!({"schema_version":1,"task_id":"phase32-owned-x64-patch-roundtrip",
        "scope":"owned_scripted_real_mcp_patch_roundtrip_not_live_acceptance","complete":complete,
        "provenance":before,"truth":truth,"workflow":result.as_ref().ok(),
        "error":result.err().map(|error|error.to_string()),"elapsed_us":elapsed_us,
        "mcp_tools_call_requests":traces.calls.len(),"calls":traces.calls,
        "sources_unchanged":sources_unchanged,"executable_unchanged":executable_unchanged,
        "original_fixture_unchanged":fixture_unchanged,
        "provider_tokens":null,"provider_calls":0,"target_executed":false,
        "phase0_improvement":false,"frozen_patch_capability_regraded":false,"phase1_live_n_earned":false,
        "phase2_recall_evidence":false,"phase33_token_acceptance":false,
        "limitations":["One x86-64 static fixture, one attempted workflow; no AArch64 MCP claim.",
            "Static disassembly and literal-return C matching are not target execution or general behavioral equivalence.",
            "Only owned isolated copies and a create-new export are written; the source fixture is unchanged.",
            "Fresh source/revision review tokens are copied from actual list_patches receipts; stale-token probes deliberately reuse an earlier receipt.",
            "Caller-collected source/build/executable hashes are bindings, not authentication or a reproducible-build attestation."]});
    write_new(&run.join("report.json"), &report)?;
    println!(
        "{}",
        json!({"complete":complete,"report":run.join("report.json"),
        "report_sha256":digest(&read(&run.join("report.json"),MAX_JSON as u64)?),
        "mcp_tools_call_requests":report["mcp_tools_call_requests"],"error":report["error"]})
    );
    Ok(complete)
}

fn main() {
    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })
        .and_then(|runtime| runtime.block_on(run()));
    match result {
        Ok(true) => (),
        Ok(false) => std::process::exit(2),
        Err(error) => {
            eprintln!("patch round-trip incomplete: {error}");
            std::process::exit(2);
        }
    }
}
