//! Finite owned MSP430/AVR8/6502 MCP windows. No Project fallback, Java run, model or target execution.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rampage_api::tools::Group;
use rampage_decompiler::{require_verified_bundled_native_context, verify_bundled_specifications};
use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Functions = BTreeMap<u64, Vec<(u64, u64)>>;

const SELF_SOURCE: &str = "crates/rampage-eval/examples/sleigh_window_measurement.rs";
const ARTIFACT_ROOT: &str = "target/phase4-1-measurement-first";
const FIXTURES: &str = "tests/fixtures/sleigh";
const SPECS: &str = "crates/rampage-decompiler/specs";
const MAX_FILE: u64 = 32 * 1024 * 1024;
const MAX_JSON: usize = 2 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(90);
const PILOTS: [(&str, &str); 3] =
    [("msp430", "TI_MSP430:LE:16:default"), ("avr8", "avr8:LE:16:default"), ("6502", "6502:LE:16:default")];

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
        return Err("file grew beyond read bound".into());
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

fn json_file(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&read(path, MAX_FILE)?)?)
}

fn number(value: &Value) -> Result<u64> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    let text = value
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .ok_or("expected numeric internal byte address or hexadecimal address string")?;
    Ok(u64::from_str_radix(text, 16)?)
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value.get(key).and_then(Value::as_array).ok_or_else(|| format!("required array {key} missing").into())
}

fn regular_tree(directory: &Path, limit: usize) -> Result<Vec<PathBuf>> {
    let mut pending = vec![directory.to_owned()];
    let mut files = Vec::new();
    let mut entries = 0;
    while let Some(path) = pending.pop() {
        entries += 1;
        if entries > limit {
            return Err("tree entry limit exceeded".into());
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err("symlink refused in measured source tree".into());
        }
        if metadata.is_file() {
            files.push(path);
        } else if metadata.is_dir() {
            for child in fs::read_dir(&path)? {
                pending.push(child?.path());
                if entries + pending.len() > limit {
                    return Err("pending tree entry limit exceeded".into());
                }
            }
        } else {
            return Err("nonregular source tree entry refused".into());
        }
    }
    files.sort();
    Ok(files)
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
    let mut names: BTreeSet<String> = listed
        .lines()
        .filter(|name| {
            matches!(
                Path::new(name).extension().and_then(|part| part.to_str()),
                Some("rs" | "toml" | "lock" | "c" | "cc" | "cpp" | "h" | "hh" | "hpp" | "inc" | "s" | "S")
            )
        })
        .map(str::to_owned)
        .collect();
    names.insert(SELF_SOURCE.into());
    for path in regular_tree(&root.join(SPECS), 4096)? {
        names.insert(path.strip_prefix(root)?.to_str().ok_or("non-UTF8 measured source path")?.to_owned());
    }
    names.extend(
        [
            "truth.json",
            "oracle.json",
            "provenance.json",
            "provenance-attempt-p2-cyz3gb1h.json",
            "provenance-historical-original.json",
            "provenance-historical-attempt-jk6eeb8n.json",
            "provenance-historical-attempt-llzq0p41.json",
            "msp430.bin",
            "msp430.asm",
            "avr8.bin",
            "avr8.asm",
            "6502.bin",
            "6502.asm",
        ]
        .map(|name| format!("{FIXTURES}/{name}")),
    );
    names.extend(
        [
            "tools/sleigh-fixture/SleighOracle.java",
            "tools/sleigh-fixture/run_oracle.py",
            "tools/sleigh-fixture/test_run_oracle.py",
        ]
        .map(str::to_owned),
    );
    if names.len() > 10_000 {
        return Err("source inventory exceeds 10000 files".into());
    }
    let mut total = 0_usize;
    let mut sources = Vec::new();
    for name in names {
        if !Path::new(&name).components().all(|part| matches!(part, Component::Normal(_))) {
            return Err("source inventory path is not repository-relative".into());
        }
        let path = root.join(&name);
        if fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err("source inventory symlink refused".into());
        }
        let bytes = read(&path, MAX_FILE)?;
        total += bytes.len();
        if total > 512 * 1024 * 1024 {
            return Err("source inventory exceeds 512 MiB".into());
        }
        sources.push(json!({"path":name,"bytes":bytes.len(),"sha256":digest(&bytes)}));
    }
    Ok(json!({"sources":sources,"total_bytes":total}))
}

fn bundle_manifest(root: &Path) -> Result<Value> {
    let specs = root.join(SPECS);
    let paths = regular_tree(&specs, 4096)?;
    if paths.len() > 512 {
        return Err("specification file count exceeds native proof bound".into());
    }
    let mut hash = Sha256::new();
    let mut total = 0_usize;
    let mut files = Vec::new();
    for path in paths {
        let relative = path.strip_prefix(&specs)?.to_str().ok_or("non-UTF8 specification path")?;
        let bytes = read(&path, MAX_FILE)?;
        total += bytes.len();
        if total > 64 * 1024 * 1024 {
            return Err("specification bytes exceed native proof bound".into());
        }
        hash.update((relative.len() as u64).to_le_bytes());
        hash.update(relative.as_bytes());
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(&bytes);
        files.push(json!({"path":relative,"bytes":bytes.len(),"sha256":digest(&bytes)}));
    }
    Ok(json!({"manifest_sha256":rampage_arch::hex::bytes(&hash.finalize()),"files":files,"total_bytes":total}))
}

fn native_context(expected_manifest: &Value, after_native_calls: bool) -> Result<Value> {
    let context =
        if after_native_calls { require_verified_bundled_native_context()? } else { verify_bundled_specifications()? };
    let identity = rampage_arch::hex::bytes(&context.manifest_sha256());
    if identity != expected_manifest["manifest_sha256"] {
        return Err(
            "collector embedded SDK specification identity differs from the frozen published source tree".into()
        );
    }
    Ok(json!({"bundle_id":context.bundle_id(),"home":context.home(),"manifest_sha256":identity,
        "full_closed_tree_verified":true,"cached_native_context_verified":after_native_calls,
        "identity_not_source_authentication":true}))
}

fn merged(mut ranges: Vec<(u64, u64)>) -> Result<Vec<(u64, u64)>> {
    ranges.sort_unstable();
    let mut result: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        if start >= end {
            return Err("empty or reversed function extent".into());
        }
        if let Some(previous) = result.last_mut().filter(|previous| start <= previous.1) {
            previous.1 = previous.1.max(end);
        } else {
            result.push((start, end));
        }
    }
    Ok(result)
}

fn manual_functions(fixture: &Value) -> Result<Functions> {
    let base = number(&fixture["base_byte_offset"])?;
    let mut functions = Functions::new();
    for function in array(fixture, "functions")? {
        let entry = base + number(&function["entry_offset_bytes"])?;
        let end = base + number(&function["extent_end_exclusive_bytes"])?;
        if functions.insert(entry, vec![(entry, end)]).is_some() {
            return Err("duplicate manual function".into());
        }
    }
    Ok(functions)
}

fn oracle_functions(fixture: &Value) -> Result<Functions> {
    let mut functions = Functions::new();
    for function in array(&fixture["program_oracle"], "functions")? {
        let entry = number(&function["entry"]["getOffset_bytes"])?;
        let ranges = array(function, "body_ranges")?
            .iter()
            .map(|range| {
                Ok((
                    number(&range["start"]["getOffset_bytes"])?,
                    number(&range["end_inclusive"]["getOffset_bytes"])?.checked_add(1).ok_or("oracle end overflow")?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        if functions.insert(entry, merged(ranges)?).is_some() {
            return Err("duplicate Java oracle function".into());
        }
    }
    Ok(functions)
}

fn discovered_functions(program: &Value) -> Result<Functions> {
    let mut functions = Functions::new();
    for function in array(program, "functions")? {
        let ranges = array(function, "blocks")?
            .iter()
            .map(|block| Ok((number(&block["start"])?, number(&block["end"])?)))
            .collect::<Result<Vec<_>>>()?;
        if functions.insert(number(&function["address"])?, merged(ranges)?).is_some() {
            return Err("duplicate discovered function".into());
        }
    }
    Ok(functions)
}

fn find_fixture<'a>(document: &'a Value, name: &str) -> Result<&'a Value> {
    array(document, "fixtures")?
        .iter()
        .find(|fixture| fixture["name"] == name)
        .ok_or_else(|| format!("fixed fixture {name} missing").into())
}

fn verify_gold(root: &Path) -> Result<Value> {
    let directory = root.join(FIXTURES);
    let truth = json_file(&directory.join("truth.json"))?;
    let oracle = json_file(&directory.join("oracle.json"))?;
    let provenance = json_file(&directory.join("provenance.json"))?;
    let oracle_hash = digest(&read(&directory.join("oracle.json"), MAX_FILE)?);
    if provenance["frozen_oracle_sha256"] != oracle_hash || provenance["current_receipt"]["status"] != "success" {
        return Err("oracle provenance index does not bind a successful current receipt".into());
    }
    let receipt_name = provenance["current_receipt"]["path"].as_str().ok_or("current oracle receipt name missing")?;
    if Path::new(receipt_name).components().count() != 1
        || !Path::new(receipt_name).components().all(|part| matches!(part, Component::Normal(_)))
    {
        return Err("oracle receipt path is not a fixed sibling".into());
    }
    let receipt_bytes = read(&directory.join(receipt_name), MAX_FILE)?;
    if digest(&receipt_bytes) != provenance["current_receipt"]["sha256"] {
        return Err("oracle receipt hash mismatch".into());
    }
    let receipt: Value = serde_json::from_slice(&receipt_bytes)?;
    let java = array(&receipt, "commands")?
        .iter()
        .find(|command| command["name"] == "oracle")
        .ok_or("current Java oracle command receipt missing")?;
    if java["exit_code"] != 0
        || java["compiled_classes_unchanged"] != true
        || java["compiled_classes_before_launch"] != java["compiled_classes_after_execution"]
    {
        return Err("current independent oracle lacks its compiled-class before/after binding".into());
    }
    let mut fixtures = Vec::new();
    for (name, profile) in PILOTS {
        let manual = find_fixture(&truth, name)?;
        let java = find_fixture(&oracle, name)?;
        let bytes = read(&directory.join(format!("{name}.bin")), 65536)?;
        if manual["language_id"] != profile
            || java["language_id"] != profile
            || java["input_sha256"] != digest(&bytes)
            || manual["window_length_bytes"] != bytes.len()
            || manual_functions(manual)? != oracle_functions(java)?
            || manual_functions(manual)?.len() != 2
        {
            return Err(format!("{name}: original-byte/manual/Java oracle contract disagrees").into());
        }
        let base = number(&manual["base_byte_offset"])?;
        let call = array(java, "rows")?
            .iter()
            .find(|row| row["fixture_offset_bytes"] == manual["known_call"]["source_offset_bytes"])
            .ok_or("independent Java call row missing")?;
        if call["flow"]["is_call"] != true
            || array(call, "direct_flow_targets")?.len() != 1
            || number(&call["direct_flow_targets"][0]["getOffset_bytes"])?
                != base + number(&manual["known_call"]["target_offset_bytes"])?
            || java["base"]["addressableUnitSize_bytes"] != manual["addressable_unit_bytes"]
        {
            return Err(
                "manual call target or addressable unit disagrees with independent Java byte coordinates".into()
            );
        }
        for row in array(java, "rows")?.iter().filter(|row| row["status"] == "decoded") {
            let offset = number(&row["fixture_offset_bytes"])? as usize;
            let length = number(&row["length_bytes"])? as usize;
            let slice = bytes.get(offset..offset + length).ok_or("Java oracle row extends beyond owned bytes")?;
            if row["bytes_hex"] != rampage_arch::hex::bytes(slice) {
                return Err("Java row bytes disagree with original file".into());
            }
        }
        fixtures.push(json!({"name":name,"profile":profile,"source_sha256":digest(&bytes),
            "expected_functions":manual_functions(manual)?,"manual_and_java_agree":true}));
    }
    let decoded_rows = array(&oracle, "fixtures")?
        .iter()
        .map(|fixture| Ok(array(fixture, "rows")?.iter().filter(|row| row["status"] == "decoded").count()))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<usize>();
    let all_rows = array(&oracle, "fixtures")?
        .iter()
        .map(|fixture| Ok(array(fixture, "rows")?.len()))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<usize>();
    if decoded_rows != 36 || all_rows - decoded_rows != 5 {
        return Err("oracle inventory differs from the fixed 36 decoded rows and five negative cases".into());
    }
    Ok(json!({"manual":truth,"oracle":oracle,"provenance":provenance,"current_receipt_sha256":digest(&receipt_bytes),
        "fixtures":fixtures,"independent_gold_verified_before_mcp":true,"java_executed_by_this_consumer":false,
        "oracle_inventory":{"decoded_rows":decoded_rows,"negative_cases":all_rows-decoded_rows,
            "all_oracle_rows_measured_over_mcp":false},
        "historical_missing_class_bindings_not_retroactively_attested":true}))
}

fn inventory(directory: &Path) -> Result<Value> {
    let mut files = Vec::new();
    for path in regular_tree(directory, 32)? {
        let bytes = read(&path, MAX_FILE)?;
        files.push(json!({"path":path.strip_prefix(directory)?,"bytes":bytes.len(),"sha256":digest(&bytes)}));
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
    async fn open(traces: &Path) -> Result<Self> {
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
        let catalog = timeout(TIMEOUT, client.list_all_tools()).await??;
        let tool =
            catalog.iter().find(|tool| tool.name == "inspect_sleigh").ok_or("actual catalog lacks inspect_sleigh")?;
        write_new(&traces.join("catalog-inspect_sleigh.json"), &serde_json::to_value(tool)?)?;
        let schema = serde_json::to_value(&tool.input_schema)?;
        let properties = schema["properties"].as_object().ok_or("inspect_sleigh schema lacks flattened properties")?;
        for key in [
            "path",
            "profile",
            "offset",
            "length",
            "base_address",
            "discover",
            "seeds",
            "include_pcode",
            "instruction_limit",
            "decode_attempt_limit",
            "handle_open_limit",
            "listing_limit",
        ] {
            if !properties.contains_key(key) {
                return Err(format!("actual file-tool schema lacks {key}").into());
            }
        }
        if ["arch", "image_offset", "image_length", "spec_path", "compiler_spec"]
            .iter()
            .any(|key| properties.contains_key(*key))
        {
            return Err("file tool unexpectedly advertises native-image/ABI/spec-path selectors".into());
        }
        for (_, profile) in PILOTS {
            if !array(&properties["profile"], "enum")?.contains(&json!(profile)) {
                return Err("fixed pilot profile absent from actual catalog".into());
            }
        }
        Ok(Self { client, server })
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
        fixtures: &Path,
        label: &str,
        input: Value,
        expected_error: bool,
    ) -> Result<Value> {
        let before = inventory(fixtures)?;
        let index = self.calls.len();
        write_new(
            &self.directory.join(format!("request-{index:03}.json")),
            &json!({"name":"inspect_sleigh","label":label,"input":input,"expected_error":expected_error}),
        )?;
        let started = Instant::now();
        let response = timeout(
            TIMEOUT,
            connection.client.call_tool(
                CallToolRequestParams::new("inspect_sleigh")
                    .with_arguments(input.as_object().ok_or("request is not an object")?.clone()),
            ),
        )
        .await;
        let mut receipt = json!({"index":index,"label":label,"name":"inspect_sleigh","input":input,
            "elapsed_us":started.elapsed().as_micros(),"expected_error":expected_error,"files_before":before});
        let body: Result<Value> = match response {
            Err(error) => {
                receipt["error"] = json!(error.to_string());
                Err("MCP request timeout".into())
            }
            Ok(Err(error)) => {
                receipt["error"] = json!(error.to_string());
                Err("MCP transport failure".into())
            }
            Ok(Ok(result)) => {
                let encoded = serde_json::to_vec(&result)?;
                receipt["serialized_response_bytes"] = json!(encoded.len());
                receipt["response_sha256"] = json!(digest(&encoded));
                receipt["result"] = serde_json::to_value(&result)?;
                let text = result.content.first().and_then(|block| block.as_text()).map(|block| &block.text);
                if encoded.len() > 65_536 || text.is_some_and(|text| text.len() > 60_000) {
                    Err("complete MCP response exceeds output bound".into())
                } else if result.content.len() != 1
                    || text.is_none()
                    || (result.is_error == Some(true)) != expected_error
                {
                    Err("MCP disposition/content differs from fixed request contract".into())
                } else if expected_error {
                    Ok(json!({"rejected":true,"reason":text}))
                } else {
                    serde_json::from_str(text.ok_or("MCP text missing")?).map_err(Into::into)
                }
            }
        };
        let after = inventory(fixtures)?;
        let unchanged = before == after;
        receipt["files_after"] = after;
        receipt["fixture_files_unchanged"] = json!(unchanged);
        write_new(&self.directory.join(format!("call-{index:03}.json")), &receipt)?;
        self.calls.push(receipt);
        if !unchanged {
            return Err("file tool created an annotation/sidecar or changed fixture/source bytes".into());
        }
        body
    }
}

fn request(path: &Path, profile: &str, offset: u64, length: usize, base: u64, discover: bool) -> Value {
    json!({"path":path,"profile":profile,"offset":offset,"length":length,"base_address":format!("{base:#x}"),
        "discover":discover,"seeds":if discover{json!([format!("{base:#x}")])}else{json!([])},
        "instruction_limit":1000,"decode_attempt_limit":4096,"handle_open_limit":128,"stop_limit":64,
        "listing_offset":0,"listing_limit":1000,"include_pcode":false,"timeout_ms":10000})
}

fn check_source(report: &Value, input: &Value, selected: &[u8]) -> Result<()> {
    let hash = digest(selected);
    if report["source_offset"] != input["offset"]
        || report["source_length"] != selected.len()
        || report["source_range_sha256"] != hash
        || report["source_range_sha256_after"] != hash
        || report["base_address"] != input["base_address"]
        || report["profile"]["language_id"] != input["profile"]
        || report["source_coordinate_space"] != "original_file_byte_offset"
        || report["code_coordinate_space"] != "sleigh_internal_code_space_byte_offset_not_display_word_address"
        || report["end_address_exclusive"] != format!("{:#x}", number(&input["base_address"])? + selected.len() as u64)
        || !report["profile"]["abi"].as_str().is_some_and(|abi| abi.contains("unknown"))
        || !report["profile"]["mapping_validation"].as_str().is_some_and(|mapping| mapping.contains("analyst_asserted"))
        || report["listing_omitted_before"] != 0
        || report["listing_omitted_after"] != 0
        || report["stops_omitted"] != 0
    {
        return Err(
            "source/profile/coordinate/completeness receipt differs from the independently selected bytes".into()
        );
    }
    for row in array(report, "rows")? {
        let offset = number(&row["window_byte_offset"])? as usize;
        let length = number(&row["length"])? as usize;
        if row["address"] != format!("{:#x}", number(&report["base_address"])? + offset as u64)
            || row["source_byte_offset"] != number(&input["offset"])? + offset as u64
            || row["bytes"]
                != rampage_arch::hex::bytes(
                    selected.get(offset..offset + length).ok_or("row extends outside selected source")?,
                )
        {
            return Err("row byte/address/source-offset evidence disagrees with original bytes".into());
        }
    }
    Ok(())
}

async fn workflow(root: &Path, run: &Path, gold: &Value, traces: &mut Traces) -> Result<Value> {
    let fixtures = run.join("fixtures");
    fs::create_dir(&fixtures)?;
    for (name, _) in PILOTS {
        let bytes = read(&root.join(FIXTURES).join(format!("{name}.bin")), 65536)?;
        let mut padded = vec![0xab; 7];
        padded.extend_from_slice(&bytes);
        padded.extend_from_slice(&[0xcd; 3]);
        write_bytes_new(&fixtures.join(format!("{name}.raw")), &padded)?;
    }
    let sibling = fixtures.join("owned-sibling.sla");
    write_bytes_new(&sibling, b"Owned non-SLA sentinel. Never load as a specification.")?;
    let connection = Connection::open(&traces.directory).await?;
    let mut pilots = Vec::new();
    for (name, profile) in PILOTS {
        let manual = find_fixture(&gold["manual"], name)?;
        let oracle = find_fixture(&gold["oracle"], name)?;
        let bytes = read(&root.join(FIXTURES).join(format!("{name}.bin")), 65536)?;
        let base = number(&manual["base_byte_offset"])?;
        let input = request(&fixtures.join(format!("{name}.raw")), profile, 7, bytes.len(), base, true);
        let report = traces.call(&connection, &fixtures, &format!("{name}-call-only"), input.clone(), false).await?;
        check_source(&report, &input, &bytes)?;
        let actual = discovered_functions(&report["program"])?;
        if report["completion"] != "seeded_discovery_finished"
            || actual != manual_functions(manual)?
            || actual != oracle_functions(oracle)?
        {
            return Err(
                format!("{name}: call-only function addresses/extents disagree with manual and Java truth").into()
            );
        }
        let call_target = base + number(&manual["known_call"]["target_offset_bytes"])?;
        if !array(&report["program"], "xrefs")?.iter().any(|row| {
            row["kind"] == "call" && row["from"] == format!("{base:#x}") && row["to"] == format!("{call_target:#x}")
        }) {
            return Err("known direct-call xref missing or uses display-word coordinates".into());
        }
        let first = array(&report, "rows")?.first().ok_or("known call listing row missing")?;
        if first["flow"]["kind"] != "direct_call" || first["flow"]["target"] != call_target {
            return Err("native call row target does not equal the manual/Java internal byte target".into());
        }
        let branch_offset = number(&manual["backward_conditional_branch"]["source_offset_bytes"])?;
        let branch = array(&report, "rows")?
            .iter()
            .find(|row| row["window_byte_offset"] == branch_offset)
            .ok_or("known backward conditional branch missing from discovery observations")?;
        if branch["flow"]["kind"] != "conditional_branch"
            || branch["flow"]["target"] != base + number(&manual["backward_conditional_branch"]["target_offset_bytes"])?
        {
            return Err("backward conditional branch differs from the manual byte target".into());
        }
        for offset in array(manual, "return_offsets_bytes")? {
            if !array(&report, "rows")?
                .iter()
                .any(|row| row["window_byte_offset"] == *offset && row["flow"]["kind"] == "return")
            {
                return Err("known return instruction missing from discovery observations".into());
            }
        }
        for row in array(&report, "rows")? {
            let offset = number(&row["window_byte_offset"])?;
            let oracle_row = array(oracle, "rows")?
                .iter()
                .find(|candidate| candidate["fixture_offset_bytes"] == offset)
                .ok_or("discovered row has no frozen Java counterpart")?;
            if row["status"] != "valid"
                || oracle_row["status"] != "decoded"
                || row["length"] != oracle_row["length_bytes"]
                || row["bytes"] != oracle_row["bytes_hex"]
            {
                return Err("call-only row differs from Java length/byte evidence".into());
            }
        }
        let code = array(&report["profile"], "spaces")?
            .iter()
            .find(|space| space["id"] == report["profile"]["code_space"])
            .ok_or("code-space metadata missing")?;
        if code["word_size"] != manual["addressable_unit_bytes"] {
            return Err("code-space addressable unit mismatch".into());
        }
        pilots.push(json!({"name":name,"functions":actual,"expected_functions":manual_functions(manual)?,
            "manual_and_java_extents_match":true,"request":input,"report":report}));
    }
    let avr = read(&root.join(FIXTURES).join("avr8.bin"), 65536)?;
    let mut cpse_input = request(&fixtures.join("avr8.raw"), "avr8:LE:16:default", 29, 4, 0x216, true);
    cpse_input["include_pcode"] = json!(true);
    let cpse = traces.call(&connection, &fixtures, "avr-cpse-valid-unknown", cpse_input.clone(), false).await?;
    check_source(&cpse, &cpse_input, &avr[22..26])?;
    let row = array(&cpse, "rows")?.first().ok_or("CPSE row missing")?;
    if row["status"] != "valid"
        || row["flow"]["kind"] != "unknown"
        || row["context_mediated_flow"] != true
        || row["unknown_gate"]["reason"] != "context_mediated_flow"
        || row["unknown_gate"]["address"] != 0x216
        || row["unknown_gate"]["profile"] != "avr8:LE:16:default"
        || !row["mnemonic"].as_str().is_some_and(|mnemonic| mnemonic.eq_ignore_ascii_case("cpse"))
        || !array(&cpse["program"], "functions")?.is_empty()
        || !array(&cpse, "stops")?.iter().any(|stop| stop["reason"] == "conservative_unknown_flow_not_invalid_opcode")
    {
        return Err("CPSE was not retained as a valid context-mediated conservative unknown gate".into());
    }
    let mut des_input = request(&fixtures.join("avr8.raw"), "avr8:LE:16:default", 33, 2, 0x21a, true);
    des_input["include_pcode"] = json!(true);
    let des = traces.call(&connection, &fixtures, "avr-des-local-pcode-branch", des_input.clone(), false).await?;
    check_source(&des, &des_input, &avr[26..28])?;
    let row = array(&des, "rows")?.first().ok_or("DES row missing")?;
    let constants: BTreeSet<_> = array(&des["profile"], "spaces")?
        .iter()
        .filter(|space| space["kind"] == 0)
        .map(|space| number(&space["id"]))
        .collect::<Result<_>>()?;
    let local_branches: Vec<_> =
        array(row, "pcode")?.iter().filter(|op| op["name"] == "BRANCH" || op["name"] == "CBRANCH").collect();
    let local_offsets: BTreeSet<_> =
        local_branches.iter().map(|op| number(&op["inputs"][0]["offset"])).collect::<Result<_>>()?;
    let avr_oracle = find_fixture(&gold["oracle"], "avr8")?;
    let java_des = array(avr_oracle, "rows")?
        .iter()
        .find(|row| row["fixture_offset_bytes"] == 26)
        .ok_or("frozen Java DES row missing")?;
    let java_local_offsets: BTreeSet<_> = array(java_des, "raw_pcode")?
        .iter()
        .filter(|op| op["mnemonic"] == "BRANCH" || op["mnemonic"] == "CBRANCH")
        .map(|op| number(&op["inputs"][0]["address"]["getOffset_raw"]))
        .collect::<Result<_>>()?;
    if row["status"] != "valid"
        || row["flow"]["kind"] != "unknown"
        || row["unknown_gate"]["reason"] != "multiple_exits"
        || row["unknown_gate"]["address"] != 0x21a
        || row["unknown_gate"]["profile"] != "avr8:LE:16:default"
        || row["flow"].get("target").is_some()
        || local_branches.len() != 2
        || local_offsets != java_local_offsets
        || !local_branches
            .iter()
            .all(|op| op["inputs"][0]["space"].as_u64().is_some_and(|space| constants.contains(&space)))
        || !array(&des["program"], "functions")?.is_empty()
    {
        return Err("DES local p-code branches were mistaken for machine targets".into());
    }
    let mut negatives = Vec::new();
    let valid = request(&fixtures.join("6502.raw"), "6502:LE:16:default", 7, 25, 0x8000, true);
    for (label, field, value) in [
        ("wrong-unregistered-profile", "profile", json!("MIPS:BE:32:default")),
        ("sibling-profile-path", "profile", json!(sibling)),
        ("relative-spec-path", "profile", json!("../owned-sibling.sla")),
        ("explicit-spec-path-injection", "spec_path", json!(sibling)),
        ("non-numeric-base", "base_address", json!("main")),
        ("selected-source-range-outside-file", "offset", json!(36)),
    ] {
        let mut input = valid.clone();
        input[field] = value;
        let rejection = traces.call(&connection, &fixtures, label, input, true).await?;
        negatives.push(json!({"name":label,"result":rejection,"no_source_sidecar_or_annotation_writes":true}));
    }
    connection.close().await?;
    Ok(json!({"pilots":pilots,"call_only_function_denominator":6,"exact_entries_and_extents":6,
        "cpse_probe":cpse,"des_probe":des,"negative_requests":negatives,"fixture_files_after":inventory(&fixtures)?,
        "probe_functions_not_added_to_denominator":true}))
}

async fn run() -> Result<bool> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3
        || args[1].is_empty()
        || !args[1].bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("usage: sleigh_window_measurement NEW-RUN-ID BUILD-RECEIPT.json; HOME must be an owned directory under artifact root".into());
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize()?;
    let artifacts = root.join(ARTIFACT_ROOT).canonicalize()?;
    let home = PathBuf::from(std::env::var_os("HOME").ok_or("owned HOME required")?).canonicalize()?;
    if !home.starts_with(&artifacts) || home == artifacts || std::env::var_os("GHIDRA_INSTALL_DIR").is_some() {
        return Err("require a separate owned HOME under artifact root and no external SDK override".into());
    }
    if fs::read_dir(&home)?.next().is_some() {
        return Err("owned HOME must be initially empty; existing caches are not overwritten".into());
    }
    let build_path = Path::new(&args[2]).canonicalize()?;
    if !build_path.starts_with(&artifacts) {
        return Err("build receipt outside owned artifact root".into());
    }
    let build_bytes = read(&build_path, MAX_JSON as u64)?;
    let build: Value = serde_json::from_slice(&build_bytes)?;
    let sources = source_snapshot(&root)?;
    let bundle = bundle_manifest(&root)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let executable_sha = digest(&read(&executable, 256 * 1024 * 1024)?);
    if build["success"] != true
        || build["source_snapshot_before"] != sources
        || build["source_snapshot_after"] != sources
        || build["executable_sha256"] != executable_sha
        || build["specification_manifest_sha256"] != bundle["manifest_sha256"]
        || build["argv"].as_array().is_none_or(Vec::is_empty)
    {
        return Err("build receipt does not bind stable complete sources/specifications and this executable".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&executable)?.permissions().mode() & 0o222 != 0 {
            return Err("collector must be frozen read-only".into());
        }
    }
    let self_bytes = read(&root.join(SELF_SOURCE), MAX_FILE)?;
    if self_bytes != include_bytes!("sleigh_window_measurement.rs") {
        return Err("compiled-in consumer source differs from disk".into());
    }
    let run = artifacts.join(&args[1]);
    fs::create_dir(&run)?;
    let traces_directory = run.join("traces");
    fs::create_dir(&traces_directory)?;
    let before = json!({"argv":args,"consumer_source":{"path":SELF_SOURCE,"sha256":digest(&self_bytes)},
        "executable":{"path":executable,"sha256":executable_sha,"mode":"0555"},
        "build_receipt":{"path":build_path,"sha256":digest(&build_bytes),"argv":build["argv"]},
        "source_snapshot":sources,"specification_manifest":bundle,"owned_home":home,
        "git_head":git(&root,&["rev-parse","HEAD"])?.trim(),
        "git_status":git(&root,&["status","--porcelain=v1","--untracked-files=all"])?,
        "started_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()});
    write_new(&run.join("before.json"), &before)?;
    let gold = verify_gold(&root)?;
    write_new(&run.join("independent-gold.json"), &gold)?;
    let context_before = native_context(&bundle, false)?;
    write_new(&run.join("specification-context-before.json"), &context_before)?;
    let mut traces = Traces { directory: traces_directory, calls: Vec::new() };
    let result = timeout(Duration::from_secs(240), workflow(&root, &run, &gold, &mut traces))
        .await
        .unwrap_or_else(|_| Err("whole finite Sleigh workflow exceeded 240 seconds".into()));
    let sources_unchanged = source_snapshot(&root)? == sources;
    let context_after = native_context(&bundle, true)?;
    let bundle_unchanged = bundle_manifest(&root)? == bundle
        && ["bundle_id", "home", "manifest_sha256"].iter().all(|key| context_before[*key] == context_after[*key]);
    write_new(&run.join("specification-context-after.json"), &context_after)?;
    let executable_unchanged = digest(&read(&executable, 256 * 1024 * 1024)?) == executable_sha;
    let complete = result.is_ok() && sources_unchanged && bundle_unchanged && executable_unchanged;
    let report = json!({"schema_version":1,"scope":"owned_three_pilot_real_mcp_sleigh_windows",
        "complete":complete,"provenance":before,"workflow":result.as_ref().ok(),
        "error":result.err().map(|error|error.to_string()),"calls":traces.calls,
        "sources_unchanged":sources_unchanged,"bundle_unchanged":bundle_unchanged,"executable_unchanged":executable_unchanged,
        "provider_tokens":null,"provider_calls":0,"target_executed":false,"java_executed":false,
        "abi_proved":false,"c_decompilation_supported":false,"ordinary_project_fallback_claimed":false,
        "sixteen_processor_roster_complete":false,"phase2_fuzzy_quality_gate_changed":false,
        "sanitizer_scope_claim":"Prior parent evidence only: context-only ASAN, not full sanitizer coverage",
        "prior_parent_evidence":{"bridge_p1_source_review":"reported_pass","full_bridge_tests_reported":120,
            "asan_scope":"context_only","sanitizers_run_by_this_consumer":false,
            "unit_test_counts_are_not_this_measurement":true},
        "limitations":["Three fixed pilot languages and six manual functions only; seeded windows do not prove complete discovery.",
            "Oracle records are independent prior Java observations; no SDK/JDK rerun or target execution occurs here.",
            "CPSE remains a valid context-dependent unknown; DES constant-space branches remain local p-code indices.",
            "All addresses, seeds and extents are internal byte coordinates, including word-addressed AVR.",
            "No C ABI, C decompilation, all-roster support, token improvement or Phase 2 quality promotion."]});
    write_new(&run.join("report.json"), &report)?;
    println!(
        "{}",
        json!({"complete":complete,"report":run.join("report.json"),"error":report["error"],
        "report_sha256":digest(&read(&run.join("report.json"),MAX_JSON as u64)?)})
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
            eprintln!("Sleigh window measurement incomplete: {error}");
            std::process::exit(2);
        }
    }
}
