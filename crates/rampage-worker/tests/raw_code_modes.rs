//! Code-mode points travel to the worker packed in one string (protocol 15). A large Raw Cortex-M image has
//! hundreds of thousands of them; as one JSON object each they passed the request's 1 M-node bound and every
//! worker decompilation failed. These tests decompile with that many points through the worker and in process and
//! require the same C.

use rampage_api::{DecompilerWorkerConfig, Project, RawProjectRequest, Session};
use rampage_decompiler::worker::{
    PROTOCOL_VERSION, WorkerCodeMode, WorkerConfig, WorkerFunction, WorkerMapping, WorkerOptions, WorkerRequest,
    run_supervised,
};
use rampage_decompiler::{Decompiler, DecompilerOptions, MemoryRegion};

const IMAGE: &[u8] = include_bytes!("../../../tests/fixtures/firmware/raw-cortex-m-decompile.bin");
const BASE: u64 = 0x0800_0000;
const POINTS: u64 = 400_000;

fn worker() -> WorkerConfig {
    WorkerConfig { executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()), ..Default::default() }
}

/// One Thumb point every two bytes from the image base: far more than 333,000, the most the old per-point
/// encoding fitted under the node bound.
fn many_points() -> Vec<(u64, bool)> {
    (0..POINTS).map(|index| (BASE + 2 * index, true)).collect()
}

#[test]
fn the_worker_decompiles_with_400_000_code_mode_points_as_the_engine_does_in_process() {
    let reset = u64::from(u32::from_le_bytes(IMAGE[4..8].try_into().unwrap())) & !1;
    let points = many_points();
    let region = MemoryRegion {
        base: BASE,
        bytes: IMAGE,
        size: IMAGE.len() as u64,
        readable: true,
        writable: false,
        executable: true,
    };
    let mut engine =
        Decompiler::open_with_options(rampage_arch::Arch::Arm, false, &[region], &DecompilerOptions::default())
            .unwrap();
    engine.set_code_modes(&points).unwrap();
    let native = engine.decompile(reset, "reset", true).unwrap();
    let request = WorkerRequest {
        version: PROTOCOL_VERSION,
        arch: rampage_arch::Arch::Arm.to_string(),
        big_endian: false,
        options: WorkerOptions::default(),
        mappings: vec![WorkerMapping {
            base: BASE,
            hex_bytes: IMAGE.iter().map(|byte| format!("{byte:02x}")).collect(),
            size: IMAGE.len() as u64,
            readable: true,
            writable: false,
            executable: true,
        }],
        code_modes: points.iter().map(|&(address, thumb)| WorkerCodeMode { address, thumb }).collect(),
        operations: Vec::new(),
        decompile: WorkerFunction { address: reset, name: "reset".into(), thumb: true },
        tokens: true,
        validate_only: false,
        type_query: None,
    };
    let isolated = run_supervised(&request, &worker(), None).expect("the worker takes 400,000 packed points");
    assert_eq!(isolated.text, native);
    assert!(native.contains("reset"), "{native}");
}

/// The manual check on a large image, which is not a fixture: set `RAMPAGE_TEST_LARGE_RAW` to a Raw Cortex-M
/// image and `RAMPAGE_TEST_LARGE_RAW_REQUEST` to its RawProjectRequest JSON, then run with `--run-ignored all`
/// (in release: discovery of a multi-megabyte image is slow in debug builds). Every tenth function, up to 40,
/// must decompile identically through the worker and in process.
#[test]
#[ignore = "needs a large Raw image named by RAMPAGE_TEST_LARGE_RAW"]
fn a_large_raw_image_decompiles_the_same_through_the_worker_and_in_process() {
    let (Some(path), Some(request)) =
        (std::env::var_os("RAMPAGE_TEST_LARGE_RAW"), std::env::var("RAMPAGE_TEST_LARGE_RAW_REQUEST").ok())
    else {
        return;
    };
    let request: RawProjectRequest = serde_json::from_str(&request).unwrap();
    let open = || -> std::sync::Arc<Project> {
        Session::default().with_analysis_store(None).open_raw(std::path::Path::new(&path), &request).unwrap()
    };
    let in_process = open();
    let isolated = open();
    isolated.set_decompiler_worker(Some(DecompilerWorkerConfig {
        executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()),
        ..Default::default()
    }));
    let functions = in_process
        .functions(&rampage_api::FunctionsQuery { limit: Some(1_000_000), ..Default::default() })
        .unwrap()
        .items;
    let mut compared = 0;
    for row in functions.iter().step_by(10).take(40) {
        let native = in_process.decompile(row.address).map(|result| result.code).map_err(|error| error.to_string());
        let worker = isolated.decompile(row.address).map(|result| result.code).map_err(|error| error.to_string());
        assert_eq!(worker, native, "{:#x}", row.address);
        compared += usize::from(native.is_ok());
    }
    eprintln!("compared {compared} decompilations of {} functions", functions.len());
    assert!(compared > 0);
}
