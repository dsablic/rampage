//! Cortex-M Raw callee inference gives the same C in this build's isolated worker, which opens a fresh engine for
//! every request, as in process, where one engine serves many decompilations and resets the inference between them.

use rampage_api::{DecompilerWorkerConfig, Project};
use rampage_loaders::{Binary, RawCodeOptions, RawProfile};

const IMAGE: &[u8] = include_bytes!("../../../tests/fixtures/firmware/raw-cortex-m-decompile.bin");
const ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m-decompile.elf");

fn project() -> Project {
    let options = RawCodeOptions {
        profile: RawProfile::CortexM,
        base: 0x0800_0000,
        entry: None,
        seeds: vec![],
        vector_table: Some(0x0800_0000),
        pointer_tables: false,
    };
    Project::new(Binary::from_raw_code(IMAGE.to_vec(), options).unwrap())
}

#[test]
fn raw_firmware_decompiles_the_same_in_process_and_isolated() {
    let elf = Binary::open(ELF).unwrap();
    let address = |name: &str| elf.symbol_by_name(name).unwrap().address & !1;
    let in_process = project();
    let isolated = project();
    isolated.set_decompiler_worker(Some(DecompilerWorkerConfig {
        executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()),
        ..Default::default()
    }));
    // In process, chain_head comes after decompilations that derive most of its chain; the worker starts fresh.
    for name in
        ["chain30", "reset_handler", "verify_image", "checksum_after_quiet", "syscall_ret", "chain_head", "chain0"]
    {
        let native = in_process.decompile(address(name)).unwrap();
        let worker = isolated.decompile(address(name)).unwrap();
        assert_eq!(worker.code, native.code, "{name}");
    }
}
