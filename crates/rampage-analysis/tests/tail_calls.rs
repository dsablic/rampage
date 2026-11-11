//! Functions a caller's tail call reaches before any direct call to them, on a generated headerless Cortex-M image
//! (`tests/fixtures/firmware/build-tail-calls.sh`): discovery finds exactly the ELF's functions, with no starts at
//! their internal join points, from the raw image and from the stripped ELF alike (which seeds only its entry, so the
//! handler only the vector table names stays unknown there).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rampage_analysis::functions;
use rampage_loaders::{Binary, RawCodeOptions, RawProfile, SymbolKind};

const BASE: u64 = 0x0800_0000;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/firmware").join(name)
}

fn truth(elf: &Path) -> BTreeSet<u64> {
    let elf = Binary::open(elf).unwrap();
    elf.symbols.iter().filter(|symbol| symbol.kind == SymbolKind::Function).map(|symbol| symbol.address & !1).collect()
}

fn vector_table_only(elf: &Path) -> u64 {
    Binary::open(elf).unwrap().symbol_by_name("default_handler").unwrap().address & !1
}

fn starts(binary: &Binary) -> BTreeSet<u64> {
    functions::analyze(binary).unwrap().functions.iter().map(|function| function.address).collect()
}

fn raw_starts(image: &Path) -> BTreeSet<u64> {
    let options = RawCodeOptions {
        profile: RawProfile::CortexM,
        base: BASE,
        entry: None,
        seeds: vec![],
        vector_table: Some(BASE),
        pointer_tables: false,
    };
    starts(&Binary::from_raw_code(std::fs::read(image).unwrap(), options).unwrap())
}

fn report(what: &str, found: &BTreeSet<u64>, truth: &BTreeSet<u64>) -> String {
    let listed = |set: Vec<&u64>| {
        let first: Vec<_> = set.iter().take(10).map(|at| format!("{at:#x}")).collect();
        format!("{} {first:?}", set.len())
    };
    let extra = listed(found.difference(truth).collect());
    let missing = listed(truth.difference(found).collect());
    format!("{what}: {} starts, {} true, extra {extra}, missing {missing}", found.len(), truth.len())
}

#[test]
fn functions_first_reached_by_a_tail_call_are_not_split_at_their_joins() {
    let elf = fixture("tail-calls.elf");
    let mut truth = truth(&elf);
    assert_eq!(truth.len(), 50, "{truth:x?}");
    let raw = raw_starts(&fixture("tail-calls.bin"));
    assert_eq!(raw, truth, "{}", report("raw image", &raw, &truth));
    truth.remove(&vector_table_only(&elf));
    let stripped = starts(&Binary::open(fixture("tail-calls-stripped.elf")).unwrap());
    assert_eq!(stripped, truth, "{}", report("stripped ELF", &stripped, &truth));
}

/// Measures a larger generated image: `RAMPAGE_TAIL_CALLS=<image.bin>:<image.elf>`, the ELF built with symbols and
/// its stripped copy beside it as `<image>-stripped.elf`.
#[test]
#[ignore = "measurement on an image built outside the repository"]
fn measure_a_generated_image() {
    let Ok(paths) = std::env::var("RAMPAGE_TAIL_CALLS") else { return };
    let (image, elf) = paths.split_once(':').unwrap();
    let mut truth = truth(Path::new(elf));
    println!("{}", report("raw image", &raw_starts(Path::new(image)), &truth));
    truth.remove(&vector_table_only(Path::new(elf)));
    let stripped = elf.replace(".elf", "-stripped.elf");
    println!("{}", report("stripped ELF", &starts(&Binary::open(stripped).unwrap()), &truth));
}
