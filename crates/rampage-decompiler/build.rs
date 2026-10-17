//! Compiles the vendored Ghidra decompiler library and the C ABI shim into a static library.

use std::fs;
use std::path::PathBuf;

fn main() {
    bundle_specs();
    let vendor = PathBuf::from("vendor/ghidra");
    let mut build = cc::Build::new();
    build.cpp(true).std("c++14").include(&vendor).warnings(false);
    // Ghidra's sources assume these are quiet; they are noisy and not actionable for us.
    build.flag_if_supported("-Wno-sign-compare").flag_if_supported("-Wno-register");

    for entry in fs::read_dir(&vendor).expect("vendor/ghidra missing") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_some_and(|ext| ext == "cc") {
            build.file(&path);
        }
    }
    build.file("src/shim.cc");
    build.compile("rampage_ghidra");

    // libz is needed for Ghidra's compressed .sla spec loading.
    println!("cargo:rustc-link-lib=z");

    println!("cargo:rerun-if-changed=src/shim.cc");
    println!("cargo:rerun-if-changed=src/tokens.hh");
    println!("cargo:rerun-if-changed=src/results.hh");
    println!("cargo:rerun-if-changed=src/local_variables.hh");
    println!("cargo:rerun-if-changed=src/type_hints.hh");
    println!("cargo:rerun-if-changed=src/type_library.hh");
    println!("cargo:rerun-if-changed=vendor/ghidra");
}

fn bundle_specs() {
    fn collect(directory: &std::path::Path, paths: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory).expect("specification directory") {
            let path = entry.expect("specification entry").path();
            if path.is_dir() {
                collect(&path, paths);
            } else {
                paths.push(path);
            }
        }
    }
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest directory")).join("specs");
    let mut paths = Vec::new();
    collect(&root, &mut paths);
    paths.sort();
    let mut hash = 0xcbf29ce484222325u64;
    let mut entries = String::new();
    for path in paths {
        let relative = path.strip_prefix(&root).expect("relative specification").to_string_lossy();
        for byte in relative.bytes().chain(fs::read(&path).expect("specification bytes")) {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
        }
        entries.push_str(&format!("({relative:?}, include_bytes!({:?})),\n", path.to_string_lossy()));
    }
    let output = PathBuf::from(std::env::var("OUT_DIR").expect("build output")).join("bundled_specs.rs");
    fs::write(
        output,
        format!(
            "const BUNDLE_ID: &str = \"specs-{hash:016x}\";\nconst BUNDLED_SPECS: &[(&str, &[u8])] = &[\n{entries}];\n"
        ),
    )
    .expect("embed specifications");
    println!("cargo:rerun-if-changed=specs");
}
