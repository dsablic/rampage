//! Compiles the vendored Ghidra decompiler library and the C ABI shim into a static library.

use std::fs;
use std::path::PathBuf;

fn main() {
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

    // Bake the path to the vendored SLEIGH specifications, so a source build decompiles with no external Ghidra
    // install. `sleigh_home` prefers this when the directory is present.
    let specs = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR")).join("specs");
    println!("cargo:rustc-env=RAMPAGE_BUNDLED_SPECS={}", specs.display());

    println!("cargo:rerun-if-changed=src/shim.cc");
    println!("cargo:rerun-if-changed=vendor/ghidra");
}
