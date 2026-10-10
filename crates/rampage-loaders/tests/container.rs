use std::path::PathBuf;

use rampage_loaders::{Binary, container};

#[test]
fn bundle_inventory_and_opening_do_not_follow_symlinked_executables() {
    let root = std::env::temp_dir().join(format!("rampage-bundle-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let bundle = root.join("Demo.app");
    let macos = bundle.join("Contents/MacOS");
    std::fs::create_dir_all(&macos).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    std::fs::copy(source, macos.join("Demo")).unwrap();
    std::os::unix::fs::symlink(&root, root.join("loop")).unwrap();
    let binary = Binary::open(&bundle).unwrap();
    assert_eq!(binary.arch, rampage_arch::Arch::X86_64);
    let inventory = container::inventory(&root).unwrap();
    assert_eq!(inventory.binaries.len(), 1);
    std::fs::write(macos.join("helper"), b"not a binary").unwrap();
    assert_eq!(container::resolve_executable(&bundle).unwrap(), macos.join("Demo"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn bundle_plist_is_authoritative_and_external_executable_directories_are_rejected() {
    let root = std::env::temp_dir().join(format!("rampage-bundle-plist-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let bundle = root.join("Renamed.app");
    let contents = bundle.join("Contents");
    let macos = contents.join("MacOS");
    std::fs::create_dir_all(&macos).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    std::fs::copy(source, macos.join("RealMain")).unwrap();
    std::fs::write(macos.join("Renamed"), b"decoy").unwrap();
    std::fs::write(
        contents.join("Info.plist"),
        b"<plist version=\"1.0\"><dict><key>CFBundleExecutable</key><string>RealMain</string></dict></plist>",
    )
    .unwrap();
    assert_eq!(container::resolve_executable(&bundle).unwrap(), macos.join("RealMain"));
    let linked = root.join("Linked.app/Contents");
    std::fs::create_dir_all(&linked).unwrap();
    std::os::unix::fs::symlink(&macos, linked.join("MacOS")).unwrap();
    assert!(container::resolve_executable(&root.join("Linked.app")).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn inventory_entry_limit_is_reported_even_in_a_flat_directory() {
    let root = std::env::temp_dir().join(format!("rampage-inventory-limit-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    for index in 0..20_000 {
        std::fs::write(root.join(index.to_string()), []).unwrap();
    }
    let inventory = container::inventory(&root).unwrap();
    assert!(inventory.warnings.iter().any(|warning| warning.contains("limit")));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn nonregular_plists_are_rejected_without_opening_them() {
    let root = std::env::temp_dir().join(format!("rampage-plist-fifo-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir_all(root.join("Contents/MacOS")).unwrap();
    let status = std::process::Command::new("mkfifo").arg(root.join("Contents/Info.plist")).status().unwrap();
    assert!(status.success());
    assert!(container::resolve_executable(&root).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
