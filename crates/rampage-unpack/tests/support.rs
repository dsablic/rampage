//! Fixture paths, scratch directories and the expected content of the shared fixture tree.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/fsimages").join(name)
}

pub fn hello_elf() -> Vec<u8> {
    std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-mips.elf")).unwrap()
}

/// A fresh directory under the system temporary directory, removed on drop.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(name: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-unpack-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The regular files every fixture image holds, with their content.
pub fn expected_files() -> Vec<(&'static str, Vec<u8>)> {
    let blocks: String = (0..400).map(|i| format!("line {i:05} of the multi-block file\n")).collect();
    vec![
        ("etc/hostname", b"demo-device\n".to_vec()),
        (
            "etc/device.conf",
            b"telemetry=off\nupload_endpoint=https://telemetry.example.invalid/collect\nmicrophone=push-to-talk\n"
                .to_vec(),
        ),
        ("usr/share/demo/readme.txt", b"An invented filesystem for rampage tests.\n".to_vec()),
        ("usr/share/demo/nested/deep.txt", b"nested file\n".to_vec()),
        ("usr/share/demo/blocks.txt", blocks.into_bytes()),
        ("usr/share/demo/empty", Vec::new()),
        ("bin/hello", hello_elf()),
    ]
}

/// Checks an extraction of the whole fixture tree under `root`.
pub fn check_tree(root: &Path, report: &rampage_unpack::ExtractReport, has_device: bool) {
    for (path, content) in expected_files() {
        assert_eq!(std::fs::read(root.join(path)).unwrap(), content, "{path}");
    }
    assert_eq!(std::fs::read_link(root.join("bin/sh")).unwrap(), Path::new("hello"));
    // The absolute link is rewritten relative to the output root, and resolves inside it.
    assert_eq!(std::fs::read_link(root.join("var/hostname")).unwrap(), Path::new("../etc/hostname"));
    assert_eq!(std::fs::read(root.join("var/hostname")).unwrap(), b"demo-device\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(root.join("bin/hello")).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o755, "no setuid bit is ever written");
    }
    assert!(report.executables.iter().any(|executable| executable.path == "bin/hello" && executable.format == "elf"));
    if has_device {
        assert!(!root.join("dev/console").exists());
        assert!(
            report.skipped.iter().any(|skip| skip.path == "dev/console" && skip.reason.contains("device")),
            "{:?}",
            report.skipped
        );
    }
}
