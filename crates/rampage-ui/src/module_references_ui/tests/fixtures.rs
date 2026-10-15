use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::{ModuleReferenceInput, Project};
use rampage_loaders::Binary;

pub(super) struct ExportSource(PathBuf);

impl ExportSource {
    pub(super) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "module-reference-export-ui-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(directory.join("renamed.bin"), export_bytes()).unwrap();
        Self(directory)
    }

    pub(super) fn input(&self) -> ModuleReferenceInput {
        ModuleReferenceInput {
            module_id: "producer".into(),
            project: Arc::new(Project::new(Binary::open(self.0.join("renamed.bin")).unwrap())),
        }
    }
}

impl Drop for ExportSource {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn export_bytes() -> Vec<u8> {
    let mut bytes = vec![0; 0x2400];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    for (at, value) in [(0x84, 0x8664u16), (0x86, 2), (0x94, 0xf0), (0x96, 0x2022), (0x98, 0x20b), (0xdc, 3)] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0xb0..0xb8].copy_from_slice(&0x180000000u64.to_le_bytes());
    for (at, value) in [
        (0x3c, 0x80u32),
        (0xa8, 0x3000),
        (0xb8, 0x1000),
        (0xbc, 0x200),
        (0xd0, 0x4000),
        (0xd4, 0x200),
        (0x104, 16),
        (0x108, 0x1500),
        (0x10c, 0x100),
        (0x190, 0x2000),
        (0x194, 0x1000),
        (0x198, 0x2000),
        (0x19c, 0x200),
        (0x1ac, 0x40000040),
        (0x1b8, 0x200),
        (0x1bc, 0x3000),
        (0x1c0, 0x200),
        (0x1c4, 0x2200),
        (0x1d4, 0x60000020),
        (0x70c, 0x1600),
        (0x710, 1),
        (0x714, 2),
        (0x718, 2),
        (0x71c, 0x1680),
        (0x720, 0x16a0),
        (0x724, 0x16c0),
        (0x880, 0x3000),
        (0x884, 0x3001),
        (0x8a0, 0x1700),
        (0x8a4, 0x1710),
    ] {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x188..0x18e].copy_from_slice(b".rdata");
    bytes[0x1b0..0x1b5].copy_from_slice(b".text");
    bytes[0x800..0x80d].copy_from_slice(b"producer.dll\0");
    bytes[0x8c2..0x8c4].copy_from_slice(&1u16.to_le_bytes());
    bytes[0x900..0x906].copy_from_slice(b"alpha\0");
    bytes[0x910..0x915].copy_from_slice(b"beta\0");
    bytes
}
