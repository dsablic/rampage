use rampage_arch::Arch;
use rampage_decompiler::{Decompiler, Segment};

#[test]
fn corrupt_spec_initialization_returns_an_error_without_aborting() {
    if std::env::var_os("RAMPAGE_CORRUPT_SPEC_CHILD").is_some() {
        let result =
            Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x1000, bytes: &[0xc3], writable: false }]);
        assert!(result.is_err());
        return;
    }
    let allocation = std::process::Command::new("mktemp")
        .arg("-d")
        .arg(std::env::temp_dir().join("rampage-spec-error.XXXXXX"))
        .output()
        .unwrap();
    assert!(allocation.status.success());
    let directory = std::path::PathBuf::from(std::str::from_utf8(&allocation.stdout).unwrap().trim());
    let result = (|| -> std::io::Result<std::process::Output> {
        let relative = "Ghidra/Processors/x86/data/languages";
        let target = directory.join(relative);
        std::fs::create_dir_all(&target)?;
        let source = rampage_decompiler::sleigh_home().unwrap().join(relative);
        for name in ["x86.ldefs", "x86-64.pspec", "x86-64-gcc.cspec"] {
            std::fs::copy(source.join(name), target.join(name))?;
        }
        std::fs::write(target.join("x86-64.sla"), b"invalid compiled specification")?;
        std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "corrupt_spec_initialization_returns_an_error_without_aborting", "--nocapture"])
            .env("GHIDRA_INSTALL_DIR", &directory)
            .env("RAMPAGE_CORRUPT_SPEC_CHILD", "1")
            .output()
    })();
    std::fs::remove_dir_all(&directory).unwrap();
    let output = result.unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
