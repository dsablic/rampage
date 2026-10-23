use rampage_arch::Arch;
use rampage_decompiler::{Decompiler, Segment};

fn open_spec() -> Result<Decompiler, rampage_decompiler::Error> {
    Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x1000, bytes: &[0xc3], writable: false }])
}

#[test]
fn corrupt_spec_initialization_returns_an_error_without_aborting() {
    if std::env::var_os("RAMPAGE_SPEC_TEST_CHILD").is_some() {
        assert!(open_spec().is_err());
        return;
    }
    run_spec_test("corrupt_spec_initialization_returns_an_error_without_aborting", |target| {
        std::fs::write(target.join("x86-64.sla"), b"invalid compiled specification")
    });
}

#[test]
fn incompatible_external_data_organization_returns_an_error_without_aborting() {
    if std::env::var_os("RAMPAGE_SPEC_TEST_CHILD").is_some() {
        let Err(error) = open_spec() else { panic!("incompatible C data organization was accepted") };
        assert!(error.to_string().contains("incompatible C data organization"), "{error}");
        return;
    }
    run_spec_test("incompatible_external_data_organization_returns_an_error_without_aborting", |target| {
        let path = target.join("x86-64-gcc.cspec");
        let original = std::fs::read_to_string(&path)?;
        let modified = original.replace("<long_size value=\"8\" />", "<long_size value=\"4\" />");
        assert_ne!(modified, original);
        std::fs::write(path, modified)
    });
}

#[test]
fn external_widths_cannot_wrap_into_an_accepted_data_model() {
    if std::env::var_os("RAMPAGE_SPEC_TEST_CHILD").is_some() {
        let Err(error) = open_spec() else { panic!("oversized width was narrowed before validation") };
        assert!(error.to_string().contains("invalid compiler data widths"), "{error}");
        return;
    }
    run_spec_test("external_widths_cannot_wrap_into_an_accepted_data_model", |target| {
        let path = target.join("x86-64-gcc.cspec");
        let original = std::fs::read_to_string(&path)?;
        let modified = original.replace("<long_size value=\"8\" />", "<long_size value=\"264\" />");
        assert_ne!(modified, original);
        std::fs::write(path, modified)
    });
}

fn run_spec_test(name: &str, modify: impl FnOnce(&std::path::Path) -> std::io::Result<()>) {
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
        for name in ["x86.ldefs", "x86-64.pspec", "x86-64-gcc.cspec", "x86-64.sla"] {
            std::fs::copy(source.join(name), target.join(name))?;
        }
        modify(&target)?;
        // Test names are module paths without the crate name.
        let test = module_path!().split_once("::").map_or(name.to_owned(), |(_, module)| format!("{module}::{name}"));
        std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", &test, "--nocapture"])
            .env("GHIDRA_INSTALL_DIR", &directory)
            .env("RAMPAGE_SPEC_TEST_CHILD", "1")
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
