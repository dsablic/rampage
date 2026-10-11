use rampage_arch::Arch;
use rampage_decompiler::{Decompiler, DecompilerOptions, MemoryRegion, Platform};
use std::path::PathBuf;
use std::process::Command;

struct FixtureExecutable(PathBuf);

impl Drop for FixtureExecutable {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn darwin_explicit_type_allocator_preserves_stack_slots_aggregates_and_cloned_rules() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let executable = FixtureExecutable(std::env::temp_dir().join(format!("darwin_allocator_{}", std::process::id())));
    let compilation = Command::new("c++")
        .arg("-std=c++14")
        .arg("-I")
        .arg(root.join("vendor/ghidra"))
        .arg(root.join("tests/fixtures/darwin_allocator.cc"))
        .arg(PathBuf::from(env!("OUT_DIR")).join("librampage_ghidra.a"))
        .arg("-lz")
        .arg("-o")
        .arg(&executable.0)
        .output()
        .unwrap();
    assert!(compilation.status.success(), "{}", String::from_utf8_lossy(&compilation.stderr));
    let output = Command::new(&executable.0).arg(root.join("specs")).output().unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn darwin_fixed_narrow_stack_arguments_remain_distinct_named_parameters() {
    let bytes: Vec<_> =
        [0x39c003e0u32, 0x39c007e8, 0x0b080000, 0xd65f03c0].into_iter().flat_map(u32::to_le_bytes).collect();
    let regions = [MemoryRegion {
        base: 0x1000,
        bytes: &bytes,
        size: bytes.len() as u64,
        readable: true,
        writable: false,
        executable: true,
    }];
    let options = DecompilerOptions { platform: Platform::Darwin, ..Default::default() };
    let mut engine = Decompiler::open_with_options(Arch::Aarch64, false, &regions, &options).unwrap();
    assert!(engine.language_id().ends_with(":apple"));
    engine.set_symbol(0x1000, "narrow").unwrap();
    engine
        .apply_prototype(
            0x1000,
            false,
            "int4 narrow(int8 a, int8 b, int8 c, int8 d, int8 e, int8 f, int8 g, int8 h, int1 first, int1 second);",
        )
        .unwrap();
    let code = engine.decompile(0x1000, "narrow", false).unwrap();
    let body = code.split_once('{').unwrap().1;
    assert!(body.contains("first") && body.contains("second") && body.contains('+'), "{code}");
    assert!(!code.contains("local_"), "{code}");
    let result = engine.structured_result().unwrap();
    assert_eq!(result.signature.parameters.len(), 10, "{result:?}");
    for (parameter, (name, offset)) in result.signature.parameters[8..].iter().zip([("first", 0), ("second", 1)]) {
        assert_eq!(parameter.name, name);
        assert_eq!(parameter.data_type.size, 1);
        assert_eq!(parameter.storage.space.as_deref(), Some("stack"));
        assert_eq!(parameter.storage.address, Some(offset));
        assert_eq!(parameter.storage.size, 1);
    }
}
