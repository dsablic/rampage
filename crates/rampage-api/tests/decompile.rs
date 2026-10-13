use rampage_api::Project;
use rampage_loaders::Binary;

#[test]
fn decompilation_reuses_discovered_thumb_context_without_loader_thumb_metadata() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm-mixed-modes.snapshot.json");
    let binary = Binary::open(path).unwrap();
    assert!(binary.thumb.is_empty());
    let project = Project::new(binary);
    for order in [[0x1014, 0x1020, 0x1000], [0x1000, 0x1020, 0x1014]] {
        for address in order {
            let output = project.decompile(address).unwrap();
            if address == 0x1014 {
                assert!(output.code.contains("return 7;"), "{}", output.code);
            }
            if address == 0x1020 {
                assert!(output.code.contains("return 5;"), "{}", output.code);
            }
            if address == 0x1000 {
                assert!(output.code.contains("sub_1014("), "{}", output.code);
            }
        }
    }
}

fn fixture(name: &str) -> Project {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data").join(name);
    Project::new(Binary::open(path).unwrap())
}

#[test]
fn querying_unseeded_arm_code_does_not_change_a_known_thumb_continuation() {
    let project = fixture("runtime-arm-context-barriers.snapshot.json");
    for _ in 0..3 {
        let thumb = project.decompile(0x1000).unwrap();
        assert!(thumb.code.contains("return 7;"), "{}", thumb.code);
        let arm = project.decompile(0x1010).unwrap();
        assert!(arm.code.contains("return 5;"), "{}", arm.code);
    }
}

#[test]
fn thumb_context_accepts_padding_boundaries_and_exclusive_32_bit_ends() {
    for (name, address) in
        [("runtime-thumb-odd-end.snapshot.json", 0x1000), ("runtime-thumb-top-address.snapshot.json", 0xffff_fffc)]
    {
        let output = fixture(name).decompile(address).unwrap();
        assert!(output.code.contains("return 7;"), "{}", output.code);
    }
}

/// The decompiler stops at calls to listed (`exit`, `abort`) and inferred (`sub_1400017c0`, which ends in
/// `__fastfail`) noreturn callees, as discovery does, instead of running on into the code after them.
#[test]
fn calls_that_never_return_end_decompiled_control_flow() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.exe");
    let project = Project::new(Binary::open(path).unwrap());
    let code = project.decompile(0x1400013f7).unwrap().code;
    let lines: Vec<_> = code.lines().map(str::trim).collect();
    for call in ["exit(", "abort(", "sub_1400017c0(8)"] {
        let at = lines.iter().position(|line| line.starts_with(call)).unwrap_or_else(|| panic!("{call}: {code}"));
        assert!(lines[at - 1].contains("Subroutine does not return"), "{call}: {code}");
    }
}
