use rampage_arch::Arch;
use rampage_decompiler::{Decompiler, Segment};

#[test]
fn branches_can_reach_mapped_code_before_the_requested_entry() {
    let cases: &[(Arch, &[u8], &[u8])] = &[
        (Arch::X86_64, &[0xb8, 7, 0, 0, 0, 0xc3], &[0xe9, 0xfb, 0xef, 0xff, 0xff]),
        (Arch::Aarch64, &[0xe0, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6], &[0x00, 0xfc, 0xff, 0x17]),
    ];
    for &(arch, body, branch) in cases {
        let segments = [
            Segment { base: 0x1000, bytes: body, writable: false },
            Segment { base: 0x2000, bytes: branch, writable: false },
        ];
        let mut decompiler = Decompiler::open(arch, false, &segments).unwrap();
        let code = decompiler.decompile(0x2000, "later_entry", false).unwrap();
        assert!(code.contains("return 7;"), "{arch:?}: {code}");
    }
}

#[test]
fn mixed_arm_thumb_functions_do_not_depend_on_query_order() {
    let thumb = [0x07, 0x20, 0x70, 0x47];
    let arm = [0x05, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];
    let segments = [
        Segment { base: 0x1000, bytes: &thumb, writable: false },
        Segment { base: 0x1010, bytes: &arm, writable: false },
    ];
    for order in [[true, false, true, false], [false, true, false, true]] {
        let mut decompiler = Decompiler::open(Arch::Arm, false, &segments).unwrap();
        for thumb in order {
            let (address, name, expected) =
                if thumb { (0x1000, "thumb_fn", "return 7;") } else { (0x1010, "arm_fn", "return 5;") };
            let code = decompiler.decompile(address, name, thumb).unwrap();
            assert!(code.contains(expected), "{code}");
        }
    }
}

#[test]
fn same_language_handles_keep_their_own_images_and_context() {
    let one = [0xb8, 1, 0, 0, 0, 0xc3];
    let two = [0xb8, 2, 0, 0, 0, 0xc3];
    let mut first =
        Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x1000, bytes: &one, writable: false }]).unwrap();
    let mut second =
        Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x1000, bytes: &two, writable: false }]).unwrap();
    for _ in 0..3 {
        let code = first.decompile(0x1000, "one", false).unwrap();
        assert!(code.contains("return 1;"), "{code}");
        let code = second.decompile(0x1000, "two", false).unwrap();
        assert!(code.contains("return 2;"), "{code}");
    }
    drop(second);
    assert!(first.decompile(0x1000, "one", false).unwrap().contains("return 1;"));
}

#[test]
fn mode_changes_invalidate_decoded_instructions_after_a_failed_request() {
    let bytes = [1, 0x20, 0x70, 0x47];
    let mut decompiler =
        Decompiler::open(Arch::Arm, false, &[Segment { base: 0x1000, bytes: &bytes, writable: false }]).unwrap();
    assert!(decompiler.decompile(0x1000, "fixture", false).is_err());
    let code = decompiler.decompile(0x1000, "fixture", true).unwrap();
    assert!(code.contains("return 1;"), "{code}");
    assert!(decompiler.decompile(0x1000, "fixture", false).is_err());
}

#[test]
fn explicit_context_points_support_arm_to_thumb_calls() {
    let arm = [0x04, 0xe0, 0x2d, 0xe5, 0x02, 0, 0, 0xfa, 0x04, 0xf0, 0x9d, 0xe4];
    let thumb = [0x07, 0x20, 0x70, 0x47];
    let mut decompiler = Decompiler::open(
        Arch::Arm,
        false,
        &[
            Segment { base: 0x1000, bytes: &arm, writable: false },
            Segment { base: 0x1014, bytes: &thumb, writable: false },
        ],
    )
    .unwrap();
    decompiler.set_code_modes(&[(0x1000, false), (0x1014, true), (0x1018, false)]).unwrap();
    decompiler.add_symbol(0x1014, "thumb_fn");
    let code = decompiler.decompile(0x1000, "caller", false).unwrap();
    assert!(code.contains("thumb_fn("), "{code}");
    assert!(decompiler.decompile(0x1014, "thumb_fn", true).unwrap().contains("return 7;"));
    decompiler.set_code_modes(&[(0x1018, false), (0x1019, true)]).unwrap();
    for invalid in
        [vec![(0x1000, true), (0x1000, false)], vec![(0x1004, false), (0x1000, true)], vec![(0x1_0000_0000, true)]]
    {
        assert!(decompiler.set_code_modes(&invalid).is_err());
    }
}

#[test]
fn independently_decoded_equal_modes_remain_context_barriers() {
    let mut bytes = vec![0u8; 0x34];
    bytes[..12].copy_from_slice(&[0x04, 0xe0, 0x2d, 0xe5, 1, 0, 0, 0xfa, 4, 0xf0, 0x9d, 0xe4]);
    bytes[0x10..0x12].copy_from_slice(&[0x0e, 0xe0]);
    bytes[0x20..0x28].copy_from_slice(&[5, 0, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1]);
    bytes[0x30..0x34].copy_from_slice(&[7, 0x20, 0x70, 0x47]);
    let mut decompiler =
        Decompiler::open(Arch::Arm, false, &[Segment { base: 0xff0, bytes: &bytes, writable: false }]).unwrap();
    decompiler.set_code_modes(&[(0xff0, false), (0x1000, true), (0x1020, true)]).unwrap();
    for _ in 0..3 {
        assert!(decompiler.decompile(0x1000, "thumb_branch", true).unwrap().contains("return 7;"));
        assert!(decompiler.decompile(0x1010, "unseeded_arm", false).unwrap().contains("return 5;"));
    }
}

fn check_many_mode_points(count: usize) {
    let bytes = [7, 0x20, 0x70, 0x47];
    let mut decompiler =
        Decompiler::open(Arch::Arm, false, &[Segment { base: 0x1000, bytes: &bytes, writable: false }]).unwrap();
    let modes: Vec<_> = (0..count).map(|index| (index as u64 * 2, true)).collect();
    decompiler.set_code_modes(&modes).unwrap();
    assert!(decompiler.decompile(0x1000, "fixture", true).unwrap().contains("return 7;"));
}

#[test]
fn mode_context_is_installed_across_multiple_bounded_batches() {
    check_many_mode_points(8193);
    let branch = [2, 0xf0, 0xfe, 0xbf];
    let callee = [7, 0x20, 0x70, 0x47];
    let mut decompiler = Decompiler::open(
        Arch::Arm,
        false,
        &[
            Segment { base: 0x1000, bytes: &branch, writable: false },
            Segment { base: 0x4000, bytes: &callee, writable: false },
        ],
    )
    .unwrap();
    let mut modes: Vec<_> = (0..8193).map(|index| (index * 2, false)).collect();
    modes.last_mut().unwrap().1 = true;
    decompiler.set_code_modes(&modes).unwrap();
    let code = decompiler.decompile(0x1000, "branch_to_final_batch", true).unwrap();
    assert!(code.contains("return 7;"), "{code}");
}

#[test]
#[ignore = "million-point context scale gate; run explicitly with --ignored"]
fn large_context_does_not_reject_a_small_function() {
    check_many_mode_points(1_000_001);
}
