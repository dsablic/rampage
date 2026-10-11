use rampage_arch::Arch;
use rampage_decompiler::{Decompiler, MemoryRegion};

fn region(base: u64, bytes: &[u8], executable: bool) -> MemoryRegion<'_> {
    MemoryRegion { base, bytes, size: bytes.len() as u64, readable: true, writable: false, executable }
}

fn decompile(regions: &[MemoryRegion], address: u64) -> Result<String, rampage_decompiler::Error> {
    Decompiler::open_regions(Arch::X86_64, false, regions)?.decompile(address, "fixture", false)
}

#[test]
fn instruction_lookahead_never_supplies_missing_instruction_bytes() {
    let ret = [0xc3];
    let text = decompile(&[region(0x1000, &ret, true)], 0x1000).unwrap();
    assert!(text.contains("return;"), "{text}");
    let jump = [0xeb];
    let missing = decompile(&[region(0x1000, &jump, true), region(0x1002, &ret, true)], 0x1000);
    assert!(missing.is_err(), "{missing:?}");
    let displacement = [0];
    assert!(
        decompile(
            &[region(0x1000, &jump, true), region(0x1001, &displacement, false), region(0x1002, &ret, true)],
            0x1000
        )
        .is_err()
    );
    let text = decompile(&[region(0x1000, &[0xeb, 0], true), region(0x1002, &ret, true)], 0x1000).unwrap();
    assert!(text.contains("return;"), "{text}");
    assert!(decompile(&[region(0x1000, &ret, true)], 0x2000).is_err());
    assert!(decompile(&[region(0x1000, &ret, false)], 0x1000).is_err());
}

#[test]
fn failed_flow_is_cleared_before_retrying_a_function() {
    let bytes = [0xb8, 1, 0, 0, 0];
    let mut decompiler = Decompiler::open_regions(Arch::X86_64, false, &[region(0x1000, &bytes, true)]).unwrap();
    for _ in 0..3 {
        let error = decompiler.decompile(0x1000, "fixture", false).unwrap_err().to_string();
        assert!(error.contains("Unavailable instruction"), "{error}");
        assert!(!error.contains("inlining"), "{error}");
    }
}

fn string_call(bytes: &[u8], size: u64) -> String {
    let text = [0xbf, 0x00, 0x30, 0x00, 0x00, 0xe8, 0xf6, 0x0f, 0x00, 0x00, 0x31, 0xc0, 0xc3];
    let data = MemoryRegion { size, ..region(0x3000, bytes, false) };
    let mut decompiler = Decompiler::open_regions(
        Arch::X86_64,
        false,
        &[region(0x1000, &text, true), region(0x2000, &[0xc3], true), data],
    )
    .unwrap();
    decompiler.add_symbol(0x2000, "puts");
    decompiler.parse_c("extern int4 puts(char *s);").unwrap();
    decompiler.decompile(0x1000, "fixture", false).unwrap()
}

#[test]
fn strings_require_an_available_terminator_even_at_the_end_of_a_mapping() {
    let unterminated = string_call(b"abc", 3);
    assert!(!unterminated.contains("\"abc\""), "{unterminated}");
    let terminated = string_call(b"abc\0", 4);
    assert!(terminated.contains("\"abc\""), "{terminated}");
    let zero_terminated = string_call(b"abc", 4);
    assert!(zero_terminated.contains("\"abc\""), "{zero_terminated}");
}

#[test]
fn declared_zero_fill_is_readable_without_materializing_its_virtual_size() {
    let output = string_call(&[], 1 << 32);
    assert!(output.contains("puts(\"\")"), "{output}");
}

#[test]
fn invalid_and_ambiguous_regions_are_rejected_before_ffi() {
    let bytes = [0xc3];
    for regions in [
        vec![region(0x1000, &bytes, true), region(0x1000, &bytes, false)],
        vec![MemoryRegion { size: 0, ..region(0x1000, &bytes, true) }],
        vec![MemoryRegion { size: 2, ..region(u64::MAX, &bytes, true) }],
    ] {
        assert!(Decompiler::open_regions(Arch::X86_64, false, &regions).is_err());
    }
    assert!(Decompiler::open_regions(Arch::X86_64, false, &[region(u64::MAX, &bytes, true)]).is_ok());
    assert!(Decompiler::open_regions(Arch::X86, false, &[region(u64::from(u32::MAX), &[0xeb, 0], true)]).is_err());
}

fn print_at(address: u64, data: &[MemoryRegion], wide: bool) -> String {
    let mut text = vec![0x48, 0xbf];
    text.extend(address.to_le_bytes());
    text.extend([0xe8, 0xf1, 0x0f, 0, 0, 0x31, 0xc0, 0xc3]);
    let mut regions = vec![region(0x1000, &text, true), region(0x2000, &[0xc3], true)];
    regions.extend(data.iter().map(|entry| MemoryRegion {
        base: entry.base,
        bytes: entry.bytes,
        size: entry.size,
        readable: entry.readable,
        writable: entry.writable,
        executable: entry.executable,
    }));
    let mut decompiler = Decompiler::open_regions(Arch::X86_64, false, &regions).unwrap();
    decompiler.add_symbol(0x2000, "print");
    decompiler.parse_c(if wide { "extern int4 print(wchar2 *s);" } else { "extern int4 print(char *s);" }).unwrap();
    decompiler.decompile(0x1000, "fixture", false).unwrap()
}

#[test]
fn a_string_read_never_wraps_to_a_terminator_at_address_zero() {
    let output = print_at(u64::MAX - 2, &[region(u64::MAX - 2, b"abc", false), region(0, &[0], false)], false);
    assert!(!output.contains("\"abc\""), "{output}");
}

#[test]
fn complete_wide_terminators_survive_incomplete_trailing_characters() {
    for bytes in [&[0x41u8, 0, 0, 0][..], &[0x41, 0, 0, 0, 0x42][..]] {
        let output = print_at(0x3000, &[region(0x3000, bytes, false)], true);
        assert!(output.contains("\"A\""), "{output}");
    }
    let output = print_at(0x3000, &[region(0x3000, &[0x41, 0, 0x42], false)], true);
    assert!(!output.contains("\"A\""), "{output}");
}
