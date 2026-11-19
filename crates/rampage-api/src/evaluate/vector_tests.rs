//! Vector processor operations: unit vectors by Intel's definitions, and the evaluate-simd fixture's functions
//! against scalar references of their intrinsics.

use serde_json::json;

use super::tests::{fixture_api, returned, run};
use super::userops::{Operand, known, run as compute};

fn register(bytes: &[u8]) -> Operand {
    Operand { bytes: bytes.to_vec(), constant: false }
}

fn immediate(value: u8) -> Operand {
    Operand { bytes: vec![value], constant: true }
}

fn op(name: &str, operands: &[Operand], out: usize) -> Vec<u8> {
    compute(name, operands, out).unwrap_or_else(|| panic!("{name} unknown")).unwrap()
}

fn words(values: &[u16]) -> Vec<u8> {
    values.iter().flat_map(|value| value.to_le_bytes()).collect()
}

fn dwords(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|value| value.to_le_bytes()).collect()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
}

#[test]
fn byte_shuffles_and_masks() {
    let bytes: Vec<u8> = (0x10..0x20).collect();
    let control = hex("0f0e0d0c80818283000102030405ff07");
    // Legacy form: the destination is shuffled by the source.
    assert_eq!(op("pshufb", &[register(&bytes), register(&control)], 16), hex("1f1e1d1c000000001011121314150017"));
    // AVX2: each 128-bit lane shuffles within itself.
    let wide: Vec<u8> = (0..32).collect();
    let control: Vec<u8> = [0u8, 15].repeat(16);
    let shuffled = op("vpshufb_avx2", &[register(&wide), register(&control)], 32);
    assert_eq!(&shuffled[..4], [0, 15, 0, 15]);
    assert_eq!(&shuffled[16..20], [16, 31, 16, 31]);
    let signs = hex("80000000ff7f000001000080ffffffff");
    assert_eq!(op("pmovmskb", &[register(&signs)], 4), 0xf811u32.to_le_bytes());
    assert_eq!(op("movmskps", &[register(&[0; 4]), register(&signs)], 4), [0b1100, 0, 0, 0]);
    assert_eq!(op("movmskpd", &[register(&[0; 4]), register(&signs)], 4), [0b10, 0, 0, 0]);
    assert!(known("vpshufb_avx") && known("pmovzxbd") && !known("vpermb_avx512_vbmi") && !known("syscall"));
}

#[test]
fn word_and_dword_shuffles() {
    let source = words(&[0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(
        op("pshuflw", &[register(&[0; 16]), register(&source), immediate(0x1b)], 16),
        words(&[3, 2, 1, 0, 4, 5, 6, 7])
    );
    assert_eq!(
        op("pshufhw", &[register(&[0; 16]), register(&source), immediate(0x1b)], 16),
        words(&[0, 1, 2, 3, 7, 6, 5, 4])
    );
    let source = dwords(&[10, 11, 12, 13]);
    assert_eq!(op("vpshufd_avx", &[register(&source), immediate(0x4e)], 16), dwords(&[12, 13, 10, 11]));
    let other = dwords(&[20, 21, 22, 23]);
    assert_eq!(
        op("shufps", &[register(&source), register(&other), immediate(0b11_10_01_00)], 16),
        dwords(&[10, 11, 22, 23])
    );
    assert_eq!(
        op("palignr", &[register(&source), register(&other), immediate(4)], 16),
        dwords(&[21, 22, 23, 10]),
        "the destination is the high half"
    );
    assert_eq!(op("vpsrldq_avx", &[register(&source), immediate(4)], 16), dwords(&[11, 12, 13, 0]));
    assert_eq!(
        op("insertps", &[register(&source), register(&other), immediate(0b1001_0001)], 16),
        dwords(&[0, 22, 12, 13])
    );
    assert_eq!(op("extractps", &[register(&[0; 4]), register(&source), immediate(2)], 4), dwords(&[12]));
    let wide = [dwords(&[0, 1, 2, 3]), dwords(&[4, 5, 6, 7])].concat();
    assert_eq!(
        op("vpermq_avx2", &[register(&wide), immediate(0x4e)], 32),
        [dwords(&[4, 5, 6, 7]), dwords(&[0, 1, 2, 3])].concat()
    );
    assert_eq!(
        op("vperm2i128_avx2", &[register(&wide), register(&[0xaa; 32]), immediate(0x21)], 32),
        [dwords(&[4, 5, 6, 7]), vec![0xaa; 16]].concat()
    );
    let indices = dwords(&[7, 0, 6, 1, 5, 2, 4, 3]);
    assert_eq!(op("vpermd_avx2", &[register(&indices), register(&wide)], 32), indices);
}

#[test]
fn extensions_packs_and_unpacks() {
    let bytes = hex("ff017f80000000000000000000000000");
    assert_eq!(op("pmovzxbd", &[register(&[0; 16]), register(&bytes)], 16), dwords(&[0xff, 1, 0x7f, 0x80]));
    assert_eq!(op("pmovsxbd", &[register(&[0; 16]), register(&bytes)], 16), dwords(&[u32::MAX, 1, 0x7f, 0xffff_ff80]));
    assert_eq!(
        op("vpmovsxwq_avx", &[register(&bytes)], 16),
        [0x01ffu64.to_le_bytes(), 0xffff_ffff_ffff_807fu64.to_le_bytes()].concat()
    );
    let a = dwords(&[70_000, (-70_000i32) as u32, 5, (-5i32) as u32]);
    let b = dwords(&[1, 2, 3, 0x8000]);
    assert_eq!(op("packssdw", &[register(&a), register(&b)], 16), words(&[0x7fff, 0x8000, 5, 0xfffb, 1, 2, 3, 0x7fff]));
    assert_eq!(op("packusdw", &[register(&a), register(&b)], 16), words(&[0xffff, 0, 5, 0, 1, 2, 3, 0x8000]));
    let a = words(&[300, 0xff80, 0x7f, 12, 0, 0, 0, 0]);
    assert_eq!(&op("vpacksswb_avx", &[register(&a), register(&a)], 16)[..4], [0x7f, 0x80, 0x7f, 12]);
    assert_eq!(&op("vpackuswb_avx", &[register(&a), register(&a)], 16)[..4], [0xff, 0, 0x7f, 12]);
    let low: Vec<u8> = (0..16).collect();
    let high: Vec<u8> = (16..32).collect();
    assert_eq!(&op("punpcklqdq", &[register(&low), register(&high)], 16)[..], [&low[..8], &high[..8]].concat());
    assert_eq!(&op("vpunpckhbw_avx", &[register(&low), register(&high)], 16)[..4], [8, 24, 9, 25]);
    assert_eq!(&op("vpunpckldq_avx", &[register(&low), register(&high)], 16)[..8], [0, 1, 2, 3, 16, 17, 18, 19]);
}

#[test]
fn arithmetic_saturates_and_multiplies() {
    let a = words(&[0xfff0, 100, 0x7ff0, 0x8000, 5, 6, 7, 8]);
    let b = words(&[0x0020, 100, 0x0020, 0xffff, 5, 6, 7, 8]);
    assert_eq!(&op("paddusw", &[register(&a), register(&b)], 16)[..8], words(&[0xffff, 200, 0x8010, 0xffff]));
    assert_eq!(&op("vpaddsw_avx", &[register(&a), register(&b)], 16)[..8], words(&[0x0010, 200, 0x7fff, 0x8000]));
    assert_eq!(&op("psubusw", &[register(&b), register(&a)], 16)[..8], words(&[0, 0, 0, 0x7fff]));
    assert_eq!(&op("pmulhw", &[register(&a), register(&b)], 16)[..8], words(&[0xffff, 0, 0x000f, 0]));
    assert_eq!(&op("pmulhuw", &[register(&a), register(&b)], 16)[..8], words(&[0x001f, 0, 0x000f, 0x7fff]));
    assert_eq!(&op("pmaddwd", &[register(&a), register(&b)], 16)[..8], dwords(&[9488, 0x0010_7e00]));
    let bytes = hex("ff01020304050607ff01020304050607");
    let signed = hex("01ff7f80010101010101010101010101");
    assert_eq!(&op("pmaddubsw", &[register(&bytes), register(&signed)], 16)[..4], words(&[0x00fe, 0xff7e]));
    assert_eq!(
        op("psadbw", &[register(&bytes), register(&[0; 16])], 16),
        [(0xff + 28u64).to_le_bytes(), (0xff + 28u64).to_le_bytes()].concat()
    );
    assert_eq!(op("pavgb", &[register(&[1]), register(&[2])], 1), [2]);
    assert_eq!(op("pabsb", &[register(&[0; 16]), register(&signed)], 16)[..4], [1, 1, 0x7f, 0x80]);
    assert_eq!(
        &op("psignb", &[register(&bytes), register(&hex("8000010000000000000000000000000000"))], 16)[..3],
        [1, 0, 2]
    );
    let a = dwords(&[7, (-3i32) as u32, 0x8000_0000, 3]);
    let b = dwords(&[(-2i32) as u32, 9, 2, 5]);
    assert_eq!(op("pmulld", &[register(&a), register(&b)], 16), dwords(&[(-14i32) as u32, (-27i32) as u32, 0, 15]));
    assert_eq!(
        op("pmuldq", &[register(&a), register(&b)], 16),
        [(-14i64).to_le_bytes(), (-0x1_0000_0000i64).to_le_bytes()].concat()
    );
    assert_eq!(op("phaddd", &[register(&a), register(&b)], 16), dwords(&[4, 0x8000_0003, 7, 7]));
    assert_eq!(
        op("vpminsd_avx", &[register(&a), register(&b)], 16),
        dwords(&[(-2i32) as u32, (-3i32) as u32, 0x8000_0000, 3])
    );
    assert_eq!(
        op("vpmaxud_avx", &[register(&a), register(&b)], 16),
        dwords(&[(-2i32) as u32, (-3i32) as u32, 0x8000_0000, 5])
    );
    assert_eq!(op("vpcmpgtd_avx", &[register(&a), register(&b)], 16), dwords(&[u32::MAX, 0, 0, 0]));
    assert_eq!(
        op("phminposuw", &[register(&[0; 16]), register(&words(&[9, 4, 7, 4, 8, 8, 8, 8]))], 16),
        words(&[4, 1, 0, 0, 0, 0, 0, 0])
    );
}

#[test]
fn shifts_blends_and_crc() {
    let value = dwords(&[0x8000_0001, 0x10, 0xffff_ffff, 3]);
    assert_eq!(op("vpsrad_avx", &[register(&value), immediate(4)], 16), dwords(&[0xf800_0000, 1, 0xffff_ffff, 0]));
    let count = 33u64.to_le_bytes();
    assert_eq!(op("vpslld_avx", &[register(&value), register(&count)], 16), [0u8; 16]);
    assert_eq!(
        op("psraw", &[register(&words(&[0x8000, 2, 0, 0, 0, 0, 0, 0])), register(&count)], 16)[..4],
        words(&[0xffff, 0])
    );
    let counts = dwords(&[1, 31, 32, 0]);
    assert_eq!(op("vpsllvd_avx2", &[register(&value), register(&counts)], 16), dwords(&[2, 0, 0, 3]));
    let mask = dwords(&[0x8000_0000, 0, 0xffff_ffff, 0x7fff_ffff]);
    assert_eq!(
        op("blendvps", &[register(&dwords(&[1, 2, 3, 4])), register(&dwords(&[5, 6, 7, 8])), register(&mask)], 16),
        dwords(&[5, 2, 7, 4])
    );
    assert_eq!(
        op(
            "vpblendd_avx2",
            &[register(&dwords(&[1, 2, 3, 4])), register(&dwords(&[5, 6, 7, 8])), immediate(0b0110)],
            16
        ),
        dwords(&[1, 6, 7, 4])
    );
    assert_eq!(
        op("pblendw", &[register(&words(&[1; 8])), register(&words(&[2; 8])), immediate(0x81)], 16),
        words(&[2, 1, 1, 1, 1, 1, 1, 2])
    );
    // CRC32C("123456789") = 0xe3069283: the instruction leaves the inverted CRC, so start and end at all ones.
    let mut crc = u32::MAX;
    for byte in b"123456789" {
        crc =
            u32::from_le_bytes(op("crc32", &[register(&crc.to_le_bytes()), register(&[*byte])], 4).try_into().unwrap());
    }
    assert_eq!(!crc, 0xe306_9283);
}

#[test]
fn packed_floats_round_compare_and_convert() {
    let floats = |values: &[f32]| -> Vec<u8> { values.iter().flat_map(|value| value.to_le_bytes()).collect() };
    let doubles = |values: &[f64]| -> Vec<u8> { values.iter().flat_map(|value| value.to_le_bytes()).collect() };
    let a = floats(&[1.5, -2.5, 2.5, -0.5]);
    assert_eq!(op("roundps", &[register(&[0; 16]), register(&a), immediate(0)], 16), floats(&[2.0, -2.0, 2.0, -0.0]));
    assert_eq!(op("roundps", &[register(&[0; 16]), register(&a), immediate(1)], 16), floats(&[1.0, -3.0, 2.0, -1.0]));
    assert_eq!(op("roundps", &[register(&[0; 16]), register(&a), immediate(3)], 16), floats(&[1.0, -2.0, 2.0, -0.0]));
    let d = doubles(&[7.5, 100.0]);
    assert_eq!(op("roundsd", &[register(&doubles(&[0.0, 9.0])), register(&d), immediate(2)], 16), doubles(&[8.0, 9.0]));
    assert_eq!(
        op("divpd", &[register(&doubles(&[1.0, 9.0])), register(&doubles(&[3.0, -2.0]))], 16),
        doubles(&[1.0 / 3.0, -4.5])
    );
    assert_eq!(
        op("vminpd_avx", &[register(&doubles(&[1.0, f64::NAN])), register(&doubles(&[3.0, 2.0]))], 16),
        doubles(&[1.0, 2.0])
    );
    let lt = op("cmpps", &[register(&a), register(&floats(&[2.0, -3.0, f32::NAN, 0.0])), immediate(1)], 16);
    assert_eq!(lt, dwords(&[u32::MAX, 0, 0, u32::MAX]));
    let unordered = op("vcmpps_avx", &[register(&a), register(&floats(&[2.0, -3.0, f32::NAN, 0.0])), immediate(3)], 16);
    assert_eq!(unordered, dwords(&[0, 0, u32::MAX, 0]));
    assert_eq!(
        op("vcvtps2dq_avx", &[register(&floats(&[2.5, -1.5, 3e9, f32::NAN]))], 16),
        dwords(&[2, (-2i32) as u32, 0x8000_0000, 0x8000_0000])
    );
    assert_eq!(op("vcvtdq2pd_avx", &[register(&dwords(&[(-7i32) as u32, 3]))], 16), doubles(&[-7.0, 3.0]));
    assert_eq!(
        op("vcvtpd2ps_avx", &[register(&doubles(&[0.1, -2.0]))], 16),
        [floats(&[0.1, -2.0]), vec![0; 8]].concat()
    );
    assert_eq!(
        op("vaddsubps_avx", &[register(&floats(&[1.0; 4])), register(&floats(&[0.5; 4]))], 16),
        floats(&[0.5, 1.5, 0.5, 1.5])
    );
    assert_eq!(
        op("vhaddps_avx", &[register(&floats(&[1.0, 2.0, 3.0, 4.0])), register(&floats(&[5.0, 6.0, 7.0, 8.0]))], 16),
        floats(&[3.0, 7.0, 11.0, 15.0])
    );
}

#[test]
fn malformed_operands_stop_without_panicking() {
    for name in ["pshufb", "pmaddwd", "blendvps", "pshuflw", "vpermq_avx2", "crc32", "insertps", "roundsd"] {
        // Too few operands, odd sizes and missing immediates fail cleanly.
        assert!(compute(name, &[], 16).unwrap().is_err(), "{name}");
        for out in [0, 1, 3, 7, 33] {
            let _ = compute(name, &[register(&[1, 2, 3]), register(&[0xff; 5]), immediate(0xff)], out);
        }
    }
}

// ----------------------------------------------------------------------------------------------------------------
// The evaluate-simd fixture against scalar references of its intrinsics.

type V = [u8; 16];

fn g16(v: &V, i: usize) -> u16 {
    u16::from_le_bytes([v[2 * i], v[2 * i + 1]])
}
fn s16(v: &mut V, i: usize, x: u16) {
    v[2 * i..2 * i + 2].copy_from_slice(&x.to_le_bytes());
}
fn g32(v: &V, i: usize) -> u32 {
    u32::from_le_bytes(v[4 * i..4 * i + 4].try_into().unwrap())
}
fn s32(v: &mut V, i: usize, x: u32) {
    v[4 * i..4 * i + 4].copy_from_slice(&x.to_le_bytes());
}
fn g64(v: &V, i: usize) -> u64 {
    u64::from_le_bytes(v[8 * i..8 * i + 8].try_into().unwrap())
}
fn s64(v: &mut V, i: usize, x: u64) {
    v[8 * i..8 * i + 8].copy_from_slice(&x.to_le_bytes());
}
fn map32(a: &V, b: &V, f: impl Fn(u32, u32) -> u32) -> V {
    let mut r = [0; 16];
    (0..4).for_each(|i| s32(&mut r, i, f(g32(a, i), g32(b, i))));
    r
}
fn map16(a: &V, b: &V, f: impl Fn(u16, u16) -> u16) -> V {
    let mut r = [0; 16];
    (0..8).for_each(|i| s16(&mut r, i, f(g16(a, i), g16(b, i))));
    r
}
fn shuffle32(a: &V, imm: u32) -> V {
    let mut r = [0; 16];
    (0..4).for_each(|i| s32(&mut r, i, g32(a, ((imm >> (2 * i)) & 3) as usize)));
    r
}
fn unpack8(a: &V, b: &V, high: bool) -> V {
    let base = if high { 8 } else { 0 };
    std::array::from_fn(|i| if i % 2 == 0 { a[base + i / 2] } else { b[base + i / 2] })
}
fn sat16(x: i32) -> u16 {
    x.clamp(-32768, 32767) as i16 as u16
}

/// `vector_mix` of evaluate-simd.c.
fn vector_mix(data: &[u8], blocks: usize) -> u32 {
    let zero = [0u8; 16];
    let mut acc = map32(&zero, &zero, |_, _| 0x0102_0304);
    let mut words = zero;
    for block in 0..blocks {
        let bytes: V = data[16 * block..16 * block + 16].try_into().unwrap();
        let mut sad = zero;
        for half in 0..2 {
            s64(&mut sad, half, (0..8).map(|i| u64::from(bytes[8 * half + i])).sum());
        }
        let low = unpack8(&bytes, &zero, false);
        let high = unpack8(&bytes, &zero, true);
        let mut products = zero;
        for i in 0..4 {
            let p = |k: usize| i32::from(g16(&low, k) as i16) * i32::from(g16(&high, k) as i16);
            s32(&mut products, i, p(2 * i).wrapping_add(p(2 * i + 1)) as u32);
        }
        acc = map32(&acc, &products, u32::wrapping_add);
        acc = map32(&acc, &acc, |x, _| x ^ (x << 3));
        acc = map32(&acc, &acc, |x, _| x.wrapping_sub(x >> 5));
        let mut sum = zero;
        (0..2).for_each(|i| s64(&mut sum, i, g64(&acc, i).wrapping_add(g64(&sad, i))));
        acc = sum;
        let mut packed = zero;
        for i in 0..8 {
            let source = if i < 4 { &products } else { &acc };
            s16(&mut packed, i, sat16((g32(source, i % 4) as i32).clamp(-32768, 32767)));
        }
        words = map16(&words, &packed, |x, y| (u32::from(x) + u32::from(y)).min(0xffff) as u16);
        let mulhi = map16(&low, &high, |x, y| ((i32::from(x as i16) * i32::from(y as i16)) >> 16) as u16);
        words = map16(&words, &mulhi, |x, y| (x as i16).max(y as i16) as u16);
        acc = shuffle32(&acc, 0b00_11_10_01);
        let mullo = map16(&low, &high, u16::wrapping_mul);
        acc = map32(&acc, &mullo, u32::wrapping_add);
        let min: V = std::array::from_fn(|i| bytes[i].min(high[i]));
        let avg: V = std::array::from_fn(|i| ((u16::from(bytes[i]) + u16::from(min[i]) + 1) >> 1) as u8);
        acc = map32(&acc, &avg, |x, y| x ^ y);
        let greater = map32(&acc, &words, |x, y| if (x as i32) > (y as i32) { u32::MAX } else { 0 });
        acc = map32(&acc, &greater, |x, y| x | (y & 0x10));
        let shifted: V = std::array::from_fn(|i| if i >= 3 { words[i - 3] } else { 0 });
        acc = map32(&acc, &shifted, |x, y| x.wrapping_add(((y as i32) >> 2) as u32));
        let right: V = std::array::from_fn(|i| if i + 5 < 16 { words[i + 5] } else { 0 });
        acc = map32(&right, &acc, |x, y| !x & y);
    }
    let mut hi = acc;
    for i in 0..4 {
        s16(&mut hi, 4 + i, g16(&acc, 4 + [2, 3, 0, 1][i]));
    }
    let mut folded = map32(&acc, &hi, u32::wrapping_add);
    folded = map32(&folded, &shuffle32(&folded, 0b01_00_11_10), u32::wrapping_add);
    folded = map32(&folded, &shuffle32(&folded, 0b10_11_00_01), u32::wrapping_add);
    let packus: V = std::array::from_fn(|i| {
        let source = if i < 8 { &words } else { &acc };
        (i32::from(g16(source, i % 8) as i16)).clamp(0, 255) as u8
    });
    let mask = (0..16).fold(0u32, |bits, i| bits | u32::from(packus[i] >> 7) << i);
    g32(&folded, 0) ^ (mask << 16) ^ u32::from(g16(&words, 5))
}

/// `vector_shuffle` of evaluate-simd.c.
fn vector_shuffle(data: &V, order: &V) -> u32 {
    let shuffled: V = std::array::from_fn(|i| if order[i] & 0x80 != 0 { 0 } else { data[(order[i] & 15) as usize] });
    let mut wide = [0u8; 16];
    (0..4).for_each(|i| s32(&mut wide, i, u32::from(shuffled[i])));
    let signs: V = std::array::from_fn(|i| match (shuffled[i] as i8).signum() {
        -1 => (data[i] as i8).wrapping_neg() as u8,
        0 => 0,
        _ => data[i],
    });
    let magnitude: V = std::array::from_fn(|i| (signs[i] as i8).unsigned_abs());
    let tripled = map32(&wide, &wide, |x, _| x.wrapping_mul(3));
    let mut paired = [0u8; 16];
    s32(&mut paired, 0, g32(&wide, 0).wrapping_add(g32(&wide, 1)));
    s32(&mut paired, 1, g32(&wide, 2).wrapping_add(g32(&wide, 3)));
    s32(&mut paired, 2, g32(&tripled, 0).wrapping_add(g32(&tripled, 1)));
    s32(&mut paired, 3, g32(&tripled, 2).wrapping_add(g32(&tripled, 3)));
    let bounded = map32(&paired, &paired, |x, _| ((x as i32).max(5) as u32).min(900));
    let aligned: V = std::array::from_fn(|i| if i + 7 < 16 { shuffled[i + 7] } else { magnitude[i + 7 - 16] });
    let mut result = g32(&bounded, 1).wrapping_add(u32::from(aligned[9]));
    let shifted = map32(&bounded, &bounded, |x, _| x << 22);
    result ^= (0..4).fold(0u32, |bits, i| bits | (g32(&shifted, i) >> 31) << i) << 24;
    result = result.wrapping_add(u32::from(magnitude.iter().all(|&byte| byte & 0x40 == 0)));
    let blended: V = std::array::from_fn(|i| if signs[i] & 0x80 != 0 { shuffled[i] } else { data[i] });
    result.wrapping_add(u32::from(blended[3]))
}

#[test]
fn vector_fixture_functions_match_their_intrinsics() {
    let project = fixture_api("evaluate-simd-x64.elf");
    for text in ["", "a", "fifteen chars!!", "sixteen chars!!!", "a rather longer text that spans several blocks"] {
        let report = run(&project, "vector_strlen", json!([{"buffer": {"text": text}}]), json!({}));
        assert_eq!(returned(&report), text.len() as u64, "{text:?}");
    }
    let report = run(&project, "vector_fill", json!([{"buffer": {"size": 40}}, 0x5a, 37]), json!({}));
    assert_eq!(report.buffers[0].hex, format!("{}{}", "5a".repeat(37), "00".repeat(3)));
    let data: Vec<u8> = (0..64u32).map(|index| (index * 37 + 11) as u8 ^ 0x5c).collect();
    for blocks in [1usize, 2, 4] {
        let report = run(&project, "vector_mix", json!([{"buffer": {"hex": hex_text(&data)}}, blocks]), json!({}));
        let result = report.result.as_ref().unwrap().unsigned.as_u64().unwrap() as u32;
        assert_eq!(result, vector_mix(&data, blocks), "{blocks} blocks: {}", report.detail);
    }
    for (data, order) in [
        (hex("00f102830405f6078809fa0b0c0d0e0f"), hex("0f0e0d0c0b0a09080706050403020180")),
        (hex("7f80ff01c03f2040ee11dd22cc33bb44"), hex("8001020383848586070605040b0a0908")),
    ] {
        let report = run(
            &project,
            "vector_shuffle",
            json!([{"buffer": {"hex": hex_text(&data)}}, {"buffer": {"hex": hex_text(&order)}}]),
            json!({}),
        );
        let result = report.result.as_ref().unwrap().unsigned.as_u64().unwrap() as u32;
        assert_eq!(result, vector_shuffle(&data.try_into().unwrap(), &order.try_into().unwrap()), "{}", report.detail);
    }
    let data: Vec<u8> = (0..96u32).map(|index| (index * 7 % 5) as u8).collect();
    for blocks in [1usize, 3] {
        let report = run(&project, "vector_count", json!([{"buffer": {"hex": hex_text(&data)}}, blocks, 1]), json!({}));
        let result = report.result.as_ref().unwrap().unsigned.as_u64().unwrap() as u32;
        let count = data[..32 * blocks].iter().filter(|&&byte| byte == 1).count() as u32;
        let mut sums = [0u32; 8];
        for block in 0..blocks {
            for i in 0..8 {
                sums[i] = sums[i].wrapping_add(u32::from(data[32 * block + i]));
            }
            let swapped: [u32; 8] = std::array::from_fn(|i| sums[(i + 4) % 8]);
            sums = std::array::from_fn(|i| sums[i] ^ swapped[i]);
        }
        let half: [u32; 4] = std::array::from_fn(|i| sums[i].wrapping_add(sums[i + 4]));
        let half: [u32; 4] = std::array::from_fn(|i| half[i].wrapping_add(half[i ^ 2]));
        let half: [u32; 4] = std::array::from_fn(|i| half[i].wrapping_add(half[i ^ 1]));
        assert_eq!(result, (count << 24) ^ half[0], "{blocks} blocks: {}", report.detail);
    }
}

fn hex_text(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
