//! Processor operations the x86 Sleigh specifications leave as CALLOTHER that the interpreter computes: SSE, SSSE3,
//! SSE4.1 and AVX/AVX2 packed integer and float operations and SSE4.2 CRC32C. Each is a pure function of its
//! operands' little-endian bytes, by Intel's definitions. AVX-512 forms (masks and wider registers) are not
//! interpreted.
//!
//! Operand order follows the specifications: legacy SSE forms pass the destination's old value first (`pshufb(XMM1,
//! XMM2)`), VEX forms their sources (`vpshufb_avx(XMM2, XMM3)`), and an immediate is a constant operand. So a binary
//! operation reads the last two register operands and a unary one the last.

use super::float::{self, DOUBLE, Format, Rounding, SINGLE};

/// One CALLOTHER input after the operation index.
pub(crate) struct Operand {
    pub bytes: Vec<u8>,
    pub constant: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lanewise {
    Add,
    AddSigned,
    AddUnsigned,
    Sub,
    SubSigned,
    SubUnsigned,
    Equal,
    Greater,
    MinSigned,
    MinUnsigned,
    MaxSigned,
    MaxUnsigned,
    Average,
    MulHighSigned,
    MulHighUnsigned,
    MulLow,
    MulHighRound,
    Sign,
    And,
    AndNot,
    Or,
    Xor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FloatOp {
    Add,
    Sub,
    Mul,
    Div,
    Min,
    Max,
    Sqrt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShiftKind {
    Left,
    Right,
    Arithmetic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Elementwise(Lanewise, usize),
    Absolute(usize),
    Float { op: FloatOp, format: Format, scalar: bool },
    AddSub(Format),
    Horizontal { format: Format, subtract: bool },
    Compare { format: Format, scalar: bool },
    Round { format: Format, scalar: bool },
    IntToFloat(Format),
    FloatToInt(Format),
    Widen,
    Narrow,
    Extend { from: usize, to: usize, signed: bool },
    Pack { from: usize, signed: bool },
    Unpack { element: usize, high: bool },
    Shuffle8,
    Shuffle32,
    ShuffleLow16,
    ShuffleHigh16,
    Shuffle16,
    ShuffleFloat32,
    ShuffleFloat64,
    Align,
    ByteShift { left: bool },
    Shift { element: usize, kind: ShiftKind },
    VariableShift { element: usize, kind: ShiftKind },
    Permute64,
    Permute32,
    Permute128,
    PermuteInLane32,
    PermuteInLane64,
    Insert32,
    Extract32,
    DuplicateOdd,
    DuplicateEven,
    HighToLow,
    LowToHigh,
    SignMask(usize),
    BlendVariable(usize),
    BlendImmediate(usize),
    BlendWords,
    SumAbsoluteDifferences,
    MultiplyAddWords,
    MultiplyAddBytes,
    MultiplyDoublewords { signed: bool },
    HorizontalInteger { element: usize, subtract: bool, saturate: bool },
    MinimumPosition,
    Crc32,
    Move,
}

/// The operation `name` stands for, after stripping a VEX form's `v` prefix and `_avx`/`_avx2` suffix.
fn kind(name: &str) -> Option<Kind> {
    let stem = match name.split_once('_') {
        Some((stem, "avx" | "avx2")) => stem.strip_prefix('v')?,
        Some(_) => return None,
        None => name,
    };
    use Kind::*;
    use Lanewise as L;
    let element = |suffix: u8| match suffix {
        b'b' => 1,
        b'w' => 2,
        b'd' => 4,
        _ => 8,
    };
    let last = *stem.as_bytes().last()?;
    Some(match stem {
        "paddb" | "paddw" | "paddd" | "paddq" => Elementwise(L::Add, element(last)),
        "paddsb" | "paddsw" => Elementwise(L::AddSigned, element(last)),
        "paddusb" | "paddusw" => Elementwise(L::AddUnsigned, element(last)),
        "psubb" | "psubw" | "psubd" | "psubq" => Elementwise(L::Sub, element(last)),
        "psubsb" | "psubsw" => Elementwise(L::SubSigned, element(last)),
        "psubusb" | "psubusw" => Elementwise(L::SubUnsigned, element(last)),
        "pcmpeqb" | "pcmpeqw" | "pcmpeqd" | "pcmpeqq" => Elementwise(L::Equal, element(last)),
        "pcmpgtb" | "pcmpgtw" | "pcmpgtd" | "pcmpgtq" => Elementwise(L::Greater, element(last)),
        "pminsb" | "pminsw" | "pminsd" => Elementwise(L::MinSigned, element(last)),
        "pminub" | "pminuw" | "pminud" => Elementwise(L::MinUnsigned, element(last)),
        "pmaxsb" | "pmaxsw" | "pmaxsd" => Elementwise(L::MaxSigned, element(last)),
        "pmaxub" | "pmaxuw" | "pmaxud" => Elementwise(L::MaxUnsigned, element(last)),
        "pavgb" | "pavgw" => Elementwise(L::Average, element(last)),
        "pmulhw" => Elementwise(L::MulHighSigned, 2),
        "pmulhuw" => Elementwise(L::MulHighUnsigned, 2),
        "pmullw" => Elementwise(L::MulLow, 2),
        "pmulld" => Elementwise(L::MulLow, 4),
        "pmulhrsw" => Elementwise(L::MulHighRound, 2),
        "psignb" | "psignw" | "psignd" => Elementwise(L::Sign, element(last)),
        "pand" | "andps" | "andpd" => Elementwise(L::And, 8),
        "pandn" | "andnps" | "andnpd" => Elementwise(L::AndNot, 8),
        "por" | "orps" | "orpd" => Elementwise(L::Or, 8),
        "pxor" | "xorps" | "xorpd" => Elementwise(L::Xor, 8),
        "pabsb" | "pabsw" | "pabsd" => Absolute(element(last)),
        "addps" | "addpd" | "subps" | "subpd" | "mulps" | "mulpd" | "divps" | "divpd" | "minps" | "minpd" | "maxps"
        | "maxpd" | "sqrtps" | "sqrtpd" | "minss" | "minsd" | "maxss" | "maxsd" => {
            let op = match &stem[..3] {
                "add" => FloatOp::Add,
                "sub" => FloatOp::Sub,
                "mul" => FloatOp::Mul,
                "div" => FloatOp::Div,
                "min" => FloatOp::Min,
                "max" => FloatOp::Max,
                _ => FloatOp::Sqrt,
            };
            Float { op, format: float_format(last), scalar: stem.as_bytes()[stem.len() - 2] == b's' }
        }
        "addsubps" | "addsubpd" => AddSub(float_format(last)),
        "haddps" | "haddpd" | "hsubps" | "hsubpd" => {
            Horizontal { format: float_format(last), subtract: &stem[1..2] == "s" }
        }
        "cmpps" | "cmppd" | "cmpss" | "cmpsd" => {
            Compare { format: float_format(last), scalar: stem.as_bytes()[stem.len() - 2] == b's' }
        }
        "roundps" | "roundpd" | "roundss" | "roundsd" => {
            Round { format: float_format(last), scalar: stem.as_bytes()[stem.len() - 2] == b's' }
        }
        "cvtdq2ps" => IntToFloat(SINGLE),
        "cvtdq2pd" => IntToFloat(DOUBLE),
        "cvtps2dq" => FloatToInt(SINGLE),
        "cvtpd2dq" => FloatToInt(DOUBLE),
        "cvtps2pd" => Widen,
        "cvtpd2ps" => Narrow,
        "pmovsxbw" | "pmovsxbd" | "pmovsxbq" | "pmovsxwd" | "pmovsxwq" | "pmovsxdq" | "pmovzxbw" | "pmovzxbd"
        | "pmovzxbq" | "pmovzxwd" | "pmovzxwq" | "pmovzxdq" => {
            let bytes = stem.as_bytes();
            Extend { from: element(bytes[6]), to: element(bytes[7]), signed: bytes[4] == b's' }
        }
        "packsswb" => Pack { from: 2, signed: true },
        "packssdw" => Pack { from: 4, signed: true },
        "packuswb" => Pack { from: 2, signed: false },
        "packusdw" => Pack { from: 4, signed: false },
        "punpcklbw" | "punpcklwd" | "punpckldq" | "punpcklqdq" | "punpckhbw" | "punpckhwd" | "punpckhdq"
        | "punpckhqdq" => {
            // p-u-n-p-c-k-{l,h}-{bw,wd,dq,qdq}
            let element = if stem.ends_with("qdq") { 8 } else { element(stem.as_bytes()[7]) };
            Unpack { element, high: stem.as_bytes()[6] == b'h' }
        }
        "unpcklps" | "unpckhps" => Unpack { element: 4, high: stem.as_bytes()[5] == b'h' },
        "unpcklpd" | "unpckhpd" => Unpack { element: 8, high: stem.as_bytes()[5] == b'h' },
        "pshufb" => Shuffle8,
        "pshufd" => Shuffle32,
        "pshuflw" => ShuffleLow16,
        "pshufhw" => ShuffleHigh16,
        "pshufw" => Shuffle16,
        "shufps" => ShuffleFloat32,
        "shufpd" => ShuffleFloat64,
        "palignr" => Align,
        "pslldq" => ByteShift { left: true },
        "psrldq" => ByteShift { left: false },
        "psllw" | "pslld" | "psllq" => Shift { element: element(last), kind: ShiftKind::Left },
        "psrlw" | "psrld" | "psrlq" => Shift { element: element(last), kind: ShiftKind::Right },
        "psraw" | "psrad" => Shift { element: element(last), kind: ShiftKind::Arithmetic },
        "psllvd" | "psllvq" => VariableShift { element: element(last), kind: ShiftKind::Left },
        "psrlvd" | "psrlvq" => VariableShift { element: element(last), kind: ShiftKind::Right },
        "psravd" => VariableShift { element: 4, kind: ShiftKind::Arithmetic },
        "permq" | "permpd" => Permute64,
        "permd" | "permps" => Permute32,
        "perm2f128" | "perm2i128" => Permute128,
        "permilps" => PermuteInLane32,
        "permilpd" => PermuteInLane64,
        "insertps" => Insert32,
        "extractps" => Extract32,
        "movshdup" => DuplicateOdd,
        "movsldup" => DuplicateEven,
        "movhlps" => HighToLow,
        "movlhps" => LowToHigh,
        "movmskps" => SignMask(4),
        "movmskpd" => SignMask(8),
        "pmovmskb" => SignMask(1),
        "pblendvb" => BlendVariable(1),
        "blendvps" => BlendVariable(4),
        "blendvpd" => BlendVariable(8),
        "blendps" | "pblendd" => BlendImmediate(4),
        "blendpd" => BlendImmediate(8),
        "pblendw" => BlendWords,
        "psadbw" => SumAbsoluteDifferences,
        "pmaddwd" => MultiplyAddWords,
        "pmaddubsw" => MultiplyAddBytes,
        "pmuldq" => MultiplyDoublewords { signed: true },
        "pmuludq" => MultiplyDoublewords { signed: false },
        "phaddw" | "phaddd" => HorizontalInteger { element: element(last), subtract: false, saturate: false },
        "phsubw" | "phsubd" => HorizontalInteger { element: element(last), subtract: true, saturate: false },
        "phaddsw" => HorizontalInteger { element: 2, subtract: false, saturate: true },
        "phsubsw" => HorizontalInteger { element: 2, subtract: true, saturate: true },
        "phminposuw" => MinimumPosition,
        "crc32" => Crc32,
        "lddqu" | "movntdqa" | "movntdq" | "movntps" | "movntpd" => Move,
        _ => return None,
    })
}

fn float_format(last: u8) -> Format {
    if last == b'd' { DOUBLE } else { SINGLE }
}

/// The instruction set whose processor operations are meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    X86,
    Arm,
}

/// Whether the interpreter computes the processor operation `name` of `family`.
pub(crate) fn known(name: &str, family: Family) -> bool {
    match family {
        Family::X86 => kind(name).is_some(),
        Family::Arm => arm_conversion(name).is_some(),
    }
}

/// 32-bit ARM VFP/NEON conversions (`vcvt`), which Ghidra's ARM specification leaves as operations on the source
/// (the first operand; later ones are mode values): (to float, from signed or unsigned integers) or (to integer,
/// signed, rounding to nearest instead of toward zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArmConversion {
    ToFloat { signed: bool },
    ToInteger { signed: bool, nearest: bool },
    FloatWidth,
}

fn arm_conversion(name: &str) -> Option<ArmConversion> {
    use ArmConversion::*;
    Some(match name {
        "VectorSignedToFloat" => ToFloat { signed: true },
        "VectorUnsignedToFloat" => ToFloat { signed: false },
        "VectorFloatToSigned" => ToInteger { signed: true, nearest: false },
        "VectorFloatToUnsigned" => ToInteger { signed: false, nearest: false },
        "VectorFloatToSignedRound" | "FloatToSignedRound" => ToInteger { signed: true, nearest: true },
        "VectorFloatToUnsignedRound" | "FloatToUnsignedRound" => ToInteger { signed: false, nearest: true },
        "VectorFloatDoubleToSingle" | "VectorFloatSingleToDouble" => FloatWidth,
        _ => return None,
    })
}

/// An ARM conversion of the first operand: elementwise over 32-bit lanes when source and result are the same size
/// (NEON), else one scalar of the source's and the result's sizes. Integers saturate; NaN converts to 0.
fn arm(conversion: ArmConversion, operands: &[Operand], out: usize) -> Option<Vec<u8>> {
    let source = &operands.first()?.bytes;
    let (count, from, to) = if source.len() == out { (out / 4, 4, 4) } else { (1, source.len(), out) };
    if !matches!(from, 4 | 8) || !matches!(to, 4 | 8) {
        return None;
    }
    let mut result = vec![0u8; out];
    for index in 0..count {
        let value = get(source, from, index);
        let converted = match conversion {
            ArmConversion::ToFloat { signed: sign } => {
                let integer = if sign { i128::from(signed(value, from)) } else { i128::from(value) };
                float::from_integer(integer, float_of(to)) as u64
            }
            ArmConversion::ToInteger { signed: sign, nearest } => {
                let format = float_of(from);
                let mut bits = u128::from(value);
                if nearest {
                    bits = float::round_integral(bits, format, Rounding::Nearest);
                }
                let (low, high) = if sign {
                    (-(1i128 << (8 * to - 1)), (1i128 << (8 * to - 1)) - 1)
                } else {
                    (0, (1i128 << (8 * to)) - 1)
                };
                let integer = match float::to_integer(bits, format) {
                    Some(integer) => integer.clamp(low, high),
                    None if float::is_nan(bits, format) => 0,
                    None if float::compare(bits, 0, format) == Some(std::cmp::Ordering::Less) => low,
                    None => high,
                };
                integer as u64 & mask(to)
            }
            ArmConversion::FloatWidth => float::convert(u128::from(value), float_of(from), float_of(to)) as u64,
        };
        put(&mut result, to, index, converted);
    }
    Some(result)
}

fn float_of(bytes: usize) -> Format {
    if bytes == 8 { DOUBLE } else { SINGLE }
}

/// The element `index` of `size` bytes in `bytes` (zero past its end).
fn get(bytes: &[u8], size: usize, index: usize) -> u64 {
    (0..size.min(8)).fold(0u64, |value, offset| {
        value | u64::from(bytes.get(index * size + offset).copied().unwrap_or(0)) << (8 * offset)
    })
}

fn put(out: &mut [u8], size: usize, index: usize, value: u64) {
    for offset in 0..size.min(8) {
        if let Some(byte) = out.get_mut(index * size + offset) {
            *byte = (value >> (8 * offset)) as u8;
        }
    }
}

fn signed(value: u64, size: usize) -> i64 {
    let shift = 64 - 8 * size as u32;
    ((value << shift) as i64) >> shift
}

fn mask(size: usize) -> u64 {
    if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 }
}

fn saturate_signed(value: i64, size: usize) -> u64 {
    let bits = 8 * size as u32;
    let (low, high) = (-(1i64 << (bits - 1)), (1i64 << (bits - 1)) - 1);
    value.clamp(low, high) as u64 & mask(size)
}

fn saturate_unsigned(value: i64, size: usize) -> u64 {
    value.clamp(0, mask(size) as i64) as u64
}

fn lanewise(op: Lanewise, a: u64, b: u64, size: usize) -> u64 {
    let (x, y) = (signed(a, size), signed(b, size));
    let wide = |value: i128| (value as u64) & mask(size);
    match op {
        Lanewise::Add => a.wrapping_add(b) & mask(size),
        Lanewise::AddSigned => saturate_signed(x + y, size),
        Lanewise::AddUnsigned => saturate_unsigned(a as i64 + b as i64, size),
        Lanewise::Sub => a.wrapping_sub(b) & mask(size),
        Lanewise::SubSigned => saturate_signed(x - y, size),
        Lanewise::SubUnsigned => saturate_unsigned(a as i64 - b as i64, size),
        Lanewise::Equal => {
            if a == b {
                mask(size)
            } else {
                0
            }
        }
        Lanewise::Greater => {
            if x > y {
                mask(size)
            } else {
                0
            }
        }
        Lanewise::MinSigned => {
            if x < y {
                a
            } else {
                b
            }
        }
        Lanewise::MinUnsigned => a.min(b),
        Lanewise::MaxSigned => {
            if x > y {
                a
            } else {
                b
            }
        }
        Lanewise::MaxUnsigned => a.max(b),
        Lanewise::Average => (a + b + 1) >> 1,
        Lanewise::MulHighSigned => wide((i128::from(x) * i128::from(y)) >> (8 * size)),
        Lanewise::MulHighUnsigned => wide((i128::from(a) * i128::from(b)) >> (8 * size)),
        Lanewise::MulLow => wide(i128::from(x) * i128::from(y)),
        Lanewise::MulHighRound => wide((((i128::from(x) * i128::from(y)) >> 14) + 1) >> 1),
        Lanewise::Sign => match y.signum() {
            -1 => a.wrapping_neg() & mask(size),
            0 => 0,
            _ => a,
        },
        Lanewise::And => a & b,
        Lanewise::AndNot => !a & b & mask(size),
        Lanewise::Or => a | b,
        Lanewise::Xor => a ^ b,
    }
}

/// `format`'s element bytes.
fn width(format: Format) -> usize {
    if format == DOUBLE { 8 } else { 4 }
}

fn float_op(op: FloatOp, a: u64, b: u64, format: Format) -> u64 {
    let (x, y) = (float::to_f64(u128::from(a), format), float::to_f64(u128::from(b), format));
    let value = match op {
        FloatOp::Add => x + y,
        FloatOp::Sub => x - y,
        FloatOp::Mul => x * y,
        FloatOp::Div => x / y,
        FloatOp::Sqrt => y.sqrt(),
        // MINPS/MAXPS return the second operand unless the first is strictly smaller (larger): for NaNs and zeros
        // of either sign too.
        FloatOp::Min => return if x < y { a } else { b },
        FloatOp::Max => return if x > y { a } else { b },
    };
    // Single precision rounds once in f64 and again to f32, which is exact for +, -, *, / and sqrt.
    float::from_f64(value, format) as u64
}

/// CMPPS predicate `predicate` (0-31; the signalling and quiet variants compare alike).
fn float_predicate(predicate: u64, x: f64, y: f64) -> bool {
    let unordered = x.is_nan() || y.is_nan();
    let result = match predicate & 7 {
        0 => x == y,
        1 => x < y,
        2 => x <= y,
        3 => unordered,
        4 => x != y,
        5 => x >= y || unordered,
        6 => x > y || unordered,
        _ => !unordered,
    };
    // 8-15 negate the ordered/unordered sense of 0-7: EQ_UQ, NGE, NGT, FALSE, NEQ_OQ, GE, GT, TRUE.
    if predicate & 8 == 0 {
        return result;
    }
    match predicate & 7 {
        0 => x == y || unordered,
        1 => x < y || unordered,
        2 => x <= y || unordered,
        3 => false,
        4 => x != y && !unordered,
        5 => x >= y,
        6 => x > y,
        _ => true,
    }
}

fn rounding(immediate: u64) -> Rounding {
    // Bit 2 selects MXCSR.RC, which the interpreter keeps at its default, round to nearest.
    if immediate & 4 != 0 {
        return Rounding::Nearest;
    }
    match immediate & 3 {
        0 => Rounding::Nearest,
        1 => Rounding::Down,
        2 => Rounding::Up,
        _ => Rounding::Toward0,
    }
}

/// CVTPS2DQ/CVTPD2DQ: round to nearest even, and the integer indefinite 0x80000000 when out of range or NaN.
fn float_to_i32(bits: u64, format: Format) -> u64 {
    let rounded = float::round_integral(u128::from(bits), format, Rounding::Nearest);
    match float::to_integer(rounded, format) {
        Some(value) if i32::try_from(value).is_ok() => value as i32 as u32 as u64,
        _ => 0x8000_0000,
    }
}

const CRC32C: u32 = 0x82f6_3b78;

fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ CRC32C } else { crc >> 1 };
        }
    }
    crc
}

/// Computes the processor operation `name` on `operands` for an `out`-byte result, or `None` when the interpreter
/// does not know it.
pub(crate) fn run(name: &str, family: Family, operands: &[Operand], out: usize) -> Option<Result<Vec<u8>, String>> {
    let result = match family {
        Family::X86 => compute(kind(name)?, operands, out),
        Family::Arm => arm(arm_conversion(name)?, operands, out),
    };
    Some(result.ok_or_else(|| format!("{name} with {} operands", operands.len())))
}

fn compute(kind: Kind, operands: &[Operand], out: usize) -> Option<Vec<u8>> {
    let registers: Vec<&[u8]> =
        operands.iter().filter(|operand| !operand.constant).map(|operand| operand.bytes.as_slice()).collect();
    let immediate = operands.iter().find(|operand| operand.constant).map(|operand| get(&operand.bytes, 8, 0));
    let count = registers.len();
    let unary = || registers.last().copied();
    let binary = || (count >= 2).then(|| (registers[count - 2], registers[count - 1]));
    let mut result = vec![0u8; out];
    // 128-bit lanes: an AVX register's halves work independently in shuffles, packs and horizontal operations.
    let lanes = out.div_ceil(16).max(1);
    let lane_bytes = out.min(16);
    use Kind::*;
    match kind {
        Elementwise(op, size) => {
            let (a, b) = binary()?;
            for index in 0..out / size {
                put(&mut result, size, index, lanewise(op, get(a, size, index), get(b, size, index), size));
            }
        }
        Absolute(size) => {
            let a = unary()?;
            for index in 0..out / size {
                put(&mut result, size, index, signed(get(a, size, index), size).unsigned_abs() & mask(size));
            }
        }
        Float { op, format, scalar } => {
            let size = width(format);
            let (a, b) = if op == FloatOp::Sqrt && count == 1 { (unary()?, unary()?) } else { binary()? };
            result.copy_from_slice(&padded(a, out));
            let elements = if scalar { 1 } else { out / size };
            for index in 0..elements {
                put(&mut result, size, index, float_op(op, get(a, size, index), get(b, size, index), format));
            }
        }
        AddSub(format) => {
            let size = width(format);
            let (a, b) = binary()?;
            for index in 0..out / size {
                let op = if index % 2 == 0 { FloatOp::Sub } else { FloatOp::Add };
                put(&mut result, size, index, float_op(op, get(a, size, index), get(b, size, index), format));
            }
        }
        Horizontal { format, subtract } => {
            let size = width(format);
            let (a, b) = binary()?;
            let op = if subtract { FloatOp::Sub } else { FloatOp::Add };
            let per_lane = lane_bytes / size;
            for lane in 0..lanes {
                let base = lane * per_lane;
                for index in 0..per_lane {
                    let source = if index < per_lane / 2 { a } else { b };
                    let pair = base + 2 * (index % (per_lane / 2));
                    let value = float_op(op, get(source, size, pair), get(source, size, pair + 1), format);
                    put(&mut result, size, base + index, value);
                }
            }
        }
        Compare { format, scalar } => {
            let size = width(format);
            let (a, b) = binary()?;
            result.copy_from_slice(&padded(a, out));
            let elements = if scalar { 1 } else { out / size };
            for index in 0..elements {
                let x = float::to_f64(u128::from(get(a, size, index)), format);
                let y = float::to_f64(u128::from(get(b, size, index)), format);
                put(&mut result, size, index, if float_predicate(immediate?, x, y) { mask(size) } else { 0 });
            }
        }
        Round { format, scalar } => {
            let size = width(format);
            let (a, b) = if count >= 2 { binary()? } else { (unary()?, unary()?) };
            let mode = rounding(immediate?);
            result.copy_from_slice(&padded(if scalar { a } else { b }, out));
            let elements = if scalar { 1 } else { out / size };
            for index in 0..elements {
                let value = float::round_integral(u128::from(get(b, size, index)), format, mode);
                put(&mut result, size, index, value as u64);
            }
        }
        IntToFloat(format) => {
            let a = unary()?;
            let size = width(format);
            for index in 0..out / size {
                let value = float::from_integer(i128::from(signed(get(a, 4, index), 4)), format);
                put(&mut result, size, index, value as u64);
            }
        }
        FloatToInt(format) => {
            let a = unary()?;
            let size = width(format);
            for index in 0..(a.len() / size).min(out / 4) {
                put(&mut result, 4, index, float_to_i32(get(a, size, index), format));
            }
        }
        Widen => {
            let a = unary()?;
            for index in 0..out / 8 {
                put(&mut result, 8, index, float::convert(u128::from(get(a, 4, index)), SINGLE, DOUBLE) as u64);
            }
        }
        Narrow => {
            let a = unary()?;
            for index in 0..(a.len() / 8).min(out / 4) {
                put(&mut result, 4, index, float::convert(u128::from(get(a, 8, index)), DOUBLE, SINGLE) as u64);
            }
        }
        Extend { from, to, signed: sign } => {
            let a = unary()?;
            for index in 0..out / to {
                let value = get(a, from, index);
                let value = if sign { signed(value, from) as u64 & mask(to) } else { value };
                put(&mut result, to, index, value);
            }
        }
        Pack { from, signed: sign } => {
            let (a, b) = binary()?;
            let to = from / 2;
            let per_source = lane_bytes / from;
            for lane in 0..lanes {
                for index in 0..2 * per_source {
                    let source = if index < per_source { a } else { b };
                    let value = signed(get(source, from, lane * per_source + index % per_source), from);
                    let packed = if sign { saturate_signed(value, to) } else { saturate_unsigned(value, to) };
                    put(&mut result, to, lane * 2 * per_source + index, packed);
                }
            }
        }
        Unpack { element, high } => {
            let (a, b) = binary()?;
            let half = lane_bytes / element / 2;
            for lane in 0..lanes {
                let base = lane * 2 * half;
                let from = base + if high { half } else { 0 };
                for index in 0..half {
                    put(&mut result, element, base + 2 * index, get(a, element, from + index));
                    put(&mut result, element, base + 2 * index + 1, get(b, element, from + index));
                }
            }
        }
        Shuffle8 => {
            let (a, b) = binary()?;
            for lane in 0..lanes {
                for index in 0..lane_bytes {
                    let control = get(b, 1, lane * 16 + index);
                    let value = if control & 0x80 != 0 { 0 } else { get(a, 1, lane * 16 + (control as usize & 15)) };
                    put(&mut result, 1, lane * 16 + index, value);
                }
            }
        }
        Shuffle32 | ShuffleFloat32 | PermuteInLane32 => {
            let (a, b) = match kind {
                ShuffleFloat32 => binary()?,
                PermuteInLane32 if immediate.is_none() => binary()?,
                _ => (unary()?, unary()?),
            };
            for lane in 0..lanes {
                for index in 0..4 {
                    let base = lane * 4;
                    let (source, selector) = match kind {
                        PermuteInLane32 if immediate.is_none() => (a, get(b, 4, base + index) & 3),
                        ShuffleFloat32 => (if index < 2 { a } else { b }, (immediate? >> (2 * index)) & 3),
                        _ => (a, (immediate? >> (2 * index)) & 3),
                    };
                    put(&mut result, 4, base + index, get(source, 4, base + selector as usize));
                }
            }
        }
        ShuffleLow16 | ShuffleHigh16 | Shuffle16 => {
            let a = unary()?;
            result.copy_from_slice(&padded(a, out));
            let immediate = immediate?;
            let words = lane_bytes / 2;
            for lane in 0..lanes {
                let base = lane * words + if kind == ShuffleHigh16 { 4 } else { 0 };
                for index in 0..4 {
                    let selector = ((immediate >> (2 * index)) & 3) as usize;
                    put(&mut result, 2, base + index, get(a, 2, base + selector));
                }
            }
        }
        ShuffleFloat64 | PermuteInLane64 => {
            let (a, b) = match kind {
                PermuteInLane64 if immediate.is_none() => binary()?,
                ShuffleFloat64 => binary()?,
                _ => (unary()?, unary()?),
            };
            for index in 0..out / 8 {
                let lane = index & !1;
                let value = match kind {
                    PermuteInLane64 if immediate.is_none() => get(a, 8, lane + ((get(b, 8, index) >> 1) & 1) as usize),
                    PermuteInLane64 => get(a, 8, lane + ((immediate? >> index) & 1) as usize),
                    _ => {
                        let source = if index % 2 == 0 { a } else { b };
                        get(source, 8, lane + ((immediate? >> index) & 1) as usize)
                    }
                };
                put(&mut result, 8, index, value);
            }
        }
        Align => {
            let (a, b) = binary()?;
            let shift = immediate? as usize;
            for lane in 0..lanes {
                for index in 0..lane_bytes {
                    // The lane's 32 bytes, `b` low and `a` high, shifted right by `shift` bytes.
                    let at = index + shift;
                    let value = match at {
                        0..16 => get(b, 1, lane * 16 + at),
                        16..32 => get(a, 1, lane * 16 + at - 16),
                        _ => 0,
                    };
                    put(&mut result, 1, lane * 16 + index, value);
                }
            }
        }
        ByteShift { left } => {
            let a = unary()?;
            let shift = (immediate? as usize).min(16);
            for lane in 0..lanes {
                for index in 0..lane_bytes {
                    let value = if left {
                        index.checked_sub(shift).map_or(0, |from| get(a, 1, lane * 16 + from))
                    } else if index + shift < 16 {
                        get(a, 1, lane * 16 + index + shift)
                    } else {
                        0
                    };
                    put(&mut result, 1, lane * 16 + index, value);
                }
            }
        }
        Shift { element, kind: shift_kind } => {
            let (value, amount) = match immediate {
                Some(immediate) => (unary()?, immediate),
                None => {
                    let (value, count) = binary()?;
                    (value, get(count, 8, 0))
                }
            };
            for index in 0..out / element {
                put(&mut result, element, index, shift(get(value, element, index), amount, element, shift_kind));
            }
        }
        VariableShift { element, kind: shift_kind } => {
            let (value, counts) = binary()?;
            for index in 0..out / element {
                let shifted = shift(get(value, element, index), get(counts, element, index), element, shift_kind);
                put(&mut result, element, index, shifted);
            }
        }
        Permute64 => {
            let a = unary()?;
            for index in 0..out / 8 {
                put(&mut result, 8, index, get(a, 8, ((immediate? >> (2 * index)) & 3) as usize));
            }
        }
        Permute32 => {
            let (indices, source) = binary()?;
            for index in 0..out / 4 {
                put(&mut result, 4, index, get(source, 4, (get(indices, 4, index) & 7) as usize));
            }
        }
        Permute128 => {
            let (a, b) = binary()?;
            let immediate = immediate?;
            for half in 0..out / 16 {
                let control = immediate >> (4 * half);
                if control & 8 != 0 {
                    continue;
                }
                let source = if control & 2 == 0 { a } else { b };
                for index in 0..2 {
                    put(&mut result, 8, 2 * half + index, get(source, 8, 2 * (control as usize & 1) + index));
                }
            }
        }
        Insert32 => {
            let (a, b) = binary()?;
            let immediate = immediate?;
            result.copy_from_slice(&padded(a, out));
            // A memory source is the 32-bit value itself; a register source selects one of its elements.
            let value = if b.len() <= 4 { get(b, 4, 0) } else { get(b, 4, ((immediate >> 6) & 3) as usize) };
            put(&mut result, 4, ((immediate >> 4) & 3) as usize, value);
            for index in 0..4 {
                if immediate & (1 << index) != 0 {
                    put(&mut result, 4, index, 0);
                }
            }
        }
        Extract32 => {
            let a = unary()?;
            put(&mut result, 4, 0, get(a, 4, (immediate? & 3) as usize));
        }
        DuplicateOdd | DuplicateEven => {
            let a = unary()?;
            for index in 0..out / 4 {
                let from = if kind == DuplicateOdd { index | 1 } else { index & !1 };
                put(&mut result, 4, index, get(a, 4, from));
            }
        }
        HighToLow | LowToHigh => {
            let (a, b) = binary()?;
            let (low, high) =
                if kind == HighToLow { (get(b, 8, 1), get(a, 8, 1)) } else { (get(a, 8, 0), get(b, 8, 0)) };
            put(&mut result, 8, 0, low);
            put(&mut result, 8, 1, high);
        }
        SignMask(size) => {
            let a = unary()?;
            let bits = (0..a.len() / size)
                .fold(0u64, |bits, index| bits | (get(a, size, index) >> (8 * size - 1) & 1) << index);
            put(&mut result, out.min(8), 0, bits);
        }
        BlendVariable(size) => {
            if count < 3 {
                return None;
            }
            let (a, b, selector) = (registers[count - 3], registers[count - 2], registers[count - 1]);
            for index in 0..out / size {
                let from_b = get(selector, size, index) >> (8 * size - 1) & 1 == 1;
                put(&mut result, size, index, get(if from_b { b } else { a }, size, index));
            }
        }
        BlendImmediate(size) => {
            let (a, b) = binary()?;
            for index in 0..out / size {
                let from_b = (immediate? >> index) & 1 == 1;
                put(&mut result, size, index, get(if from_b { b } else { a }, size, index));
            }
        }
        BlendWords => {
            let (a, b) = binary()?;
            for index in 0..out / 2 {
                let from_b = (immediate? >> (index % 8)) & 1 == 1;
                put(&mut result, 2, index, get(if from_b { b } else { a }, 2, index));
            }
        }
        SumAbsoluteDifferences => {
            let (a, b) = binary()?;
            for group in 0..out / 8 {
                let sum: u64 =
                    (0..8).map(|index| get(a, 1, group * 8 + index).abs_diff(get(b, 1, group * 8 + index))).sum();
                put(&mut result, 8, group, sum);
            }
        }
        MultiplyAddWords => {
            let (a, b) = binary()?;
            for index in 0..out / 4 {
                let product = |at: usize| signed(get(a, 2, at), 2) * signed(get(b, 2, at), 2);
                put(&mut result, 4, index, (product(2 * index) + product(2 * index + 1)) as u64 & mask(4));
            }
        }
        MultiplyAddBytes => {
            let (a, b) = binary()?;
            for index in 0..out / 2 {
                let product = |at: usize| get(a, 1, at) as i64 * signed(get(b, 1, at), 1);
                put(&mut result, 2, index, saturate_signed(product(2 * index) + product(2 * index + 1), 2));
            }
        }
        MultiplyDoublewords { signed: sign } => {
            let (a, b) = binary()?;
            for index in 0..out / 8 {
                let (x, y) = (get(a, 4, 2 * index), get(b, 4, 2 * index));
                let product = if sign { (signed(x, 4) * signed(y, 4)) as u64 } else { x * y };
                put(&mut result, 8, index, product);
            }
        }
        HorizontalInteger { element, subtract, saturate } => {
            let (a, b) = binary()?;
            let per_lane = lane_bytes / element;
            for lane in 0..lanes {
                let base = lane * per_lane;
                for index in 0..per_lane {
                    let source = if index < per_lane / 2 { a } else { b };
                    let pair = base + 2 * (index % (per_lane / 2));
                    let (x, y) =
                        (signed(get(source, element, pair), element), signed(get(source, element, pair + 1), element));
                    let value = if subtract { x - y } else { x + y };
                    let value = if saturate { saturate_signed(value, element) } else { value as u64 & mask(element) };
                    put(&mut result, element, base + index, value);
                }
            }
        }
        MinimumPosition => {
            let a = unary()?;
            let (position, minimum) =
                (0..8).map(|index| (index, get(a, 2, index))).min_by_key(|&(index, value)| (value, index))?;
            put(&mut result, 2, 0, minimum);
            put(&mut result, 2, 1, position as u64);
        }
        Crc32 => {
            let (crc, data) = binary()?;
            put(&mut result, out.min(8), 0, u64::from(crc32c(get(crc, 4, 0) as u32, data)));
        }
        Move => result.copy_from_slice(&padded(unary()?, out)),
    }
    Some(result)
}

fn shift(value: u64, amount: u64, element: usize, kind: ShiftKind) -> u64 {
    let bits = 8 * element as u64;
    match kind {
        ShiftKind::Left if amount < bits => (value << amount) & mask(element),
        ShiftKind::Right if amount < bits => value >> amount,
        ShiftKind::Arithmetic => (signed(value, element) >> amount.min(bits - 1)) as u64 & mask(element),
        _ => 0,
    }
}

/// `bytes` cut or zero-padded to `length`.
fn padded(bytes: &[u8], length: usize) -> Vec<u8> {
    let mut out = bytes[..bytes.len().min(length)].to_vec();
    out.resize(length, 0);
    out
}
