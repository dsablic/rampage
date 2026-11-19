//! IEEE binary32/binary64 and x87 80-bit extended values as raw bits: exact conversions between them and integers,
//! with round-to-nearest-even (the default rounding mode; no other mode is modelled).

use std::cmp::Ordering;

/// A finite nonzero value `mantissa * 2^exponent` with the mantissa's top bit set (bit 63), or a special.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Unpacked {
    Zero {
        negative: bool,
    },
    Finite {
        negative: bool,
        mantissa: u64,
        exponent: i32,
    },
    Infinity {
        negative: bool,
    },
    /// The fraction (quiet bit first), left-aligned in 64 bits, and the sign.
    Nan {
        negative: bool,
        payload: u64,
    },
}

/// A binary interchange format: fraction bits (without the implicit bit) and exponent bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Format {
    fraction: u32,
    exponent: u32,
    /// x87 extended stores its integer bit.
    explicit: bool,
}

pub(crate) const SINGLE: Format = Format { fraction: 23, exponent: 8, explicit: false };
pub(crate) const DOUBLE: Format = Format { fraction: 52, exponent: 11, explicit: false };
pub(crate) const EXTENDED: Format = Format { fraction: 63, exponent: 15, explicit: true };

/// The format of a `bytes`-byte float, for the sizes the interpreter handles.
pub(crate) fn format(bytes: u32) -> Option<Format> {
    match bytes {
        4 => Some(SINGLE),
        8 => Some(DOUBLE),
        10 => Some(EXTENDED),
        _ => None,
    }
}

impl Format {
    fn bias(self) -> i32 {
        (1 << (self.exponent - 1)) - 1
    }

    fn max_exponent(self) -> u64 {
        (1 << self.exponent) - 1
    }

    fn sign_bit(self) -> u32 {
        self.fraction + self.exponent + u32::from(self.explicit)
    }

    pub fn unpack(self, bits: u128) -> Unpacked {
        let negative = (bits >> self.sign_bit()) & 1 == 1;
        let stored = (bits >> (self.fraction + u32::from(self.explicit))) as u64 & self.max_exponent();
        let fraction = bits as u64 & ((1u64 << self.fraction) - 1);
        if stored == self.max_exponent() {
            if fraction == 0 {
                return Unpacked::Infinity { negative };
            }
            return Unpacked::Nan { negative, payload: fraction << (64 - self.fraction) };
        }
        // Without an explicit bit, a normal value's integer bit is implied; an x87 unnormal keeps what is stored.
        let integer = if self.explicit { (bits >> 63) as u64 & 1 } else { u64::from(stored != 0) };
        let significand = (integer << self.fraction) | fraction;
        if significand == 0 {
            return Unpacked::Zero { negative };
        }
        let exponent = stored.max(1) as i32 - self.bias() - self.fraction as i32;
        let shift = significand.leading_zeros();
        Unpacked::Finite { negative, mantissa: significand << shift, exponent: exponent - shift as i32 }
    }

    /// Encodes `value`, rounding a finite one to nearest, ties to even.
    pub fn pack(self, value: Unpacked) -> u128 {
        let sign = |negative: bool| u128::from(negative) << self.sign_bit();
        let exponent_field = |stored: u64| u128::from(stored) << (self.fraction + u32::from(self.explicit));
        let explicit = |bits: u128, set: bool| if self.explicit && set { bits | (1 << 63) } else { bits };
        match value {
            Unpacked::Zero { negative } => sign(negative),
            Unpacked::Infinity { negative } => explicit(sign(negative) | exponent_field(self.max_exponent()), true),
            Unpacked::Nan { negative, payload } => {
                let fraction = (payload >> (64 - self.fraction)) | (1 << (self.fraction - 1));
                explicit(sign(negative) | exponent_field(self.max_exponent()) | u128::from(fraction), true)
            }
            Unpacked::Finite { negative, mantissa, exponent } => {
                // value = mantissa * 2^exponent, mantissa in [2^63, 2^64): its unbiased exponent is exponent + 63.
                let unbiased = exponent + 63;
                let minimum = 1 - self.bias();
                let width = self.fraction + 1;
                // Keep `width` bits for a normal result, fewer for a subnormal one.
                let drop = 64 - width as i64 + i64::from((minimum - unbiased).max(0));
                let rounded = round_shift(u128::from(mantissa), drop);
                let (mut stored, mut significand) =
                    if unbiased >= minimum { (unbiased + self.bias(), rounded) } else { (0, rounded) };
                if significand >> width != 0 {
                    // Rounding carried into a new bit.
                    significand >>= 1;
                    stored += 1;
                } else if stored == 0 && significand >> self.fraction != 0 {
                    // A subnormal that rounded up to the smallest normal.
                    stored = 1;
                }
                if stored as u64 >= self.max_exponent() {
                    return self.pack(Unpacked::Infinity { negative });
                }
                if significand == 0 {
                    return sign(negative);
                }
                let fraction = significand & ((1 << self.fraction) - 1);
                explicit(sign(negative) | exponent_field(stored as u64) | fraction, significand >> self.fraction != 0)
            }
        }
    }
}

/// `value >> shift`, rounded to nearest, ties to even.
fn round_shift(value: u128, shift: i64) -> u128 {
    if shift <= 0 {
        return value << (-shift).min(127);
    }
    if shift > 128 {
        return 0;
    }
    let shift = shift as u32;
    let quotient = if shift == 128 { 0 } else { value >> shift };
    let remainder = if shift == 128 { value } else { value & ((1 << shift) - 1) };
    let half = 1u128 << (shift - 1);
    if remainder > half || (remainder == half && quotient & 1 == 1) { quotient + 1 } else { quotient }
}

/// Converts between formats exactly, or rounded to nearest even when narrowing.
pub(crate) fn convert(bits: u128, from: Format, to: Format) -> u128 {
    to.pack(from.unpack(bits))
}

/// The signed integer `value` in `format`, rounded to nearest even.
pub(crate) fn from_integer(value: i128, format: Format) -> u128 {
    if value == 0 {
        return format.pack(Unpacked::Zero { negative: false });
    }
    let negative = value < 0;
    let magnitude = value.unsigned_abs();
    let shift = magnitude.leading_zeros();
    let normalized = magnitude << shift;
    // The top 64 bits; the lower half only matters for rounding.
    let top = (normalized >> 64) as u64;
    let exponent = 64 - shift as i32;
    if normalized as u64 == 0 {
        return format.pack(Unpacked::Finite { negative, mantissa: top, exponent });
    }
    if format.fraction + 1 >= 64 {
        // Extended: round the 128-bit magnitude to 64 bits directly.
        let rounded = round_shift(normalized, 64);
        return if rounded >> 64 != 0 {
            format.pack(Unpacked::Finite { negative, mantissa: 1 << 63, exponent: exponent + 1 })
        } else {
            format.pack(Unpacked::Finite { negative, mantissa: rounded as u64, exponent })
        };
    }
    // Narrower formats drop at least 11 bits of `top`, so its lowest bit can stand for the dropped lower half.
    format.pack(Unpacked::Finite { negative, mantissa: top | 1, exponent })
}

/// How a float becomes an integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rounding {
    Nearest,
    Down,
    Up,
    Toward0,
    /// To nearest, ties away from zero (ARM `vcvta`).
    TiesAway,
}

/// `bits` rounded to an integral value in its own format (`Unpacked` of the result).
pub(crate) fn round_integral(bits: u128, format: Format, rounding: Rounding) -> u128 {
    let (negative, mantissa, exponent) = match format.unpack(bits) {
        Unpacked::Finite { negative, mantissa, exponent } => (negative, mantissa, exponent),
        // A signalling NaN comes back quiet, as the instructions return it.
        nan @ Unpacked::Nan { .. } => return format.pack(nan),
        _ => return bits,
    };
    if exponent >= 0 {
        return bits;
    }
    let shift = (-exponent) as u32;
    let (integer, fraction_nonzero, above_half, half) = if shift > 64 {
        (0u128, true, false, false)
    } else {
        let value = u128::from(mantissa);
        let integer = value >> shift;
        let fraction = value & ((1u128 << shift) - 1);
        let half = 1u128 << (shift - 1);
        (integer, fraction != 0, fraction > half, fraction == half)
    };
    let up = match rounding {
        Rounding::Nearest => above_half || (half && integer & 1 == 1),
        Rounding::TiesAway => above_half || half,
        Rounding::Toward0 => false,
        Rounding::Down => negative && fraction_nonzero,
        Rounding::Up => !negative && fraction_nonzero,
    };
    let integer = integer + u128::from(up);
    if integer == 0 {
        return format.pack(Unpacked::Zero { negative });
    }
    let magnitude = from_integer(integer as i128, format);
    magnitude | (u128::from(negative) << format.sign_bit())
}

/// `bits` truncated toward zero to an integer, or `None` when it is NaN, infinite or does not fit in 127 bits.
pub(crate) fn to_integer(bits: u128, format: Format) -> Option<i128> {
    match format.unpack(bits) {
        Unpacked::Zero { .. } => Some(0),
        Unpacked::Finite { negative, mantissa, exponent } => {
            let magnitude = if exponent >= 0 {
                if exponent > 63 {
                    return None;
                }
                u128::from(mantissa) << exponent
            } else if exponent <= -64 {
                0
            } else {
                u128::from(mantissa >> (-exponent))
            };
            let value = i128::try_from(magnitude).ok()?;
            Some(if negative { -value } else { value })
        }
        _ => None,
    }
}

/// IEEE comparison: `None` when either is NaN.
pub(crate) fn compare(a: u128, b: u128, format: Format) -> Option<Ordering> {
    let key = |value: Unpacked| -> Option<(i32, i128)> {
        // Sign, then magnitude as (exponent, mantissa) for finite values; infinities beyond every exponent.
        match value {
            Unpacked::Nan { .. } => None,
            Unpacked::Zero { .. } => Some((0, 0)),
            Unpacked::Infinity { negative } => Some(if negative { (-1, i128::MIN) } else { (1, i128::MAX) }),
            Unpacked::Finite { negative, mantissa, exponent } => {
                let magnitude = (i128::from(exponent + 20_000) << 64) | i128::from(mantissa);
                Some(if negative { (-1, -magnitude) } else { (1, magnitude) })
            }
        }
    };
    // Negatives order by negated magnitude, so a larger magnitude sorts first.
    Some(key(format.unpack(a))?.cmp(&key(format.unpack(b))?))
}

/// `bits` as an `f64`, rounded to nearest when the format is wider.
pub(crate) fn to_f64(bits: u128, format: Format) -> f64 {
    f64::from_bits(convert(bits, format, DOUBLE) as u64)
}

/// `value` in `format`, rounded to nearest when narrower.
pub(crate) fn from_f64(value: f64, format: Format) -> u128 {
    convert(u128::from(value.to_bits()), DOUBLE, format)
}

pub(crate) fn is_nan(bits: u128, format: Format) -> bool {
    matches!(format.unpack(bits), Unpacked::Nan { .. })
}

pub(crate) fn negate(bits: u128, format: Format) -> u128 {
    bits ^ (1 << format.sign_bit())
}

pub(crate) fn absolute(bits: u128, format: Format) -> u128 {
    bits & !(1 << format.sign_bit())
}
