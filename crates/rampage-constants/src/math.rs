//! Just enough arbitrary-precision arithmetic to derive constants from their definitions: integer roots (the
//! SHA-2, SHA-1 and RIPEMD constants) and the hexadecimal digits of pi (the Blowfish initial state).

use std::cmp::Ordering;

/// An unsigned integer as little-endian 32-bit limbs.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Big(Vec<u32>);

impl Big {
    fn from_u128(value: u128) -> Self {
        Self((0..4).map(|limb| (value >> (32 * limb)) as u32).collect()).trimmed()
    }

    fn trimmed(mut self) -> Self {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
        self
    }

    fn shl(&self, bits: usize) -> Self {
        let (limbs, bits) = (bits / 32, bits % 32);
        let mut out = vec![0u32; limbs];
        let mut carry = 0u32;
        for &limb in &self.0 {
            out.push(if bits == 0 { limb } else { limb << bits | carry });
            carry = if bits == 0 { 0 } else { limb >> (32 - bits) };
        }
        out.push(carry);
        Self(out).trimmed()
    }

    fn mul(&self, other: &Self) -> Self {
        let mut out = vec![0u32; self.0.len() + other.0.len()];
        for (i, &a) in self.0.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.0.iter().enumerate() {
                let sum = u64::from(a) * u64::from(b) + u64::from(out[i + j]) + carry;
                out[i + j] = sum as u32;
                carry = sum >> 32;
            }
            out[i + other.0.len()] = carry as u32;
        }
        Self(out).trimmed()
    }

    fn compare(&self, other: &Self) -> Ordering {
        self.0.len().cmp(&other.0.len()).then_with(|| self.0.iter().rev().cmp(other.0.iter().rev()))
    }

    fn bit_len(&self) -> usize {
        self.0.last().map_or(0, |top| 32 * self.0.len() - top.leading_zeros() as usize)
    }
}

/// `floor((n * 2^shift)^(1/k))`, which must fit in a `u128`.
fn root(n: u64, shift: usize, k: u32) -> u128 {
    let target = Big::from_u128(u128::from(n)).shl(shift);
    let bits = target.bit_len().div_ceil(k as usize);
    assert!(bits < 128, "root does not fit in u128");
    let mut result = 0u128;
    for bit in (0..=bits).rev() {
        let candidate = result | 1 << bit;
        let big = Big::from_u128(candidate);
        let power = (1..k).fold(big.clone(), |acc, _| acc.mul(&big));
        if power.compare(&target) != Ordering::Greater {
            result = candidate;
        }
    }
    result
}

/// The first `bits` bits of the fractional part of the `k`-th root of `n`.
pub fn fractional_root(n: u64, k: u32, bits: usize) -> u64 {
    let mask = if bits == 64 { u128::from(u64::MAX) } else { (1u128 << bits) - 1 };
    (root(n, bits * k as usize, k) & mask) as u64
}

/// `floor(2^shift * n^(1/k))`, the form SHA-1 and RIPEMD use for their round constants (shift 30).
pub fn scaled_root(n: u64, k: u32, shift: usize) -> u32 {
    root(n, shift * k as usize, k) as u32
}

pub fn first_primes(count: usize) -> Vec<u64> {
    let mut primes = Vec::with_capacity(count);
    let mut candidate = 2u64;
    while primes.len() < count {
        if primes.iter().take_while(|&&p| p * p <= candidate).all(|&p| !candidate.is_multiple_of(p)) {
            primes.push(candidate);
        }
        candidate += 1;
    }
    primes
}

/// A fixed-point fraction with `limbs` 32-bit limbs below the binary point and one integer limb above it.
struct Fixed(Vec<u32>);

impl Fixed {
    fn one(limbs: usize) -> Self {
        let mut value = vec![0u32; limbs + 1];
        value[limbs] = 1;
        Self(value)
    }

    fn is_zero(&self) -> bool {
        self.0.iter().all(|&limb| limb == 0)
    }

    fn div_small(&self, divisor: u32) -> Self {
        let mut out = vec![0u32; self.0.len()];
        let mut remainder = 0u64;
        for (index, &limb) in self.0.iter().enumerate().rev() {
            let current = remainder << 32 | u64::from(limb);
            out[index] = (current / u64::from(divisor)) as u32;
            remainder = current % u64::from(divisor);
        }
        Self(out)
    }

    fn mul_small(&self, factor: u32) -> Self {
        let mut carry = 0u64;
        let out = self
            .0
            .iter()
            .map(|&limb| {
                let product = u64::from(limb) * u64::from(factor) + carry;
                carry = product >> 32;
                product as u32
            })
            .collect();
        Self(out)
    }

    fn add_assign(&mut self, other: &Self) {
        let mut carry = 0u64;
        for (limb, &addend) in self.0.iter_mut().zip(&other.0) {
            let sum = u64::from(*limb) + u64::from(addend) + carry;
            *limb = sum as u32;
            carry = sum >> 32;
        }
    }

    fn sub_assign(&mut self, other: &Self) {
        let mut borrow = 0i64;
        for (limb, &subtrahend) in self.0.iter_mut().zip(&other.0) {
            let difference = i64::from(*limb) - i64::from(subtrahend) - borrow;
            *limb = difference.rem_euclid(1 << 32) as u32;
            borrow = i64::from(difference < 0);
        }
    }

    /// `arctan(1/x)` by its Taylor series.
    fn arctan_inverse(x: u32, limbs: usize) -> Self {
        let mut power = Self::one(limbs).div_small(x);
        let mut sum = Self(power.0.clone());
        let mut term = 1u32;
        while !power.is_zero() {
            power = power.div_small(x * x);
            let next = power.div_small(2 * term + 1);
            if term % 2 == 1 {
                sum.sub_assign(&next);
            } else {
                sum.add_assign(&next);
            }
            term += 1;
        }
        sum
    }
}

/// The first `words` 32-bit words of the hexadecimal fraction of pi (`0x243f6a88, 0x85a308d3, ...`).
pub fn pi_fraction_words(words: usize) -> Vec<u32> {
    // Two guard limbs absorb the truncation error accumulated over the series' few thousand divisions.
    let limbs = words + 2;
    // Machin: pi = 16 arctan(1/5) - 4 arctan(1/239).
    let mut pi = Fixed::arctan_inverse(5, limbs).mul_small(16);
    pi.sub_assign(&Fixed::arctan_inverse(239, limbs).mul_small(4));
    pi.0[..limbs].iter().rev().take(words).copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_match_known_constants() {
        assert_eq!(fractional_root(2, 2, 32), 0x6a09_e667);
        assert_eq!(fractional_root(2, 3, 32), 0x428a_2f98);
        assert_eq!(fractional_root(2, 2, 64), 0x6a09_e667_f3bc_c908);
        assert_eq!(scaled_root(2, 2, 30), 0x5a82_7999);
        assert_eq!(scaled_root(2, 3, 30), 0x50a2_8be6);
        assert_eq!(first_primes(8), [2, 3, 5, 7, 11, 13, 17, 19]);
    }

    #[test]
    fn pi_digits_start_correctly() {
        let words = pi_fraction_words(4);
        assert_eq!(words, [0x243f_6a88, 0x85a3_08d3, 0x1319_8a2e, 0x0370_7344]);
    }
}
