/// Shannon entropy of `bytes` in bits per byte, from 0.0 (one repeated value) to 8.0 (uniform); 0.0 when empty.
/// Unrounded, so callers comparing against thresholds see the exact value.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }
    let total = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_spans_zero_to_eight_bits() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[7; 100]), 0.0);
        assert_eq!(shannon_entropy(&[0, 1, 0, 1]), 1.0);
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(shannon_entropy(&all), 8.0);
        let skewed = shannon_entropy(&[0, 0, 0, 1]);
        assert!((skewed - 0.811_278_124_459_132_9).abs() < 1e-15, "{skewed}");
    }
}
