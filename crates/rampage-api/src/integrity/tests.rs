use super::*;

const CHECK: &[u8] = b"123456789";

/// Known-answer vectors: the catalogue "check" value of each CRC over "123456789", and published values for
/// the others.
#[test]
fn every_algorithm_matches_its_known_answer() {
    let number = |algorithm: Algorithm, bytes: &[u8]| {
        let mut state = algorithm.start(false);
        state.update(bytes);
        state.number().expect("value")
    };
    for (algorithm, expected) in [
        (Algorithm::Crc32, 0xcbf4_3926),
        (Algorithm::Crc32Bzip2, 0xfc89_1918),
        (Algorithm::Crc32Mpeg2, 0x0376_e6e7),
        (Algorithm::Crc32Jamcrc, 0x340b_c6d9),
        (Algorithm::Crc32c, 0xe306_9283),
        (Algorithm::Crc16CcittFalse, 0x29b1),
        (Algorithm::Crc16Xmodem, 0x31c3),
        (Algorithm::Crc16Kermit, 0x2189),
        (Algorithm::Crc16Modbus, 0x4b37),
        (Algorithm::Crc16Arc, 0xbb3d),
        (Algorithm::Crc8Smbus, 0xf4),
        (Algorithm::Crc8Maxim, 0xa1),
        (Algorithm::Adler32, 0x091e_01de),
        (Algorithm::Sum8, 0xdd),
        (Algorithm::Sum8Neg, 0x23),
        (Algorithm::Sum16, 0x01dd),
        (Algorithm::Sum16Neg, 0xfe23),
        (Algorithm::Sum32, 0x01dd),
        (Algorithm::Sum32Neg, 0xffff_fe23),
        (Algorithm::Xor8, 0x31),
    ] {
        assert_eq!(number(algorithm, CHECK), expected, "{}", algorithm.name());
    }
    // Fletcher (Wikipedia's examples); Fletcher-32 over little-endian 16-bit words with a zero-padded tail.
    assert_eq!(number(Algorithm::Fletcher16, b"abcde"), 0xc8f0);
    assert_eq!(number(Algorithm::Fletcher16, b"abcdef"), 0x2057);
    assert_eq!(number(Algorithm::Fletcher32, b"abcde"), 0xf04f_c729);
    assert_eq!(number(Algorithm::Fletcher32, b"abcdef"), 0x5650_2d2a);
    assert_eq!(number(Algorithm::Fletcher32, b"abcdefgh"), 0xebe1_9591);
    // The STM32 CRC unit over the word 0x12345678 (stored little-endian).
    assert_eq!(number(Algorithm::Crc32Mpeg2Words, &[0x78, 0x56, 0x34, 0x12]), 0xdf8a_8a2b);
    // Word sums take the image's byte order; a range that is not whole words has no value.
    let words = [1, 0, 0, 0, 2, 0, 0, 0];
    assert_eq!(number(Algorithm::Sum32Words, &words), 3);
    assert_eq!(number(Algorithm::Sum32WordsNeg, &words), 0xffff_fffd);
    assert_eq!(number(Algorithm::Sum16Words, &words), 3);
    assert_eq!(number(Algorithm::Xor32Words, &words), 3);
    let mut big = Algorithm::Sum32Words.start(true);
    big.update(&words);
    assert_eq!(big.number(), Some(0x0300_0000));
    assert_eq!(Algorithm::Sum32Words.compute(&words[..6], false), None);
    // Digests.
    assert_eq!(hex(&Algorithm::Md5.compute(CHECK, false).unwrap()), "25f9e794323b453885f5181f1b624d0b");
    assert_eq!(
        hex(&Algorithm::Sha256.compute(CHECK, false).unwrap()),
        "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225"
    );
}

/// Reading a state mid-stream and continuing gives the same values as computing each prefix from scratch, for
/// every algorithm, whatever the chunking.
#[test]
fn streaming_reads_equal_whole_computations() {
    let data: Vec<u8> = (0..200u32).map(|index| (index * 37 + 11) as u8).collect();
    for algorithm in ALGORITHMS {
        let mut state = algorithm.start(false);
        let mut at = 0;
        for end in [3usize, 4, 8, 13, 64, 100, 199, 200] {
            state.update(&data[at..end]);
            at = end;
            assert_eq!(state.value(), algorithm.compute(&data[..end], false), "{} at {end}", algorithm.name());
        }
    }
}

fn block(start: u64, bytes: &[u8]) -> Block<'_> {
    Block::new("test".into(), start, bytes)
}

fn search<'a>(blocks: &'a [Block<'a>], constants: &'a BTreeSet<u64>, budget: u64) -> Search<'a> {
    Search {
        blocks,
        big_endian: false,
        constants,
        stats: SearchStats {
            blocks: Vec::new(),
            blocks_omitted: 0,
            algorithms: 0,
            candidate_fields: 0,
            range_starts: 0,
            bytes_hashed: 0,
            budget_bytes: budget,
            budget_exhausted: false,
            skipped_items: 0,
        },
        matches: Vec::new(),
    }
}

/// A boot part padded with 0xff, then an application whose CRC-32 is stored in its last word.
fn image() -> Vec<u8> {
    let mut image: Vec<u8> = (0..0x100u32).map(|index| (index * 7 + 3) as u8).collect();
    image.resize(0x400, 0xff);
    image.extend((0..0x3fcu32).map(|index| (index * 13 + 5) as u8));
    let crc = Algorithm::Crc32.compute(&image[0x400..0x7fc], false).unwrap();
    image.extend(crc);
    image
}

#[test]
fn brute_force_finds_a_crc_after_padding_and_stops_at_its_budget() {
    let image = image();
    let blocks = [block(0x0800_0000, &image)];
    let constants = BTreeSet::new();
    let mut found = search(&blocks, &constants, SEARCH_BUDGET_BYTES);
    found.run(&ALGORITHMS);
    let checks = select(found.matches, &CodeEvidence::default());
    let best = &checks[0];
    assert_eq!(
        (best.algorithm, best.field, best.range, best.endian),
        (Some(Algorithm::Crc32), 0x0800_07fc, (0x0800_0400, 0x0800_07fc), Endian::Little),
        "{checks:?}"
    );
    assert!(!found.stats.budget_exhausted);
    // A budget below one stream over the image skips every item and says so.
    let mut starved = search(&blocks, &constants, 0x100);
    starved.run(&ALGORITHMS);
    assert!(starved.matches.is_empty() && starved.stats.budget_exhausted && starved.stats.skipped_items > 0);
    assert_eq!(starved.stats.bytes_hashed, 0);
}

#[test]
fn a_crc_that_covers_another_checks_value_is_fixed_after_it() {
    let check = |field: u64, range: (u64, u64)| Found {
        algorithm: Some(Algorithm::Crc32),
        field,
        endian: Endian::Little,
        range,
        score: 0.9,
        emulated: false,
        evidence: Vec::new(),
        alternatives: 0,
    };
    // 0 covers 1's value, 1 covers 2's value: fix 2, then 1, then 0.
    let checks = [check(0x1000, (0x100, 0x900)), check(0x800, (0x400, 0x7f8)), check(0x7f0, (0x500, 0x600))];
    assert_eq!(fix_order(&checks, &[true; 3]).unwrap(), [2, 1, 0]);
    assert_eq!(fix_order(&checks, &[true, false, true]).unwrap(), [2, 0]);
    let cycle = [check(0x100, (0x200, 0x300)), check(0x200, (0x100, 0x110))];
    assert!(fix_order(&cycle, &[true; 2]).unwrap_err().contains("cycle"));
    assert_eq!(fix_order(&cycle, &[true, false]).unwrap(), [0]);
}

#[test]
fn pe_checksum_matches_the_reference_algorithm() {
    // A minimal PE-shaped buffer: MZ, e_lfanew = 0x40, PE signature, CheckSum at 0x40 + 24 + 64.
    let mut bytes = vec![0u8; 0x200];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c] = 0x40;
    bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
    for (index, byte) in bytes.iter_mut().enumerate().skip(0x100) {
        *byte = index as u8;
    }
    let field = pe_checksum_offset(&bytes).unwrap();
    assert_eq!(field, 0x40 + 88);
    // Reference: 16-bit word sum with carries folded, the field taken as zero, plus the length.
    let mut sum: u32 = 0;
    for (index, pair) in bytes.chunks(2).enumerate() {
        if (field..field + 4).contains(&(index * 2)) {
            continue;
        }
        sum += u32::from(u16::from_le_bytes([pair[0], pair[1]]));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    assert_eq!(pe_checksum(&bytes, field), sum + bytes.len() as u32);
    // The field's current value never matters.
    bytes[field..field + 4].copy_from_slice(&[1, 2, 3, 4]);
    assert_eq!(pe_checksum(&bytes, field), sum + bytes.len() as u32);
}
