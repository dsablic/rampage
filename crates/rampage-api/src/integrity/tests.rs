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
            lookups: 0,
            lookup_budget: SEARCH_LOOKUP_BUDGET,
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
    let (checks, _) = select(found.matches, &CodeEvidence::default());
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
    // The lookup budget stops the comparisons independently of the byte budget, and says so.
    let mut capped = search(&blocks, &constants, SEARCH_BUDGET_BYTES);
    capped.stats.lookup_budget = 3;
    capped.run(&ALGORITHMS);
    assert_eq!(capped.stats.lookups, 3);
    assert!(capped.stats.budget_exhausted && capped.stats.skipped_items > 0);
}

/// A value inside a higher-scored check's range is dropped as a chance match on its bytes, unless code references
/// it.
#[test]
fn values_inside_a_stronger_checks_range_are_dropped_unless_code_references_them() {
    let found = |algorithm, field, range| Match { algorithm, field, endian: Endian::Little, range, adjacent: true };
    let strong = found(Algorithm::Crc32, 0x7fc, (0x400, 0x7fc));
    let weak = found(Algorithm::Sum8, 0x500, (0x440, 0x500));
    let (checks, dropped) = select(vec![strong.clone(), weak.clone()], &CodeEvidence::default());
    assert_eq!(checks.iter().map(|check| check.field).collect::<Vec<_>>(), [0x7fc]);
    assert_eq!(dropped.iter().map(|check| check.field).collect::<Vec<_>>(), [0x500]);
    // A weak value whose range ends at the stronger check's code-referenced field does not borrow that reference.
    let code = CodeEvidence { constants: BTreeSet::from([0x7fc]), ..CodeEvidence::default() };
    let borrowed = found(Algorithm::Sum8, 0x500, (0x501, 0x7fc));
    let (checks, _) = select(vec![strong.clone(), borrowed], &code);
    assert_eq!(checks.iter().map(|check| check.field).collect::<Vec<_>>(), [0x7fc]);
    let code = CodeEvidence { constants: BTreeSet::from([0x500]), ..CodeEvidence::default() };
    let referenced = weak;
    let (checks, _) = select(vec![strong, referenced], &code);
    assert_eq!(checks.len(), 2);
    assert!(checks[1].code_bound);
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
        routine: None,
        code_bound: false,
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

/// CRC-16 polynomials formed by one immediate: a lone Thumb `movw` (not one completed by a `movt`), a Thumb `mov.w`
/// modified immediate, and A32 `movw`/`mov`.
#[test]
fn single_immediates_are_decoded_in_thumb_and_a32() {
    let halfwords = |values: &[u16]| values.iter().flat_map(|value| value.to_le_bytes()).collect::<Vec<u8>>();
    // movw r12, #0xa001; movw r0, #0x1021; movt r0, #0x1234; mov.w r3, #0x00ab00ab
    let thumb = halfwords(&[0xf24a, 0x0c01, 0xf241, 0x0021, 0xf2c1, 0x2034, 0xf04f, 0x13ab]);
    let found = thumb_narrow_constants(&thumb, 0x1000);
    assert!(found.contains(&(0x1000, 0xa001)), "{found:x?}");
    assert!(found.contains(&(0x100c, 0x00ab_00ab)), "{found:x?}");
    assert!(!found.iter().any(|(_, value)| *value == 0x1021), "movw completed by movt is a 32-bit value: {found:x?}");
    assert_eq!(thumb_expand_immediate(0xc20), 0xa000);
    assert_eq!(thumb_expand_immediate(0x3ab), 0xabab_abab);
    // movw r1, #0x8408; mov r2, #0xff000000; an unconditional-space word is not decoded; movw r0, #0x1021 completed by
    // movt r0, #0x1234 is the 32-bit value 0x12341021, not a CRC-16 polynomial; movw r3, #0xa001 then movt r4 stays.
    let words = [0xe308_1408u32, 0xe3a0_24ff, 0xf308_1408, 0xe301_0021, 0xe341_0234, 0xe30a_3001, 0xe341_4234];
    let a32: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    assert_eq!(arm_narrow_constants(&a32, 0x2000), [(0x2000, 0x8408), (0x2004, 0xff00_0000), (0x2014, 0xa001)]);
}

/// The routine that confirmed a check runs again over the range as a fix leaves it: it agrees with the recomputed
/// value, the fix's earlier writes included; it disagrees when the value was computed over other bytes than it reads;
/// and with no routine, or one that cannot run, the check is unconfirmed rather than an error.
#[test]
fn device_checks_agree_disagree_or_stay_unconfirmed() {
    const FIRMWARE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m-crc");
    const BASE: u64 = 0x0800_0000;
    let image = std::fs::read(format!("{FIRMWARE}.bin")).unwrap();
    let options = rampage_loaders::RawCodeOptions {
        profile: rampage_loaders::RawProfile::CortexM,
        base: BASE,
        entry: None,
        seeds: vec![],
        vector_table: Some(BASE),
        pointer_tables: false,
    };
    let project = Project::new(Binary::from_raw_code(image.clone(), options).unwrap());
    let elf = Binary::open(format!("{FIRMWARE}.elf")).unwrap();
    let routine = elf.symbol_by_name("crc32_compute").unwrap().address & !1;
    let check = |routine: Option<(u64, bool)>| Found {
        algorithm: Some(Algorithm::Crc32),
        field: BASE + 0x7fc,
        endian: Endian::Little,
        range: (BASE + 0x400, BASE + 0x7fc),
        score: 0.98,
        emulated: true,
        routine,
        code_bound: false,
        evidence: Vec::new(),
        alternatives: 0,
    };
    let located = check(Some((routine, true)));
    let blocks = [block(BASE, &image)];
    let result = device_check(&project, &located, &blocks, &[]);
    assert_eq!(result.status, "agrees", "{result:?}");

    let mut changed = image.clone();
    changed[0x500] ^= 0xff;
    let changed_blocks = [block(BASE, &changed)];
    let result = device_check(&project, &located, &changed_blocks, &[(BASE + 0x500, vec![changed[0x500]])]);
    assert_eq!(result.status, "agrees", "{result:?}");
    let result = device_check(&project, &located, &changed_blocks, &[]);
    assert_eq!(result.status, "disagrees", "{result:?}");

    let result = device_check(&project, &check(None), &blocks, &[]);
    assert_eq!(result.status, "unconfirmed", "{result:?}");
    let result = device_check(&project, &check(Some((BASE + 0x10_0000, true))), &blocks, &[]);
    assert_eq!(result.status, "unconfirmed", "{result:?}");
    assert!(result.detail.contains("could not run") || result.detail.contains("did not return"), "{result:?}");
}

/// Suite v4 (1.9.0): an agent converted little-endian `computed_hex` to the wrong integer by hand; the report gives
/// the integer at the field's byte order, exact as a JSON number, and a `0x` string past 2^53-1.
#[test]
fn field_values_read_the_bytes_at_their_width_and_byte_order() {
    let bytes = [0xa1, 0x0f, 0x98, 0xc2];
    assert_eq!(field_value(&bytes, Endian::Little), Some(Value::from(0xc298_0fa1_u64)));
    assert_eq!(field_value(&bytes, Endian::Big), Some(Value::from(0xa10f_98c2_u64)));
    assert_eq!(field_value(&[0x7f], Endian::Bytes), Some(Value::from(0x7f)));
    assert_eq!(field_value(&[0x12, 0x34], Endian::Little), Some(Value::from(0x3412)));
    assert_eq!(field_value(&[0xff; 8], Endian::Big), Some(Value::from("0xffffffffffffffff")));
    assert_eq!(field_value(&[0; 16], Endian::Bytes), None);
    assert_eq!(field_value(&[], Endian::Little), None);
}
