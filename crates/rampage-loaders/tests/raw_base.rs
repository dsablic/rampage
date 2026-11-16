//! Load-address candidates for Raw Cortex-M images, checked against the fixtures' ELFs.

use std::path::Path;
use std::time::{Duration, Instant};

use rampage_loaders::Binary;
use rampage_loaders::raw_base::{BaseConfidence, BaseHint, BaseMethod, BaseVerdict, base_candidates, check_base};

const FIRMWARE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/");

/// Fixtures with self-pointers or self-referencing constants besides the vector table.
const STRIPPED: [&str; 10] = [
    "raw-cortex-m",
    "raw-cortex-m-tables",
    "raw-cortex-m-stages",
    "raw-cortex-m-stages-lzss",
    "raw-cortex-m-strings",
    "raw-cortex-m-crc",
    "raw-cortex-m-locks",
    "embedded-libs-m0",
    "embedded-libs-m4f",
    "elf-cortex-m-crc32",
];

/// The image bytes and the base the ELF links them at: its lowest read-only mapping with file bytes.
fn fixture(name: &str) -> (Vec<u8>, u64) {
    let bytes = std::fs::read(format!("{FIRMWARE}{name}.bin")).unwrap();
    let elf = Binary::open(Path::new(&format!("{FIRMWARE}{name}.elf"))).unwrap();
    let base = elf
        .segments
        .iter()
        .filter(|segment| segment.file_size > 0 && !segment.perms.write)
        .map(|segment| segment.address)
        .min()
        .unwrap();
    (bytes, base)
}

/// Zeroes the vector table at offset 0: the initial SP and every following empty word or odd word inside the image.
fn strip_vector_table(bytes: &mut [u8], base: u64) {
    let end = base + bytes.len() as u64;
    for index in 0..bytes.len() / 4 {
        let word = u64::from(u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap()));
        if index > 0 && word != 0 && !(word & 1 == 1 && (base..end).contains(&word)) {
            break;
        }
        bytes[index * 4..index * 4 + 4].fill(0);
    }
}

#[test]
fn the_linked_base_ranks_first_without_a_vector_table() {
    for name in STRIPPED {
        let (mut bytes, base) = fixture(name);
        strip_vector_table(&mut bytes, base);
        let found = base_candidates(&bytes, None, &[]);
        let first = found.candidates.first().unwrap_or_else(|| panic!("{name}: no candidate"));
        assert_eq!(first.base_address, base, "{name}: {found:#?}");
        assert!(!first.methods.contains(&BaseMethod::VectorTable), "{name}");
    }
}

#[test]
fn a_vector_table_at_offset_0_names_the_base() {
    for name in STRIPPED.iter().chain(&["raw-cortex-m-scatter-gcc", "raw-cortex-m-scatter-table"]) {
        let (bytes, base) = fixture(name);
        let found = base_candidates(&bytes, None, &[]);
        let first = &found.candidates[0];
        assert_eq!(first.base_address, base, "{name}: {found:#?}");
        assert!(first.methods.contains(&BaseMethod::VectorTable), "{name}");
    }
}

#[test]
fn a_wrong_base_is_named_with_the_linked_one() {
    let (mut bytes, base) = fixture("raw-cortex-m-tables");
    strip_vector_table(&mut bytes, base);
    let wrong = 0x0100_0000;
    let check = check_base(&bytes, wrong, None, std::slice::from_ref(&(wrong..wrong + bytes.len() as u64)), None);
    assert_eq!(check.verdict, BaseVerdict::LooksWrong, "{check:#?}");
    assert_eq!(check.better_candidate.as_ref().unwrap().base_address, base);
    assert!(check.next.as_deref().unwrap().contains(&format!("{base:#x}")), "{:?}", check.next);
    let right = check_base(&bytes, base, None, std::slice::from_ref(&(base..base + bytes.len() as u64)), None);
    assert_eq!(right.verdict, BaseVerdict::Consistent, "{right:#?}");
    assert!(right.better_candidate.is_none() && right.next.is_none());
}

#[test]
fn a_hint_joins_the_ranking_with_its_source() {
    let (mut bytes, base) = fixture("raw-cortex-m-stages");
    strip_vector_table(&mut bytes, base);
    let hint = BaseHint { base_address: base, source: "record words at 0x10 and 0x20".into() };
    let found = base_candidates(&bytes, None, std::slice::from_ref(&hint));
    let first = &found.candidates[0];
    assert_eq!(first.base_address, base);
    assert!(first.methods.contains(&BaseMethod::Hint));
    assert_eq!(first.evidence.hints, [hint.source]);
    assert_ne!(first.confidence, BaseConfidence::Weak);
}

fn xorshift(length: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// 4 MiB of erased flash, noise, one repeated word, and distinct odd words that are all `push {…, lr}` prologues
/// (the most votes per word): bounded work, and no candidate is strong except where the words really do point at
/// prologues.
#[test]
fn hostile_images_stay_bounded_and_give_no_strong_candidate() {
    const LENGTH: usize = 4 << 20;
    let budget = if cfg!(debug_assertions) { Duration::from_secs(20) } else { Duration::from_millis(200) };
    let pushes: Vec<u8> = (0..LENGTH as u32 / 4).flat_map(|index| (0xb500_0001 | index << 1).to_le_bytes()).collect();
    let cases = [
        ("erased", vec![0xff; LENGTH], false),
        ("random", xorshift(LENGTH), false),
        ("one word", [0x01, 0xb5, 0x01, 0xb5].repeat(LENGTH / 4), false),
        ("prologue words", pushes, true),
    ];
    for (name, bytes, structured) in cases {
        let start = Instant::now();
        let found = base_candidates(&bytes, None, &[]);
        let took = start.elapsed();
        assert!(took < budget, "{name}: {took:?}");
        assert!(found.votes <= 1 << 23, "{name}: {}", found.votes);
        if !structured {
            assert!(found.strong().is_none(), "{name}: {:#?}", found.candidates.first());
        }
        let check = check_base(
            &bytes,
            0x0800_0000,
            None,
            std::slice::from_ref(&(0x0800_0000..0x0800_0000 + LENGTH as u64)),
            None,
        );
        if !structured {
            assert_ne!(check.verdict, BaseVerdict::LooksWrong, "{name}: {check:#?}");
        }
    }
}
