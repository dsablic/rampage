//! Cross-program identification on the committed musl fixtures, scheme 1 against scheme 2. This crate cannot run
//! function discovery, so extents come from two stand-ins that treat both schemes identically: the eval truth's
//! function starts (`eval-target-*`), and the targets of direct calls found by a linear sweep (`musl-static-*`,
//! which has no truth). Each extent runs to the next start, minus trailing x86 `int3` padding.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use iced_x86::{Decoder, DecoderOptions, FlowControl};
use rampage_arch::Arch;
use rampage_loaders::{Binary, SymbolKind};
use rampage_signatures::{CURRENT_SCHEME, LEGACY_SCHEME, MaskContext, SignatureDb, bundled};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn open(name: &str) -> Binary {
    Binary::open(fixtures().join("bin").join(name)).unwrap()
}

/// Function starts and names from an eval truth file.
fn truth(arch: &str) -> BTreeMap<u64, String> {
    let text = std::fs::read_to_string(fixtures().join(format!("data/eval-truth-{arch}.json"))).unwrap();
    let raw: BTreeMap<String, String> = serde_json::from_str(&text).unwrap();
    raw.into_iter().map(|(key, name)| (u64::from_str_radix(&key[2..], 16).unwrap(), name)).collect()
}

/// The executable segments of `binary`.
fn code(binary: &Binary) -> Vec<(u64, u64)> {
    let segments = binary.segments.iter().filter(|segment| segment.perms.execute && segment.size > 0);
    segments.map(|segment| (segment.address, segment.address + segment.size)).collect()
}

/// Direct call targets inside executable segments, found by a linear sweep.
fn call_targets(binary: &Binary) -> BTreeSet<u64> {
    let mut targets = BTreeSet::new();
    for (start, end) in code(binary) {
        let Some(bytes) = binary.read(start, end - start) else { continue };
        if binary.arch == Arch::Aarch64 {
            for (index, word) in bytes.as_chunks::<4>().0.iter().enumerate() {
                let word = u32::from_le_bytes(*word);
                if word & 0xfc00_0000 == 0x9400_0000 {
                    let offset = i64::from(((word & 0x03ff_ffff) << 6) as i32 >> 6) * 4;
                    targets.insert((start + index as u64 * 4).wrapping_add_signed(offset));
                }
            }
        } else {
            let decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
            for instruction in decoder {
                if instruction.flow_control() == FlowControl::Call && instruction.is_call_near() {
                    targets.insert(instruction.near_branch_target());
                }
            }
        }
    }
    let ranges = code(binary);
    targets.retain(|&target| ranges.iter().any(|&(start, end)| (start..end).contains(&target)));
    targets
}

/// Each start's extent: up to the next start or the end of its segment, minus trailing `int3` padding on x86.
fn extents(binary: &Binary, starts: &BTreeSet<u64>) -> Vec<(u64, u64)> {
    let ranges = code(binary);
    let ordered: Vec<u64> = starts.iter().copied().collect();
    let mut result = Vec::new();
    for (index, &start) in ordered.iter().enumerate() {
        let Some(&(_, segment_end)) = ranges.iter().find(|&&(low, high)| (low..high).contains(&start)) else {
            continue;
        };
        let end = ordered.get(index + 1).map_or(segment_end, |&next| next.min(segment_end));
        let Some(bytes) = binary.read(start, end - start) else { continue };
        let mut length = bytes.len();
        if binary.arch != Arch::Aarch64 {
            while length > 0 && bytes[length - 1] == 0xcc {
                length -= 1;
            }
        }
        if length > 0 {
            result.push((start, length as u64));
        }
    }
    result
}

/// The names `db` gives each extent of `binary`, by address. Scheme-1 lookups use the plain `identify`.
fn names(db: &SignatureDb, binary: &Binary, extents: &[(u64, u64)]) -> BTreeMap<u64, String> {
    let target = binary.target();
    let image = MaskContext::from_binary(binary);
    let mut found = BTreeMap::new();
    for &(address, length) in extents {
        let bytes = binary.read(address, length).unwrap();
        let name = if db.scheme() == LEGACY_SCHEME {
            db.identify(&target, bytes, address)
        } else {
            db.identify_in(&target, &image, bytes, address)
        };
        if let Some(name) = name {
            found.insert(address, name.to_owned());
        }
    }
    found
}

/// Correct and wrong names against a truth.
fn score(found: &BTreeMap<u64, String>, truth: &BTreeMap<u64, String>) -> (usize, usize) {
    let correct = found.iter().filter(|(address, name)| truth.get(address) == Some(name)).count();
    (correct, found.len() - correct)
}

fn measure_eval_pair(arch: &str) -> [(usize, usize); 2] {
    let reference = open(&format!("eval-ref-{arch}.elf"));
    let target = open(&format!("eval-target-{arch}.elf"));
    let truth = truth(arch);
    let extents = extents(&target, &truth.keys().copied().collect());
    let legacy = SignatureDb::from_binary_with_scheme(&reference, LEGACY_SCHEME);
    let current = SignatureDb::from_binary(&reference);
    assert_eq!(current.scheme(), CURRENT_SCHEME);
    let before = score(&names(&legacy, &target, &extents), &truth);
    let after = score(&names(&current, &target, &extents), &truth);
    eprintln!(
        "{arch} eval-ref -> eval-target ({} truth functions): scheme 1 {} correct / {} wrong ({} sigs), \
         scheme 2 {} correct / {} wrong ({} sigs)",
        truth.len(),
        before.0,
        before.1,
        legacy.len(),
        after.0,
        after.1,
        current.len()
    );
    [before, after]
}

#[test]
fn scheme_2_names_more_of_a_different_program_without_wrong_names_x86_64() {
    let [before, after] = measure_eval_pair("x86_64");
    assert_eq!(after.1, 0, "scheme 2 proposed wrong names");
    assert!(after.0 > before.0, "scheme 2 ({}) does not beat scheme 1 ({})", after.0, before.0);
}

#[test]
fn scheme_2_names_more_of_a_different_program_without_wrong_names_aarch64() {
    let [before, after] = measure_eval_pair("aarch64");
    assert_eq!(after.1, 0, "scheme 2 proposed wrong names");
    assert!(after.0 > before.0, "scheme 2 ({}) does not beat scheme 1 ({})", after.0, before.0);
}

/// Matches on the stripped `musl-static-*` program (no truth: these are proposals) from a database built from the
/// different program `eval-ref-*`.
fn measure_musl_static(arch: &str) -> [usize; 2] {
    let reference = open(&format!("eval-ref-{arch}.elf"));
    let target = open(&format!("musl-static-{arch}.elf"));
    let extents = extents(&target, &call_targets(&target));
    let legacy = names(&SignatureDb::from_binary_with_scheme(&reference, LEGACY_SCHEME), &target, &extents);
    let current = names(&SignatureDb::from_binary(&reference), &target, &extents);
    // Scheme 2 masks a superset of scheme 1's fields; only a new ambiguity could lose a name, and none does here.
    for (address, name) in &legacy {
        assert_eq!(current.get(address), Some(name), "{arch}: scheme 2 lost or renamed {name} at {address:#x}");
    }
    // The bundled database was built from a symbolized build of musl-static's own toolchain, so where it names a
    // function too, it is a partial truth.
    let bundled = names(&bundled(target.arch).unwrap(), &target, &extents);
    let disagree: Vec<_> =
        current.iter().filter(|(address, name)| bundled.get(address).is_some_and(|other| other != *name)).collect();
    assert!(disagree.is_empty(), "{arch}: scheme 2 and the bundled database disagree: {disagree:?}");
    let gained: Vec<&String> =
        current.iter().filter(|(address, _)| !legacy.contains_key(address)).map(|(_, name)| name).collect();
    eprintln!("{arch} named only by scheme 2: {gained:?}");
    eprintln!(
        "{arch} eval-ref -> musl-static ({} call-target extents): scheme 1 {} names, scheme 2 {} names",
        extents.len(),
        legacy.len(),
        current.len()
    );
    [legacy.len(), current.len()]
}

#[test]
fn scheme_2_names_more_of_musl_static() {
    for arch in ["x86_64", "aarch64"] {
        let [before, after] = measure_musl_static(arch);
        assert!(after > before, "{arch}: scheme 2 ({after}) does not beat scheme 1 ({before})");
    }
}

/// The twin case: a database identifies the functions of the binary it was built from (as a stripped twin would
/// be, with identical bytes at identical addresses) about as well under scheme 2. A few bodies that differed only
/// in which global they touch become ambiguous and drop out (x86-64: `gmtime`/`localtime`, which differ only in
/// their static result buffer), but nothing is misnamed.
#[test]
fn same_binary_twin_does_not_regress() {
    for arch in ["x86_64", "aarch64"] {
        let reference = open(&format!("eval-ref-{arch}.elf"));
        let mut truth = BTreeMap::new();
        let mut sized = Vec::new();
        for symbol in &reference.symbols {
            if symbol.kind == SymbolKind::Function && symbol.size > 0 && !symbol.name.is_empty() {
                truth.entry(symbol.address).or_insert_with(Vec::new).push(symbol.name.clone());
                sized.push((symbol.address, symbol.size));
            }
        }
        sized.sort();
        sized.dedup_by_key(|(address, _)| *address);
        let count = |db: &SignatureDb| {
            let found = names(db, &reference, &sized);
            let wrong = found.iter().filter(|(address, name)| !truth[*address].contains(name)).count();
            (found.len(), wrong)
        };
        let before = count(&SignatureDb::from_binary_with_scheme(&reference, LEGACY_SCHEME));
        let after = count(&SignatureDb::from_binary(&reference));
        eprintln!("{arch} twin ({} functions): scheme 1 {before:?}, scheme 2 {after:?} (named, wrong)", sized.len());
        assert_eq!((before.1, after.1), (0, 0), "{arch}: a twin function got another function's name");
        assert!(after.0 >= before.0 * 95 / 100, "{arch}: twin identification fell from {} to {}", before.0, after.0);
    }
}

/// The bundled databases predate schemes: they load as scheme 1, and `identify_in` hashes them exactly as
/// `identify` always did, whatever context it is given.
#[test]
fn bundled_scheme_1_databases_match_as_before() {
    for arch in [Arch::X86_64, Arch::Aarch64] {
        let db = bundled(arch).unwrap();
        assert_eq!(db.scheme(), LEGACY_SCHEME);
        let target = open(&format!("musl-static-{arch}.elf"));
        let image = MaskContext::from_binary(&target);
        assert!(!image.ranges().is_empty(), "{arch}: musl-static is ET_EXEC, it has a context");
        let platform = target.target();
        let extents = extents(&target, &call_targets(&target));
        let mut matched = 0;
        for &(address, length) in &extents {
            let bytes = target.read(address, length).unwrap();
            let plain = db.identify(&platform, bytes, address);
            assert_eq!(plain, db.identify_in(&platform, &image, bytes, address), "{arch} at {address:#x}");
            matched += usize::from(plain.is_some());
        }
        eprintln!("{arch} bundled scheme 1 on musl-static: {matched} of {} call-target extents", extents.len());
        assert!(matched > 0, "{arch}: the bundled database matched nothing");
    }
}
