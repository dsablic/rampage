//! MSVC C++ metadata against the owned clang-cl/lld-link fixtures in `tests/fixtures/msvc-cpp`, whose PDBs are the
//! truth: `truth-<arch>.txt` lists every procedure, thunk and public symbol llvm-pdbutil reads from them.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rampage_loaders::Binary;
use rampage_loaders::msvc::{exception_tables, vftables};
use rampage_loaders::pdb::matched_symbols;

const ARCHES: [(&str, [u64; 3]); 2] =
    [("x64", [0x1_4000_1000, 0x1_4000_3000, 0x1_4000_5000]), ("x86", [0x40_1000, 0x40_2000, 0x40_3000])];

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/msvc-cpp").join(name)
}

/// The truth listing: kind, then the virtual address of each named record.
fn truth(arch: &str, sections: [u64; 3]) -> BTreeMap<&'static str, BTreeMap<u64, Vec<String>>> {
    let text = std::fs::read_to_string(path(&format!("truth-{arch}.txt"))).unwrap();
    let mut truth: BTreeMap<&'static str, BTreeMap<u64, Vec<String>>> = BTreeMap::new();
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let mut fields = line.splitn(3, ' ');
        let (kind, address, name) = (fields.next().unwrap(), fields.next().unwrap(), fields.next().unwrap());
        let (section, offset) = address.split_once(':').unwrap();
        let Some(&base) = sections.get(section.parse::<usize>().unwrap().wrapping_sub(1)) else { continue };
        let kind = match kind {
            "function" | "thunk" => "code",
            "public-function" => "public",
            "public-data" => "data",
            other => panic!("unknown truth kind {other}"),
        };
        let address = base + offset.parse::<u64>().unwrap();
        truth.entry(kind).or_default().entry(address).or_default().push(name.to_owned());
    }
    truth
}

#[test]
fn vftables_match_the_pdb_vftable_symbols_slot_for_slot() {
    for (arch, sections) in ARCHES {
        let binary = Binary::open(path(&format!("msvc-cpp-{arch}.exe"))).unwrap();
        let truth = truth(arch, sections);
        let expected: BTreeMap<u64, &str> = truth["data"]
            .iter()
            .filter_map(|(&address, names)| {
                let name = names.iter().find(|name| name.starts_with("??_7"))?;
                (!name.contains("type_info")).then_some((address, name.as_str()))
            })
            .collect();
        let tables = vftables(&binary);
        let found: BTreeMap<u64, _> = tables.iter().map(|table| (table.address, table)).collect();
        assert_eq!(found.keys().collect::<Vec<_>>(), expected.keys().collect::<Vec<_>>(), "{arch}");
        // Procedure names win over the decorated public names at the same address.
        let code: BTreeMap<u64, &str> = truth["public"]
            .iter()
            .chain(&truth["code"])
            .map(|(&address, names)| (address, names[0].as_str()))
            .collect();
        for table in &tables {
            // `??_7Sprite@geo@@6BDrawable@1@@` belongs to the class its type descriptor names: `.?AVSprite@geo@@`.
            let symbol = expected[&table.address];
            let class = &symbol[4..symbol.rfind("6B").unwrap()];
            assert_eq!(&table.mangled[4..], class, "{symbol}");
            // Secondary tables: a second base's, and the shared virtual base `Node`'s.
            let secondary = ["6BDrawable@", "6BSerializable@", "6BRightNode@", "6BNode@"];
            let is_secondary = secondary.iter().any(|base| symbol.contains(base));
            assert_eq!(table.offset != 0, is_secondary, "{symbol} at offset {}", table.offset);
            for slot in &table.slots {
                assert!(code.contains_key(slot), "{arch} {symbol}: slot {slot:#x} is no PDB function");
                // Virtual methods are reached through no call; the table makes them function starts.
                assert!(binary.function_starts.binary_search(slot).is_ok(), "{arch} {symbol}: slot {slot:#x}");
            }
        }
        let sprite = tables.iter().find(|table| table.mangled == ".?AVSprite@geo@@" && table.offset == 0).unwrap();
        let names: Vec<&str> = sprite.slots.iter().map(|slot| code[slot]).collect();
        assert_eq!(names, ["geo::Sprite::~Sprite", "geo::Rect::area", "geo::Rect::perimeter", "geo::Sprite::name"]);
    }
}

#[test]
fn frame_handler_tables_give_try_blocks_typed_catches_and_cleanups() {
    for (arch, sections) in ARCHES {
        let binary = Binary::open(path(&format!("msvc-cpp-{arch}.exe"))).unwrap();
        let truth = truth(arch, sections);
        let named = |name: &str| *truth["code"].iter().find(|(_, names)| names[0] == name).unwrap().0;
        let report = exception_tables(&binary);
        assert_eq!(report.undecoded_handlers, 0, "{arch}");
        assert_eq!(report.functions.len(), 4, "{arch}: {:#?}", report.functions);
        assert!(
            report.functions.iter().all(|function| function.handler_import.as_deref() == Some("__CxxFrameHandler3"))
        );

        let owner = |function: &rampage_loaders::msvc::EhFunction| match arch {
            "x64" => function.function.unwrap(),
            // x86 tables are tied to a function by the store that registers their handler thunk.
            _ => {
                let at = function.registrations[0];
                *truth["code"].range(..=at).next_back().unwrap().0
            }
        };
        let by_owner: BTreeMap<u64, _> = report.functions.iter().map(|function| (owner(function), function)).collect();
        let owners: Vec<u64> = by_owner.keys().copied().collect();
        let mut expected = ["guarded_lookup", "nested_handlers", "cleanup_only", "entry"].map(named);
        expected.sort_unstable();
        assert_eq!(owners, expected, "{arch}");

        let lookup = by_owner[&named("guarded_lookup")];
        assert_eq!(lookup.try_blocks.len(), 1);
        let catches: Vec<_> =
            lookup.try_blocks[0].catches.iter().map(|catch| catch.mangled.as_deref().unwrap_or("...")).collect();
        assert_eq!(catches, [".?AURangeError@@", ".?AUError@@", ".H", "..."], "{arch}");
        assert_eq!(lookup.try_blocks[0].ranges.is_empty(), arch == "x86");
        let nested = by_owner[&named("nested_handlers")];
        assert_eq!(nested.try_blocks.len(), 2);
        // Each Guard destructor on an unwind path is a cleanup funclet; cleanup_only has two and no try block.
        let cleanup = by_owner[&named("cleanup_only")];
        assert!(cleanup.try_blocks.is_empty());
        assert_eq!(cleanup.unwind.iter().filter(|entry| entry.action.is_some()).count(), 2);
        for function in by_owner.values() {
            for funclet in function.funclets() {
                assert!(binary.function_starts.binary_search(&funclet).is_ok(), "{arch}: funclet {funclet:#x}");
            }
        }

        let thrown: Vec<Vec<&str>> = report
            .throws
            .iter()
            .map(|throw| throw.types.iter().map(|caught| caught.mangled.as_str()).collect())
            .collect();
        assert_eq!(thrown, [vec![".H"], vec![".?AURangeError@@", ".?AUError@@"], vec![".?AUError@@"]], "{arch}");
    }
}

#[test]
fn pdb_names_cover_every_procedure_with_decorated_aliases_where_needed() {
    for (arch, sections) in ARCHES {
        let binary = Binary::open(path(&format!("msvc-cpp-{arch}.exe"))).unwrap();
        let truth = truth(arch, sections);
        let report = matched_symbols(&binary, &path(&format!("msvc-cpp-{arch}.pdb"))).unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        let names: BTreeMap<u64, &str> =
            report.functions.iter().map(|function| (function.address, function.name.as_str())).collect();
        for (address, procedure) in &truth["code"] {
            assert!(names.contains_key(address), "{arch}: {address:#x} {procedure:?} unnamed");
        }
        // Plain unique procedure names are kept; templates, operators and names shared by several functions take
        // their decorated public name.
        let lookup = truth["code"].iter().find(|(_, n)| n[0] == "guarded_lookup").unwrap().0;
        assert_eq!(names[lookup], "guarded_lookup");
        let get = truth["code"].iter().find(|(_, n)| n[0] == "Box<int>::get").unwrap().0;
        assert!(names[get].starts_with("?get@?$Box@H@@"), "{}", names[get]);
        let unique: std::collections::BTreeSet<&str> = names.values().copied().collect();
        assert_eq!(unique.len(), names.len());
    }
}
