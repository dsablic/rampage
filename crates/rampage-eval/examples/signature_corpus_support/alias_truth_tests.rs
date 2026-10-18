use super::*;
use crate::fixture_support::TempFiles;
use rampage_signatures::{MaskContext, SignatureDb};

const ADDRESS: u64 = 0x201000;
const BODY: &[u8] = &[0x55, 0x48, 0x89, 0xe5, 0xb8, 7, 0, 0, 0, 0x5d, 0xc3];
const SIZE: u64 = BODY.len() as u64;

fn native_image(alias_offset: u64, alias_size: u64, hidden_owned: bool) -> Vec<u8> {
    native_image_custom(alias_offset, alias_size, hidden_owned, false, |_| {})
}

fn native_image_custom(
    alias_offset: u64,
    alias_size: u64,
    hidden_owned: bool,
    extra_body: bool,
    edit: impl FnOnce(&mut object::build::elf::Builder<'_>),
) -> Vec<u8> {
    let mut object =
        object::write::Object::new(object::BinaryFormat::Elf, object::Architecture::X86_64, object::Endianness::Little);
    let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
    let mut body = BODY.to_vec();
    body.resize(16, 0x90);
    if extra_body {
        body.extend_from_slice(BODY);
        body.resize(32, 0x90);
    }
    object.append_section_data(text, &body, 16);
    for (name, offset, size, weak) in [("__producer", 0, SIZE, false), ("producer", alias_offset, alias_size, true)] {
        object.add_symbol(object::write::Symbol {
            name: name.as_bytes().to_vec(),
            value: offset,
            size,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Dynamic,
            weak,
            section: object::write::SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });
    }
    if extra_body {
        object.add_symbol(object::write::Symbol {
            name: b"unrelated_body".to_vec(),
            value: 16,
            size: SIZE,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Dynamic,
            weak: false,
            section: object::write::SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });
    }
    let bytes = object.write().unwrap();
    let mut image = object::build::elf::Builder::read(bytes.as_slice()).unwrap();
    let text_id = image.sections.iter().find(|section| section.name.as_slice() == b".text").unwrap().id();
    image.sections.get_mut(text_id).sh_addr = ADDRESS;
    image.sections.get_mut(text_id).sh_offset = 0x1000;
    for symbol in &mut image.symbols {
        if symbol.section == Some(text_id) {
            symbol.st_value += ADDRESS;
            if hidden_owned && symbol.name.as_slice() == b"__producer" {
                symbol.st_other = object::elf::STV_HIDDEN.into();
            }
        }
    }
    image.header.e_type = object::elf::ET_EXEC;
    image.header.e_entry = ADDRESS;
    image.header.e_phoff = 64;
    let segment = image.segments.add();
    segment.p_type = object::elf::PT_LOAD;
    segment.p_flags = object::elf::PF_R | object::elf::PF_X;
    segment.p_offset = 0x1000;
    segment.p_vaddr = ADDRESS;
    segment.p_paddr = ADDRESS;
    segment.p_filesz = body.len() as u64;
    segment.p_memsz = body.len() as u64;
    segment.p_align = 0x1000;
    segment.sections.push(text_id);
    edit(&mut image);
    let mut result = Vec::new();
    image.write(&mut result).unwrap();
    result
}

fn call_body(address: u64, callee: u64) -> Vec<u8> {
    let mut body = vec![0x55, 0x48, 0x89, 0xe5, 0xe8];
    body.extend_from_slice(&((callee as i64 - (address + 9) as i64) as i32).to_le_bytes());
    body.extend_from_slice(&[0x83, 0xc0, 1, 0x5d, 0xc3]);
    body
}

fn native_call_image(candidate: bool, include_other_caller: bool) -> Vec<u8> {
    native_image_custom(0, SIZE, false, false, |image| {
        let text_id = image.sections.iter().find(|section| section.name.as_slice() == b".text").unwrap().id();
        let mut body = BODY.to_vec();
        if candidate {
            body[5] = 9;
        }
        body.resize(16, 0x90);
        body.extend_from_slice(&call_body(ADDRESS + 16, ADDRESS));
        body.resize(32, 0x90);
        body.extend_from_slice(&call_body(ADDRESS + 32, ADDRESS + 48));
        body.resize(48, 0x90);
        let mut other_callee = BODY.to_vec();
        other_callee[5] = 13;
        body.extend_from_slice(&other_callee);
        body.resize(64, 0x90);
        let text = image.sections.get_mut(text_id);
        text.data = object::build::elf::SectionData::Data(body.into());
        text.sh_size = 64;
        for segment in &mut image.segments {
            segment.p_filesz = 64;
            segment.p_memsz = 64;
        }
        if candidate {
            for symbol in &mut image.symbols {
                if symbol.name.as_slice() == b"__producer" {
                    symbol.delete = true;
                }
                if symbol.name.as_slice() == b"producer" {
                    symbol.set_st_info(object::elf::STB_GLOBAL, object::elf::STT_FUNC);
                }
            }
        }
        for (offset, size, name) in [
            (16, 14, if candidate { "wrong_caller" } else { "caller_b" }),
            (32, 14, "other_caller"),
            (48, SIZE, "other_callee"),
        ] {
            if offset == 32 && !include_other_caller {
                continue;
            }
            let symbol = image.symbols.add();
            symbol.name = name.as_bytes().to_vec().into();
            symbol.section = Some(text_id);
            symbol.st_value = ADDRESS + offset;
            symbol.st_size = size;
            symbol.set_st_info(object::elf::STB_GLOBAL, object::elf::STT_FUNC);
        }
    })
}

#[test]
fn reference_preserves_original_callee_negative_keys_while_selecting_strong_answers() {
    for include_other_caller in [false, true] {
        check_original_callee_negative_keys(include_other_caller);
    }
}

fn check_original_callee_negative_keys(include_other_caller: bool) {
    let files = TempFiles::new();
    let bytes = native_call_image(false, include_other_caller);
    let path = files.write("call-reference.elf", &bytes);
    let source = Binary::open(&path).unwrap();
    let candidate_image = Binary::open(files.write("call-candidate.elf", &native_call_image(true, true))).unwrap();
    let mut candidate = SignatureDb::from_binary(&candidate_image);
    candidate.withhold_exact_fallbacks();
    let target = candidate_image.target();
    let image = MaskContext::from_binary(&candidate_image);
    let caller = call_body(ADDRESS + 16, ADDRESS);
    let lookup = |database: &SignatureDb| {
        database
            .identify_with_callees(&target, &image, &caller, ADDRESS + 16, |address| {
                (address == ADDRESS).then_some("producer")
            })
            .map(str::to_owned)
    };
    assert_eq!(lookup(&candidate).as_deref(), Some("wrong_caller"));
    assert_eq!(candidate.identify_in(&target, &image, &caller, ADDRESS + 16), None);

    let mut old_view = Binary::open(&path).unwrap();
    old_view.symbols.retain(|symbol| symbol.name != "producer");
    let mut escaped = candidate.clone();
    escaped.reject_reference_conflicts_from([&SignatureDb::from_binary(&old_view)]).unwrap();
    assert_eq!(lookup(&escaped).as_deref(), Some("wrong_caller"));
    let changed_callee = candidate_image.read(ADDRESS, SIZE).unwrap();
    assert_eq!(escaped.identify(&target, changed_callee, ADDRESS), Some("producer"));

    let extents = BTreeMap::new();
    let source_callees = Truth::from_binary(&source);
    assert_eq!(
        SignatureDb::from_binary_with_extents_and_callees(&source, &extents, &source_callees.0).to_json(),
        SignatureDb::from_binary_with_extents(&source, &extents).to_json()
    );
    let (reference, evidence) =
        crate::producer_alias_reference(&source, &path, &crate::digest(&bytes), &extents).unwrap();
    candidate.reject_reference_conflicts_from([&reference]).unwrap();
    assert_eq!(lookup(&candidate), None);
    assert_eq!(candidate.identify(&target, changed_callee, ADDRESS), Some("producer"));
    assert_eq!(evidence["original_source_callee_truth"][format!("{ADDRESS:#x}")], "producer");

    let mut strong_source = Binary::open(&path).unwrap();
    strong_source.symbols.retain(|symbol| symbol.name == "__producer");
    let mut strong_candidate = SignatureDb::from_binary(&strong_source);
    strong_candidate.reject_reference_conflicts_from([&reference]).unwrap();
    assert_eq!(strong_candidate.identify(&source.target(), BODY, ADDRESS), Some("__producer"));

    let mut reversed = source;
    reversed.symbols.reverse();
    let reordered = crate::producer_alias_reference(&reversed, &path, &crate::digest(&bytes), &extents).unwrap().0;
    assert_eq!(reference.to_gzip().unwrap(), reordered.to_gzip().unwrap());
    let mut contexts = SignatureDb::from_binary_with_extents_and_callees(&old_view, &extents, &source_callees.0);
    let view_context = SignatureDb::from_binary_with_extents(&old_view, &extents);
    let mut reversed_contexts = view_context.clone();
    reversed_contexts.combine(&contexts).unwrap();
    contexts.combine(&view_context).unwrap();
    assert_eq!(contexts.to_gzip().unwrap(), reversed_contexts.to_gzip().unwrap());
}

#[test]
fn native_strong_weak_same_range_accepts_raw_alias_without_regrading_owned() {
    let files = TempFiles::new();
    let binary = Binary::open(files.write("alias.elf", &native_image(0, SIZE, false))).unwrap();
    let full = Truth::from_binary(&binary);
    assert_eq!(full.0[&ADDRESS], "producer");
    let aliases = producer_alias_sets(&binary, &full).unwrap();
    assert!(aliases[&ADDRESS].admits_owned("__producer", false));
    assert!(!aliases[&ADDRESS].admits_owned("producer", false));
    assert!(!aliases[&ADDRESS].admits_owned("missing", true));
    let owned = Truth(BTreeMap::from([(ADDRESS, "__producer".into())]));
    assert!(crate::validate_owned_truth(&owned, &full, None, false).is_err());
    assert!(crate::validate_owned_truth(&owned, &full, Some(&aliases), false).is_ok());
    let proposed = vec![(ADDRESS, Some("__producer".into()))];
    let (_, strict_full, strict_passed) = crate::grade(&proposed, &owned, &full);
    assert!(!strict_passed);
    assert_eq!(strict_full.wrong, 1);
    let (report, accepted) = score_aliases(&proposed, &full, &aliases).unwrap();
    assert_eq!((report.correct, report.wrong, report.spurious), (1, 0, 0));
    assert_eq!((report.precision, report.recall), (1.0, 1.0));
    assert_eq!(accepted[0].raw_name, "__producer");
    assert_eq!(accepted[0].producer_alias_set.canonical_name, "producer");
    assert_eq!(accepted[0].producer_alias_set.original_symbol_size, SIZE);
    let weak_proposal = vec![(ADDRESS, Some("producer".into()))];
    assert_eq!(crate::grade(&weak_proposal, &owned, &full).0.wrong, 1);
    let (empty, _) = score_aliases(&[], &full, &aliases).unwrap();
    assert_eq!((empty.precision, empty.recall, empty.missed), (0.0, 0.0, 1));
}

#[test]
fn unequal_zero_or_interior_ranges_never_become_aliases() {
    let files = TempFiles::new();
    for (index, (offset, size)) in [(0, SIZE - 1), (0, 0), (1, SIZE), (0, 17)].into_iter().enumerate() {
        let binary =
            Binary::open(files.write(&format!("different-{index}.elf"), &native_image(offset, size, false))).unwrap();
        let full = Truth::from_binary(&binary);
        let aliases = producer_alias_sets(&binary, &full).unwrap();
        assert!(aliases.is_empty());
        if offset == 0 && size != 0 {
            let owned = Truth(BTreeMap::from([(ADDRESS, "__producer".into())]));
            assert!(crate::validate_owned_truth(&owned, &full, Some(&aliases), false).is_err());
        }
    }
}

#[test]
fn hidden_linked_owned_names_require_explicit_linked_scope_for_reconciliation() {
    let files = TempFiles::new();
    let binary = Binary::open(files.write("hidden.elf", &native_image(0, SIZE, true))).unwrap();
    let aliases = producer_alias_sets(&binary, &Truth::from_binary(&binary)).unwrap();
    assert!(!aliases[&ADDRESS].admits_owned("__producer", false));
    assert!(aliases[&ADDRESS].admits_owned("__producer", true));
}

#[test]
fn wrong_and_spurious_raw_names_remain_visible_and_in_denominators() {
    let files = TempFiles::new();
    let binary = Binary::open(files.write("wrong.elf", &native_image(0, SIZE, false))).unwrap();
    let full = Truth::from_binary(&binary);
    let aliases = producer_alias_sets(&binary, &full).unwrap();
    let proposed = vec![(ADDRESS, Some("not_a_producer_name".into())), (ADDRESS + 1, Some("__producer".into()))];
    let (report, accepted) = score_aliases(&proposed, &full, &aliases).unwrap();
    assert!(accepted.is_empty());
    assert_eq!((report.correct, report.wrong, report.spurious, report.recall), (0, 1, 1, 0.0));
    assert_eq!(report.disagreements[0].proposed.as_deref(), Some("not_a_producer_name"));
    assert_eq!(report.disagreements[1].proposed.as_deref(), Some("__producer"));
    let mut extended = full.clone();
    extended.0.insert(ADDRESS + 16, "other".into());
    extended.0.insert(ADDRESS + 32, "undiscovered".into());
    let mixed = vec![
        (ADDRESS, Some("__producer".into())),
        (ADDRESS + 16, Some("wrong_raw".into())),
        (ADDRESS + 1, Some("__producer".into())),
    ];
    let (report, accepted) = score_aliases(&mixed, &extended, &aliases).unwrap();
    assert_eq!((report.correct, report.wrong, report.missed, report.spurious), (1, 1, 1, 1));
    assert_eq!((report.precision, report.recall), (1.0 / 3.0, 1.0 / 3.0));
    assert_eq!(accepted.len(), 1);
    assert!(report.disagreements.iter().any(|row| row.proposed.as_deref() == Some("wrong_raw")));
}

#[test]
fn reference_unique_strong_definition_is_selected_without_importing_weak_answers() {
    let files = TempFiles::new();
    let bytes = native_image(0, SIZE, false);
    let path = files.write("reference.elf", &bytes);
    let binary = Binary::open(&path).unwrap();
    let strict = SignatureDb::from_binary(&binary);
    assert_eq!(strict.identify(&binary.target(), BODY, ADDRESS), Some("producer"));
    let original_symbols = binary.symbols.clone();
    let (safe, evidence) =
        crate::producer_alias_reference(&binary, &path, &crate::digest(&bytes), &BTreeMap::new()).unwrap();
    assert_eq!(safe.identify(&binary.target(), BODY, ADDRESS), Some("__producer"));
    assert_eq!(evidence["native_spelling_views"], 1);
    assert_eq!(
        evidence["definition_evidence"]["selected_existing_strong_definitions"][ADDRESS.to_string()],
        "__producer"
    );
    assert_eq!(Truth::from_binary(&binary).0[&ADDRESS], "producer");
    assert_eq!(binary.symbols, original_symbols);
    assert_eq!(crate::digest(binary.image_bytes()), crate::digest(&bytes));
    assert_eq!(
        evidence["definition_evidence"]["source_address_function_definitions"][ADDRESS.to_string()]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let mut owned_source = Binary::open(&path).unwrap();
    owned_source.symbols.retain(|symbol| symbol.name == "__producer");
    let mut candidate = SignatureDb::from_binary(&owned_source);
    assert_eq!(candidate.identify(&binary.target(), BODY, ADDRESS), Some("__producer"));
    assert_eq!(candidate.reject_reference_conflicts_from([&safe]).unwrap(), 0);
    assert_eq!(candidate.identify(&binary.target(), BODY, ADDRESS), Some("__producer"));
    let mut weak_candidate = strict;
    assert!(weak_candidate.reject_reference_conflicts_from([&safe]).unwrap() > 0);
    assert_eq!(weak_candidate.identify(&binary.target(), BODY, ADDRESS), None);
}

#[test]
fn reference_same_body_at_an_unrelated_address_still_conflicts() {
    let files = TempFiles::new();
    let bytes = native_image_custom(0, SIZE, false, true, |_| {});
    let path = files.write("collision.elf", &bytes);
    let binary = Binary::open(&path).unwrap();
    let (reference, _) =
        crate::producer_alias_reference(&binary, &path, &crate::digest(&bytes), &BTreeMap::new()).unwrap();
    let mut owned = Binary::open(&path).unwrap();
    owned.symbols.retain(|symbol| symbol.name == "__producer");
    let mut candidate = SignatureDb::from_binary(&owned);
    assert_eq!(candidate.identify(&binary.target(), BODY, ADDRESS), Some("__producer"));
    assert!(candidate.reject_reference_conflicts_from([&reference]).unwrap() > 0);
    assert_eq!(candidate.identify(&binary.target(), BODY, ADDRESS), None);
}

#[test]
fn reference_hidden_local_all_weak_and_multiple_global_groups_remain_ambiguous() {
    let files = TempFiles::new();
    for mode in 0..5 {
        let bytes = native_image_custom(0, SIZE, mode == 0, false, |image| {
            for symbol in &mut image.symbols {
                if symbol.name.as_slice() == b"producer" {
                    match mode {
                        1 => symbol.set_st_info(object::elf::STB_GLOBAL, object::elf::STT_FUNC),
                        2 => symbol.set_st_info(object::elf::STB_LOCAL, object::elf::STT_FUNC),
                        3 => symbol.st_other = object::elf::STV_HIDDEN.into(),
                        _ => (),
                    }
                }
                if mode == 4 && symbol.name.as_slice() == b"__producer" {
                    symbol.set_st_info(object::elf::STB_WEAK, object::elf::STT_FUNC);
                }
            }
        });
        let path = files.write(&format!("ambiguous-{mode}.elf"), &bytes);
        let binary = Binary::open(&path).unwrap();
        let (reference, evidence) =
            crate::producer_alias_reference(&binary, &path, &crate::digest(&bytes), &BTreeMap::new()).unwrap();
        assert_eq!(reference.identify(&binary.target(), BODY, ADDRESS), None, "mode={mode}; evidence={evidence}");
        assert_eq!(evidence["definition_evidence"]["selected_existing_strong_definitions"], serde_json::json!({}));
        assert_eq!(evidence["native_spelling_views"], 2);
    }
}

#[test]
fn reference_extra_zero_sized_different_range_or_ifunc_definition_blocks_selection() {
    let files = TempFiles::new();
    for mode in 0..3 {
        let bytes = native_image_custom(0, SIZE, false, false, |image| {
            let section = image.sections.iter().find(|section| section.name.as_slice() == b".text").unwrap().id();
            let symbol = image.symbols.add();
            symbol.name = b"__other_definition".as_slice().into();
            symbol.section = Some(section);
            symbol.st_value = ADDRESS;
            symbol.st_size = match mode {
                0 => 0,
                1 => SIZE - 1,
                _ => SIZE,
            };
            symbol.set_st_info(
                object::elf::STB_WEAK,
                if mode == 2 { object::elf::STT_GNU_IFUNC } else { object::elf::STT_FUNC },
            );
        });
        let path = files.write(&format!("unsupported-{mode}.elf"), &bytes);
        let binary = Binary::open(&path).unwrap();
        let (reference, evidence) =
            crate::producer_alias_reference(&binary, &path, &crate::digest(&bytes), &BTreeMap::new()).unwrap();
        let facts = evidence["definition_evidence"]["source_address_function_definitions"][ADDRESS.to_string()]
            .as_array()
            .unwrap();
        assert_eq!(facts.len(), 3, "mode={mode}; all section-defined native FUNC/IFUNC records must reach the veto");
        if mode == 2 {
            assert!(facts.iter().any(|fact| fact["symbol_type"] == object::elf::STT_GNU_IFUNC.0));
        }
        assert_eq!(reference.identify(&binary.target(), BODY, ADDRESS), None, "mode={mode}; evidence={evidence}");
        assert_eq!(evidence["definition_evidence"]["selected_existing_strong_definitions"], serde_json::json!({}));
    }
}

#[test]
fn reference_without_aliases_preserves_native_database_exactly() {
    let files = TempFiles::new();
    let bytes = native_image_custom(0, SIZE, false, false, |image| {
        for symbol in &mut image.symbols {
            if symbol.name.as_slice() == b"producer" {
                symbol.delete = true;
            }
        }
    });
    let path = files.write("plain.elf", &bytes);
    let binary = Binary::open(&path).unwrap();
    let extents = BTreeMap::from([(ADDRESS, ADDRESS + SIZE)]);
    let expected = SignatureDb::from_binary_with_extents(&binary, &extents).to_json();
    let (reference, evidence) =
        crate::producer_alias_reference(&binary, &path, &crate::digest(&bytes), &extents).unwrap();
    assert_eq!(reference.to_json(), expected);
    assert_eq!(evidence["native_spelling_views"], 0);
}

#[test]
fn reference_definition_choice_is_stable_across_symbol_order_and_parallel_calls() {
    let files = TempFiles::new();
    let bytes = native_image(0, SIZE, false);
    let path = files.write("stable.elf", &bytes);
    let hash = crate::digest(&bytes);
    let mut binary = Binary::open(&path).unwrap();
    let expected = crate::producer_alias_reference(&binary, &path, &hash, &BTreeMap::new()).unwrap().0.to_json();
    binary.symbols.reverse();
    assert_eq!(crate::producer_alias_reference(&binary, &path, &hash, &BTreeMap::new()).unwrap().0.to_json(), expected);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    let binary = Binary::open(&path).unwrap();
                    crate::producer_alias_reference(&binary, &path, &hash, &BTreeMap::new()).unwrap().0.to_json()
                })
            })
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap(), expected);
        }
    });
}
