use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use object::{Object, ObjectSection, ObjectSymbol};
use rampage_eval::{Truth, discovered_extents, proposals, score};
use rampage_loaders::Binary;
use rampage_signatures::{MaskContext, SignatureDb, canonical_functions, function_hash_in};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    reference: PathBuf,
    #[arg(long = "object", required = true)]
    objects: Vec<PathBuf>,
    #[arg(long)]
    target: PathBuf,
    #[arg(long)]
    stripped: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    report: PathBuf,
}

fn digest(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let size = file.metadata().map_err(|error| error.to_string())?.len();
    if size > 256 * 1024 * 1024 {
        return Err("signature corpus input exceeds 256 MiB".into());
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(256 * 1024 * 1024 + 1).read_to_end(&mut bytes).map_err(|error| error.to_string())?;
    if bytes.len() as u64 != size {
        return Err("signature corpus input changed length while reading".into());
    }
    Ok(bytes)
}

fn owned_names(
    paths: &[PathBuf],
    architecture: object::Architecture,
) -> Result<(BTreeSet<String>, Vec<String>), String> {
    if paths.is_empty() || paths.len() > 1024 {
        return Err("signature corpus requires 1..1024 explicit library objects".into());
    }
    let mut names = BTreeSet::new();
    let mut hashes = Vec::new();
    for path in paths {
        let bytes = read(path)?;
        hashes.push(digest(&bytes));
        let file = object::File::parse(bytes.as_slice()).map_err(|error| error.to_string())?;
        if file.architecture() != architecture || file.kind() != object::ObjectKind::Relocatable {
            return Err(format!("{}: expected a same-architecture library object", path.display()));
        }
        for symbol in file.symbols() {
            if symbol.is_undefined()
                || symbol.kind() != object::SymbolKind::Text
                || !symbol.is_global()
                || symbol.is_weak()
                || !matches!(
                    symbol.flags().elf_visibility(),
                    Some(object::elf::STV_DEFAULT | object::elf::STV_PROTECTED)
                )
            {
                continue;
            }
            let name = symbol.name().map_err(|error| error.to_string())?;
            if !name.is_empty() {
                if name.len() > 4096 || name.contains('\0') || names.len() >= 100_000 {
                    return Err("library symbol name/count budget exceeded".into());
                }
                if !names.insert(name.to_owned()) {
                    return Err(format!("duplicate strong library definition {name}"));
                }
            }
        }
    }
    if names.is_empty() {
        return Err("library objects contain no defined text symbols".into());
    }
    Ok((names, hashes))
}

fn verify_twin(symbolized: &Binary, stripped: &Binary, truth: &Truth) -> Result<(), String> {
    let before = symbolized.target();
    let after = stripped.target();
    if before.arch != after.arch
        || before.big_endian != after.big_endian
        || before.data_big_endian != after.data_big_endian
        || before.thumb != after.thumb
    {
        return Err("stripped twin target differs from symbolized target".into());
    }
    if symbolized.format != rampage_loaders::Format::Elf || stripped.format != rampage_loaders::Format::Elf {
        return Err("this corpus pilot validates ELF stripping only".into());
    }
    if symbolized.segments != stripped.segments || symbolized.entry != stripped.entry {
        return Err("stripping changed load mappings or entry point".into());
    }
    for segment in &symbolized.segments {
        let original = normalized_segment(symbolized.image_bytes(), segment.file_offset, segment.file_size)?;
        let retained = normalized_segment(stripped.image_bytes(), segment.file_offset, segment.file_size)?;
        if original != retained {
            return Err("stripping changed load-image bytes outside permitted section-table header fields".into());
        }
    }
    let retained_sections = |binary: &Binary, stripped: bool| -> Result<Vec<_>, String> {
        let file = object::File::parse(binary.image_bytes()).map_err(|error| error.to_string())?;
        let mut sections = Vec::new();
        for section in file.sections() {
            let name = section.name().map_err(|error| error.to_string())?;
            if removable_metadata(name, section.flags())? {
                if stripped && name != ".shstrtab" {
                    return Err("stripped twin retains removable metadata".into());
                }
                continue;
            }
            let backing = section.file_range().map(|(_, size)| size);
            let allocated = matches!(section.flags(),object::SectionFlags::Elf {sh_flags,..}
                if sh_flags.contains(object::elf::SHF_ALLOC));
            sections.push((
                name.to_owned(),
                section.address(),
                section.size(),
                section.align(),
                section.flags(),
                section.kind(),
                backing,
                if allocated { section.file_range() } else { None },
                digest(section.data().map_err(|error| error.to_string())?),
            ));
        }
        Ok(sections)
    };
    if retained_sections(symbolized, false)? != retained_sections(stripped, true)? {
        return Err("stripping changed retained section types, boundaries, backing or data".into());
    }
    let symbols = canonical_functions(symbolized);
    for address in truth.0.keys() {
        let symbol = symbols.get(address).ok_or("missing sized library function")?;
        let original = symbolized.read(*address, symbol.size).ok_or("unbacked truth function")?;
        if stripped.read(*address, symbol.size) != Some(original) {
            return Err(format!("stripping changed library function bytes at {address:#x}"));
        }
    }
    let file = object::File::parse(stripped.image_bytes()).map_err(|error| error.to_string())?;
    if file
        .symbols()
        .chain(file.dynamic_symbols())
        .any(|symbol| symbol.kind() == object::SymbolKind::Text && !symbol.is_undefined())
        || file
            .sections()
            .any(|section| section.name().is_ok_and(|name| name.starts_with(".debug") || name.starts_with(".zdebug")))
    {
        return Err("stripped twin retains static function symbols or debug sections".into());
    }
    Ok(())
}

fn removable_metadata(name: &str, flags: object::SectionFlags) -> Result<bool, String> {
    let object::SectionFlags::Elf { sh_type, sh_flags } = flags else {
        return Err("expected ELF section flags".into());
    };
    let expected = match name {
        ".symtab" => Some(object::elf::SHT_SYMTAB),
        ".strtab" | ".shstrtab" => Some(object::elf::SHT_STRTAB),
        ".symtab_shndx" => Some(object::elf::SHT_SYMTAB_SHNDX),
        _ => None,
    };
    if let Some(expected) = expected {
        if sh_type != expected || sh_flags.0 != 0 {
            return Err("reserved metadata section name has incompatible type/flags".into());
        }
        return Ok(true);
    }
    if name.starts_with(".debug") || name.starts_with(".zdebug") {
        if sh_type != object::elf::SHT_PROGBITS
            || sh_flags.contains(object::elf::SHF_ALLOC)
            || sh_flags.contains(object::elf::SHF_EXECINSTR)
        {
            return Err("debug section has analysis-relevant type/flags".into());
        }
        return Ok(true);
    }
    Ok(false)
}

fn normalized_segment(image: &[u8], offset: u64, length: u64) -> Result<Vec<u8>, String> {
    let start = usize::try_from(offset).map_err(|_| "invalid load offset")?;
    let end =
        usize::try_from(offset.checked_add(length).ok_or("invalid load extent")?).map_err(|_| "invalid load extent")?;
    let mut bytes = image.get(start..end).ok_or("unbacked load segment")?.to_vec();
    let fields: &[(usize, usize)] = match image.get(..5) {
        Some([0x7f, b'E', b'L', b'F', 1]) => &[(32, 36), (48, 52)],
        Some([0x7f, b'E', b'L', b'F', 2]) => &[(40, 48), (60, 64)],
        _ => return Err("expected ELF header".into()),
    };
    for &(first, last) in fields {
        for position in first..last {
            if (start..end).contains(&position) {
                bytes[position - start] = 0;
            }
        }
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(bytes).map_err(|error| error.to_string())
}

fn retain_owned(binary: &mut Binary, names: &BTreeSet<String>) -> Result<(), String> {
    let file = object::File::parse(binary.image_bytes()).map_err(|error| error.to_string())?;
    let mut owned = BTreeSet::new();
    for symbol in file.symbols().filter(|symbol| {
        symbol.is_global()
            && !symbol.is_weak()
            && !symbol.is_undefined()
            && symbol.kind() == object::SymbolKind::Text
            && matches!(symbol.flags().elf_visibility(), Some(object::elf::STV_DEFAULT | object::elf::STV_PROTECTED))
    }) {
        let name = symbol.name().map_err(|error| error.to_string())?;
        if names.contains(name) {
            let address = if binary.arch == rampage_arch::Arch::Arm { symbol.address() & !1 } else { symbol.address() };
            owned.insert((address, name.to_owned()));
        }
    }
    binary.symbols.retain(|symbol| owned.contains(&(symbol.address, symbol.name.clone())));
    Ok(())
}

fn run(arguments: Arguments) -> Result<(), String> {
    let mut reference = Binary::open(&arguments.reference).map_err(|error| error.to_string())?;
    let target = Binary::open(&arguments.target).map_err(|error| error.to_string())?;
    let stripped = Binary::open(&arguments.stripped).map_err(|error| error.to_string())?;
    let reference_file = object::File::parse(reference.image_bytes()).map_err(|error| error.to_string())?;
    let architecture = reference_file.architecture();
    if digest(reference.image_bytes()) == digest(target.image_bytes()) {
        return Err("reference and target must be different linked programs, not copies of one image".into());
    }
    let (names, mut object_hashes) = owned_names(&arguments.objects, architecture)?;
    let reference_model = reference.target();
    let target_model = target.target();
    if reference_model.arch != target_model.arch
        || reference_model.big_endian != target_model.big_endian
        || reference_model.data_big_endian != target_model.data_big_endian
    {
        return Err("reference and target library builds have different targets".into());
    }
    let reference_extents = discovered_extents(&reference).map_err(|error| error.to_string())?;
    let all_reference_symbols = reference.symbols.clone();
    retain_owned(&mut reference, &names)?;
    let owned_symbols = reference.symbols.clone();
    let owned_addresses: BTreeSet<_> = canonical_functions(&reference).keys().copied().collect();
    const NEGATIVE_PREFIX: &str = "__rampage_corpus_negative_";
    if names.iter().any(|name| name.starts_with(NEGATIVE_PREFIX)) {
        return Err("library name conflicts with the corpus negative-example namespace".into());
    }
    reference.symbols.extend(
        all_reference_symbols
            .into_iter()
            .filter(|symbol| {
                symbol.kind == rampage_loaders::SymbolKind::Function && !owned_addresses.contains(&symbol.address)
            })
            .map(|mut symbol| {
                symbol.name = format!("{NEGATIVE_PREFIX}{:x}", symbol.address);
                symbol
            }),
    );
    let mut target_truth = Binary::open(&arguments.target).map_err(|error| error.to_string())?;
    retain_owned(&mut target_truth, &names)?;
    for (role, symbols) in [("reference", &owned_symbols), ("target", &target_truth.symbols)] {
        let retained: BTreeSet<_> = symbols
            .iter()
            .filter(|symbol| symbol.kind == rampage_loaders::SymbolKind::Function && symbol.size > 0)
            .map(|symbol| symbol.name.clone())
            .collect();
        let missing: Vec<_> = names.difference(&retained).take(8).collect();
        if !missing.is_empty() {
            return Err(format!("{role} dropped or lost sized library definitions: {missing:?}; disable linker GC"));
        }
    }
    let truth = Truth::from_binary(&target_truth);
    if truth.0.is_empty() || owned_symbols.is_empty() {
        return Err("reference/target has no sized symbols owned by the library objects".into());
    }
    verify_twin(&target, &stripped, &truth)?;
    let mut database = SignatureDb::from_binary_with_extents(&reference, &reference_extents);
    database.retain_names(&names);
    let empty = || {
        SignatureDb::from_json(&format!("{{\"arch\":\"{}\",\"scheme\":2,\"entries\":{{}}}}", reference.arch))
            .map_err(|error| error.to_string())
    };
    let baseline_available = rampage_signatures::bundled_counts(reference.arch).is_some();
    let baseline = match rampage_signatures::bundled(reference.arch) {
        Some(database) => database,
        None => empty()?,
    };
    let baseline_proposals = proposals(&baseline, &stripped).map_err(|error| error.to_string())?;
    let baseline_unrelated =
        baseline_proposals.iter().filter(|(address, name)| name.is_some() && !truth.0.contains_key(address)).count();
    let baseline_report =
        score(baseline_proposals.into_iter().filter(|(address, _)| truth.0.contains_key(address)), &truth);
    let serialized = database.to_json();
    let compressed = database.to_gzip().map_err(|error| error.to_string())?;
    let measured_database = SignatureDb::from_gzip(&compressed).map_err(|error| error.to_string())?;
    let after = rampage_eval::evaluate(&measured_database, &stripped, &truth).map_err(|error| error.to_string())?;
    let image = MaskContext::from_binary(&stripped);
    let symbol_sized_correct = canonical_functions(&target_truth)
        .into_iter()
        .filter(|(address, symbol)| {
            stripped.read(*address, symbol.size).is_some_and(|bytes| {
                measured_database.identify_in(&stripped.target(), &image, bytes, *address) == Some(symbol.name.as_str())
            })
        })
        .count();
    let mut diagnostic_misses = Vec::new();
    for symbol in canonical_functions(&target_truth).values() {
        let bytes = target.read(symbol.address, symbol.size).ok_or("missing diagnostic target bytes")?;
        if measured_database.identify_in(&target.target(), &image, bytes, symbol.address) == Some(symbol.name.as_str())
        {
            continue;
        }
        let Some(original) = owned_symbols.iter().find(|original| original.name == symbol.name) else { continue };
        let original_bytes =
            reference.read(original.address, original.size).ok_or("missing diagnostic reference bytes")?;
        let hash = |binary: &Binary, bytes: &[u8], address| {
            function_hash_in(&binary.target(), &MaskContext::from_binary(binary), bytes, address)
                .map(|hash| rampage_arch::hex::bytes(&hash))
        };
        diagnostic_misses.push(json!({"name":symbol.name,"reference_size":original.size,"target_size":symbol.size,
            "raw_bytes_equal":original_bytes==bytes,"reference_hash":hash(&reference,original_bytes,original.address),
            "target_hash":hash(&target,bytes,symbol.address)}));
        if diagnostic_misses.len() == 8 {
            break;
        }
    }
    let gzip_path = PathBuf::from(format!("{}.gz", arguments.output.display()));
    object_hashes.sort();
    let report = json!({
        "schema_version":1,"measurement":"phase2-1-library-signatures",
        "collector_source_sha256":digest(include_bytes!("signature_corpus.rs")),
        "evaluator_binary_sha256":digest(&read(&std::env::current_exe().map_err(|error|error.to_string())?)?),
        "arch":reference.arch.to_string(),"scheme":database.scheme(),
        "reference_sha256":digest(reference.image_bytes()),
        "symbolized_target_sha256":digest(target.image_bytes()),
        "stripped_target_sha256":digest(stripped.image_bytes()),
        "database_sha256":digest(serialized.as_bytes()),"compressed_database_sha256":digest(&compressed),
        "database_bytes":serialized.len(),"compressed_database_bytes":compressed.len(),
        "library_object_count":arguments.objects.len(),"library_object_sha256":object_hashes,
        "library_defined_names":names.len(),"truth_functions":truth.0.len(),
        "library_truth":serde_json::from_str::<Value>(&truth.to_json()).map_err(|error|error.to_string())?,
        "database_signatures":database.len(),"database_callee_keys":database.callee_keys(),
        "diagnostic_symbol_sized_direct_matches":symbol_sized_correct,
        "diagnostic_first_eight_symbol_sized_misses":diagnostic_misses,
        "ownership_scope":"externally visible strong ELF function definitions only; local, hidden and weak definitions excluded",
        "nonlibrary_reference_collision_evidence":true,
        "baseline":baseline_report,"baseline_available":baseline_available,
        "baseline_other_library_proposals":baseline_unrelated,
        "after":after,"load_image_equivalent_stripped_twin":true,"target_executed":false,
        "matched_version_recall_gate":0.8,
        "passed":after.recall>=0.8 && after.wrong==0 && after.spurious==0,
        "limitations":[
            "Exact build and linked subset only; this is not near-miss or version identification.",
            "Baseline recall scores owned library addresses; unrelated bundled runtime names are counted separately.",
            "After precision includes all named target proposals, including outside the owned library truth.",
            "Names are selected by unique externally visible strong object definitions; static, hidden and weak coverage is not measured."
        ]
    });
    for path in [&arguments.output, &gzip_path, &arguments.report] {
        if path.try_exists().map_err(|error| error.to_string())? {
            return Err(format!("{}: refusing to overwrite an existing artifact", path.display()));
        }
    }
    reference.validate_backing_source().map_err(|error| error.to_string())?;
    target.validate_backing_source().map_err(|error| error.to_string())?;
    target_truth.validate_backing_source().map_err(|error| error.to_string())?;
    stripped.validate_backing_source().map_err(|error| error.to_string())?;
    write_new(&arguments.output, serialized.as_bytes())?;
    write_new(&gzip_path, &compressed)?;
    write_new(&arguments.report, &serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?)?;
    if report["passed"] != true {
        return Err("signature recall/precision gate failed; the complete failed measurement was retained".into());
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_cli_requires_explicit_ownership_and_separate_twins() {
        assert!(Arguments::try_parse_from(["signature_corpus", "--reference", "reference"]).is_err());
        let arguments = Arguments::try_parse_from([
            "signature_corpus",
            "--reference",
            "reference",
            "--object",
            "lib.o",
            "--target",
            "target",
            "--stripped",
            "stripped",
            "--output",
            "db.json",
            "--report",
            "report.json",
        ])
        .unwrap();
        assert_eq!(arguments.objects, vec![PathBuf::from("lib.o")]);
    }

    #[test]
    fn library_ownership_excludes_local_data_and_undefined_symbols_in_real_objects() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin");
        let object = root.join("eval-program-corpus-x86_64.o");
        let (names, hashes) = owned_names(std::slice::from_ref(&object), object::Architecture::X86_64).unwrap();
        assert_eq!(names, BTreeSet::from(["main".to_owned()]));
        assert_eq!(hashes, vec![digest(&read(&object).unwrap())]);
        assert!(owned_names(&[object], object::Architecture::Aarch64).is_err());
        let mut image = Binary::open(root.join("eval-ref-x86_64.elf")).unwrap();
        assert!(image.symbols.iter().any(|symbol| symbol.name == "cmp"));
        retain_owned(&mut image, &BTreeSet::from(["main".into(), "cmp".into(), "sink".into()])).unwrap();
        assert_eq!(image.symbols.len(), 1);
        assert_eq!(image.symbols[0].name, "main");
    }

    #[test]
    fn training_image_recognition_is_rejected_before_measurement_or_output() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin");
        let image = root.join("eval-ref-x86_64.elf");
        let error = run(Arguments {
            reference: image.clone(),
            target: image.clone(),
            stripped: image.clone(),
            objects: vec![root.join("eval-program-corpus-x86_64.o")],
            output: image.clone(),
            report: image,
        })
        .unwrap_err();
        assert!(error.contains("different linked programs"), "{error}");
    }

    #[test]
    #[ignore = "requires RAMPAGE_SIGNATURE_LUA_OBJECT pointing to the compiled Lua lstate.c object"]
    fn hidden_library_internals_are_not_mistaken_for_missing_public_definitions() {
        let path = PathBuf::from(std::env::var_os("RAMPAGE_SIGNATURE_LUA_OBJECT").expect("explicit Lua object"));
        let (names, _) = owned_names(&[path], object::Architecture::X86_64).unwrap();
        assert!(names.contains("lua_newstate"));
        assert!(!names.contains("luaE_checkcstack"));
        assert!(!names.contains("close_state"));
    }

    #[test]
    fn strip_normalization_never_ignores_entry_program_headers_or_body_changes() {
        let mut original = vec![0u8; 128];
        original[..5].copy_from_slice(b"\x7fELF\x02");
        let expected = normalized_segment(&original, 0, 128).unwrap();
        let mut stripped = original.clone();
        for range in [40..48, 60..64] {
            stripped[range].fill(0xff);
        }
        assert_eq!(normalized_segment(&stripped, 0, 128).unwrap(), expected);
        for index in [24, 32, 48, 56, 64, 100] {
            let mut changed = original.clone();
            changed[index] = 0xff;
            assert_ne!(normalized_segment(&changed, 0, 128).unwrap(), expected, "byte {index}");
        }
        assert!(normalized_segment(&original, 100, 29).is_err());
    }

    #[test]
    fn metadata_names_do_not_hide_analysis_changing_section_types_or_permissions() {
        let flags = |sh_type, sh_flags| object::SectionFlags::Elf { sh_type, sh_flags };
        assert!(removable_metadata(".strtab", flags(object::elf::SHT_STRTAB, object::elf::SectionFlags(0))).unwrap());
        assert!(removable_metadata(".strtab", flags(object::elf::SHT_PROGBITS, object::elf::SHF_EXECINSTR)).is_err());
        assert!(removable_metadata(".debug_line", flags(object::elf::SHT_PROGBITS, object::elf::SHF_ALLOC)).is_err());
        assert!(
            !removable_metadata(".eh_frame", flags(object::elf::SHT_PROGBITS, object::elf::SectionFlags(0))).unwrap()
        );
    }
}
