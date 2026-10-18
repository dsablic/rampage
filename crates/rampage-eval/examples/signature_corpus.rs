#[path = "signature_corpus_support/linked_inputs.rs"]
mod linked_inputs;
#[path = "signature_corpus_support/ownership.rs"]
mod ownership;
mod signature_corpus_support;

#[cfg(test)]
mod fixture_support {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/pdb/support.rs"));
}

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use linked_inputs::{LinkedInputs, apply_definitions, frozen_starter};
use object::{Object, ObjectSection, ObjectSymbol};
use rampage_eval::{Truth, discovered_extents, proposals, score};
use rampage_loaders::Binary;
use rampage_signatures::{MaskContext, SignatureDb, canonical_functions, function_hash_in};
use serde_json::{Value, json};
use signature_corpus_support::{digest, verify_twin};

const NEGATIVE_PREFIX: &str = "__rampage_corpus_negative_";

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum OwnershipScope {
    PublicStrong,
    LinkedArtifact,
}

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    reference: PathBuf,
    /// Explicit identity-matched reference PDB; required for PE producer procedure sizes.
    #[arg(long, requires = "target_pdb")]
    pdb: Option<PathBuf>,
    /// Explicit identity-matched target PDB; never used by stripped-target discovery.
    #[arg(long, requires = "pdb")]
    target_pdb: Option<PathBuf>,
    #[arg(long = "object", required = true)]
    objects: Vec<PathBuf>,
    #[arg(long, value_enum, default_value = "public-strong")]
    ownership_scope: OwnershipScope,
    #[arg(long, required_if_eq("ownership_scope", "linked-artifact"))]
    reference_map: Option<PathBuf>,
    #[arg(long, required_if_eq("ownership_scope", "linked-artifact"))]
    target_map: Option<PathBuf>,
    /// JSON receipt array or runtime-provenance object with archive_member_receipts.
    #[arg(long, required_if_eq("ownership_scope", "linked-artifact"))]
    member_receipts: Option<PathBuf>,
    #[arg(long)]
    target: PathBuf,
    #[arg(long)]
    stripped: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    report: PathBuf,
    /// Address-sorted truth rows with exact matcher evidence; zero disables the diagnostic matrix.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u16).range(0..=512))]
    diagnostic_limit: u16,
}

impl Arguments {
    fn linked_paths(&self) -> Result<Option<(&Path, &Path, &Path)>, String> {
        match (self.ownership_scope, &self.reference_map, &self.target_map, &self.member_receipts) {
            (OwnershipScope::PublicStrong, None, None, None) => Ok(None),
            (OwnershipScope::LinkedArtifact, Some(reference), Some(target), Some(receipts)) => {
                if self.pdb.is_some() || self.target_pdb.is_some() {
                    return Err("linked-artifact ownership supports ELF Linux/System V only, not PE/PDB".into());
                }
                Ok(Some((reference, target, receipts)))
            }
            (OwnershipScope::PublicStrong, ..) => {
                Err("maps/member receipts require --ownership-scope linked-artifact".into())
            }
            _ => Err("linked-artifact ownership requires reference-map, target-map and member-receipts".into()),
        }
    }
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    read_bounded(path, 256 * 1024 * 1024)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    if !std::fs::metadata(path).map_err(|error| error.to_string())?.is_file() {
        return Err("signature corpus requires regular input files".into());
    }
    let file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    let size = metadata.len();
    if !metadata.is_file() || size > limit {
        return Err(format!("signature corpus input exceeds {} MiB", limit / (1024 * 1024)));
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).map_err(|error| error.to_string())?;
    if bytes.len() as u64 != size {
        return Err("signature corpus input changed length while reading".into());
    }
    Ok(bytes)
}

fn owned_names(
    paths: &[PathBuf],
    architecture: object::Architecture,
    format: object::BinaryFormat,
) -> Result<(BTreeSet<String>, Vec<String>), String> {
    if paths.is_empty() || paths.len() > signature_corpus_support::MAX_LIBRARY_OBJECTS {
        return Err("signature corpus requires 1..2048 explicit library objects".into());
    }
    let mut names = BTreeSet::new();
    let mut hashes = Vec::new();
    for path in paths {
        let bytes = read(path)?;
        hashes.push(digest(&bytes));
        let file = object::File::parse(bytes.as_slice()).map_err(|error| error.to_string())?;
        if file.architecture() != architecture
            || file.kind() != object::ObjectKind::Relocatable
            || file.format() != format
        {
            return Err(format!("{}: expected a same-format, same-architecture library object", path.display()));
        }
        for symbol in file.symbols() {
            if symbol.is_undefined()
                || symbol.kind() != object::SymbolKind::Text
                || !symbol.is_global()
                || symbol.is_weak()
                || !public_definition(&file, &symbol)
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

fn public_definition(file: &object::File<'_>, symbol: &object::Symbol<'_, '_>) -> bool {
    match file.format() {
        object::BinaryFormat::Elf => {
            matches!(symbol.flags().elf_visibility(), Some(object::elf::STV_DEFAULT | object::elf::STV_PROTECTED))
        }
        object::BinaryFormat::Coff | object::BinaryFormat::Pe => {
            symbol.section_index().and_then(|index| file.section_by_index(index).ok()).is_some_and(|section| {
                matches!(section.flags(), object::SectionFlags::Coff { characteristics }
                    if characteristics.contains(object::pe::IMAGE_SCN_CNT_CODE)
                        && characteristics.contains(object::pe::IMAGE_SCN_MEM_EXECUTE))
            })
        }
        _ => false,
    }
}

struct ProcedureEvidence {
    provenance: rampage_loaders::pdb::PdbProvenance,
    public_definitions: BTreeSet<(u64, String)>,
}

fn procedure_symbols(
    procedures: Vec<rampage_loaders::pdb::PdbProcedure>,
) -> (Vec<rampage_loaders::Symbol>, BTreeSet<(u64, String)>) {
    let public = procedures
        .iter()
        .filter(|procedure| procedure.global)
        .map(|procedure| (procedure.address, procedure.name.clone()))
        .collect();
    let symbols = procedures
        .into_iter()
        .map(|procedure| rampage_loaders::Symbol {
            name: procedure.name,
            address: procedure.address,
            size: procedure.size,
            kind: rampage_loaders::SymbolKind::Function,
        })
        .collect();
    (symbols, public)
}

fn load_procedures(binary: &mut Binary, pdb: Option<&Path>) -> Result<Option<ProcedureEvidence>, String> {
    if binary.format != rampage_loaders::Format::Pe {
        if pdb.is_some() {
            return Err("explicit PDB procedure truth requires a PE image".into());
        }
        return Ok(None);
    }
    let pdb = pdb.ok_or("PE corpus requires explicit --pdb and --target-pdb producer sizes")?;
    let (procedures, provenance) =
        rampage_loaders::pdb::matched_procedures_checked(binary, pdb).map_err(|error| error.to_string())?;
    let (symbols, public_definitions) = procedure_symbols(procedures);
    binary.symbols = symbols;
    Ok(Some(ProcedureEvidence { provenance, public_definitions }))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(bytes).map_err(|error| error.to_string())
}

fn open_image(path: &Path) -> Result<Binary, String> {
    let bytes = read(path)?;
    let binary = Binary::open(path).map_err(|error| error.to_string())?;
    if bytes != binary.image_bytes() {
        return Err("selected image changed between bounded read and loader admission".into());
    }
    Ok(binary)
}

fn retain_definitions(
    symbols: &mut Vec<rampage_loaders::Symbol>,
    names: &BTreeSet<String>,
    owned: &BTreeSet<(u64, String)>,
) -> Result<(), String> {
    let mut addresses = BTreeMap::new();
    for (address, name) in owned.iter().filter(|(_, name)| names.contains(name)) {
        if addresses.insert(name, address).is_some_and(|previous| previous != address) {
            return Err(format!("ambiguous global linked library definition {name}"));
        }
    }
    symbols.retain(|symbol| names.contains(&symbol.name) && owned.contains(&(symbol.address, symbol.name.clone())));
    Ok(())
}

fn retain_owned(binary: &mut Binary, names: &BTreeSet<String>, pdb: Option<&ProcedureEvidence>) -> Result<(), String> {
    if binary.format == rampage_loaders::Format::Pe {
        let pdb = pdb.ok_or("PE ownership requires explicit PDB procedure binding evidence")?;
        return retain_definitions(&mut binary.symbols, names, &pdb.public_definitions);
    }
    let file = object::File::parse(binary.image_bytes()).map_err(|error| error.to_string())?;
    let mut owned = BTreeSet::new();
    for symbol in file.symbols().filter(|symbol| {
        symbol.is_global()
            && !symbol.is_weak()
            && !symbol.is_undefined()
            && symbol.kind() == object::SymbolKind::Text
            && public_definition(&file, symbol)
    }) {
        let name = symbol.name().map_err(|error| error.to_string())?;
        if names.contains(name) {
            let address = if binary.arch == rampage_arch::Arch::Arm { symbol.address() & !1 } else { symbol.address() };
            owned.insert((address, name.to_owned()));
        }
    }
    retain_definitions(&mut binary.symbols, names, &owned)
}

fn append_collision_evidence(
    reference: &mut Binary,
    all_symbols: Vec<rampage_loaders::Symbol>,
    owned_addresses: &BTreeSet<u64>,
) {
    reference.symbols.extend(
        all_symbols
            .into_iter()
            .filter(|symbol| {
                symbol.kind == rampage_loaders::SymbolKind::Function && !owned_addresses.contains(&symbol.address)
            })
            .map(|mut symbol| {
                symbol.name = format!("{NEGATIVE_PREFIX}{:x}", symbol.address);
                symbol
            }),
    );
}

fn diagnostic_body(
    database: &SignatureDb,
    binary: &Binary,
    address: u64,
    end: Option<u64>,
    callees: &BTreeMap<u64, String>,
    name_source: &str,
) -> Value {
    let body = end.and_then(|end| end.checked_sub(address)).and_then(|size| binary.read(address, size));
    let Some(body) = body else {
        return json!({"start":format!("{address:#x}"),"end":end.map(|end|format!("{end:#x}")),"available":false});
    };
    let mut evidence =
        json!(database.explain_in(&binary.target(), &MaskContext::from_binary(binary), body, address, callees));
    if let Some(inputs) = evidence["known_callee_inputs"].as_array_mut() {
        for input in inputs {
            input["synthetic_reference_label"] = json!(
                name_source == "reference_supplied_labels"
                    && input["name_preview"]
                        .as_str()
                        .is_some_and(|name| name.starts_with("__rampage_corpus_negative_"))
            );
        }
    }
    json!({"start":format!("{address:#x}"),"end":end.map(|end|format!("{end:#x}")),"available":true,
        "raw_sha256":digest(body),"bytes":body.len(),
        "callee_name_input_source":name_source,"match_evidence":evidence})
}

fn paired_reference<'a>(
    symbols: &'a [rampage_loaders::Symbol],
    target: &rampage_loaders::Symbol,
    ownership: Option<&(ownership::OwnershipReceipt, ownership::OwnershipReceipt)>,
) -> Option<&'a rampage_loaders::Symbol> {
    if let Some((reference, linked_target)) = ownership {
        let source = linked_target.definitions.iter().find(|definition| {
            definition.address == target.address && definition.raw_name == target.name && definition.size == target.size
        })?;
        let original = reference.definitions.iter().find(|definition| {
            definition.object_index == source.object_index
                && definition.source_symbol_index == source.source_symbol_index
        })?;
        symbols.iter().find(|symbol| {
            symbol.address == original.address && symbol.name == original.raw_name && symbol.size == original.size
        })
    } else {
        symbols.iter().find(|original| original.name == target.name)
    }
}

fn run(arguments: Arguments) -> Result<(), String> {
    let linked_paths = arguments.linked_paths()?;
    let mut reference = open_image(&arguments.reference)?;
    let target = open_image(&arguments.target)?;
    let stripped = open_image(&arguments.stripped)?;
    let reference_pdb = load_procedures(&mut reference, arguments.pdb.as_deref())?;
    let reference_file = object::File::parse(reference.image_bytes()).map_err(|error| error.to_string())?;
    let architecture = reference_file.architecture();
    let object_format = match reference_file.format() {
        object::BinaryFormat::Pe => object::BinaryFormat::Coff,
        format => format,
    };
    if digest(reference.image_bytes()) == digest(target.image_bytes()) {
        return Err("reference and target must be different linked programs, not copies of one image".into());
    }
    let reference_model = reference.target();
    let target_model = target.target();
    if reference.format != target.format
        || reference_model.arch != target_model.arch
        || reference_model.big_endian != target_model.big_endian
        || reference_model.data_big_endian != target_model.data_big_endian
    {
        return Err("reference and target library builds have different targets".into());
    }
    let reference_extents = discovered_extents(&reference).map_err(|error| error.to_string())?;
    let all_reference_symbols = reference.symbols.clone();
    let mut target_truth = open_image(&arguments.target)?;
    let target_pdb = load_procedures(&mut target_truth, arguments.target_pdb.as_deref())?;
    let linked_inputs = linked_paths
        .map(|(reference_map, target_map, receipts)| {
            LinkedInputs::load(&arguments.objects, reference_map, target_map, receipts)
        })
        .transpose()?;
    let (names, mut object_hashes, linked_ownership) = if let Some(inputs) = &linked_inputs {
        let reference_receipt = inputs.collect(&reference, true)?;
        let target_receipt = inputs.collect(&target_truth, false)?;
        let names = reference_receipt.definitions.iter().map(|definition| definition.raw_name.clone()).collect();
        apply_definitions(&mut reference, &reference_receipt);
        apply_definitions(&mut target_truth, &target_receipt);
        (names, inputs.object_hashes(), Some((reference_receipt, target_receipt)))
    } else {
        let (names, hashes) = owned_names(&arguments.objects, architecture, object_format)?;
        retain_owned(&mut reference, &names, reference_pdb.as_ref())?;
        retain_owned(&mut target_truth, &names, target_pdb.as_ref())?;
        (names, hashes, None)
    };
    let owned_symbols = reference.symbols.clone();
    let owned_addresses: BTreeSet<_> = canonical_functions(&reference).keys().copied().collect();
    if names.iter().any(|name| name.starts_with(NEGATIVE_PREFIX)) {
        return Err("library name conflicts with the corpus negative-example namespace".into());
    }
    append_collision_evidence(&mut reference, all_reference_symbols, &owned_addresses);
    if linked_ownership.is_none() {
        for (role, symbols) in [("reference", &owned_symbols), ("target", &target_truth.symbols)] {
            let retained: BTreeSet<_> = symbols
                .iter()
                .filter(|symbol| symbol.kind == rampage_loaders::SymbolKind::Function && symbol.size > 0)
                .map(|symbol| symbol.name.clone())
                .collect();
            let missing: Vec<_> = names.difference(&retained).take(8).collect();
            if !missing.is_empty() {
                return Err(format!(
                    "{role} dropped or lost sized library definitions: {missing:?}; disable linker GC"
                ));
            }
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
    let starter = frozen_starter(reference.arch)?;
    let baseline_available = starter.is_some();
    let baseline_source = if baseline_available { "frozen_musl_starter_scheme2" } else { "empty_no_starter" };
    let baseline = match starter {
        Some(source) => SignatureDb::from_json(source).map_err(|error| error.to_string())?,
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
    let measured_proposals = proposals(&measured_database, &stripped).map_err(|error| error.to_string())?;
    let final_names: BTreeMap<_, _> = measured_proposals
        .iter()
        .filter_map(|(address, name)| name.as_ref().map(|name| (*address, name.clone())))
        .collect();
    let after = score(measured_proposals, &truth);
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
        let Some(original) = paired_reference(&owned_symbols, symbol, linked_ownership.as_ref()) else { continue };
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
    let mut diagnostic_rows = Vec::new();
    if arguments.diagnostic_limit > 0 {
        let target_extents = discovered_extents(&stripped).map_err(|error| error.to_string())?;
        let reference_names = canonical_functions(&reference)
            .into_iter()
            .map(|(address, symbol)| (address, symbol.name.clone()))
            .collect();
        for symbol in canonical_functions(&target_truth).values().take(usize::from(arguments.diagnostic_limit)) {
            let Some(original) = paired_reference(&owned_symbols, symbol, linked_ownership.as_ref()) else { continue };
            diagnostic_rows.push(json!({"name":symbol.name,
                "final_proposal":final_names.get(&symbol.address),
                "reference_symbol":diagnostic_body(&measured_database,&reference,original.address,
                    original.address.checked_add(original.size),&reference_names,"reference_supplied_labels"),
                "reference_discovered":diagnostic_body(&measured_database,&reference,original.address,
                    reference_extents.get(&original.address).copied(),&reference_names,"reference_supplied_labels"),
                "target_symbol":diagnostic_body(&measured_database,&stripped,symbol.address,
                    symbol.address.checked_add(symbol.size),&final_names,"final_measured_proposals"),
                "target_discovered":diagnostic_body(&measured_database,&stripped,symbol.address,
                    target_extents.get(&symbol.address).copied(),&final_names,"final_measured_proposals")}));
        }
    }
    let gzip_path = PathBuf::from(format!("{}.gz", arguments.output.display()));
    object_hashes.sort();
    let mut report = json!({
        "schema_version":1,"measurement":"phase2-1-library-signatures",
        "collector_source_sha256":digest(include_bytes!("signature_corpus.rs")),
        "collector_support_sha256":digest(include_bytes!("signature_corpus_support/mod.rs")),
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
        "diagnostic_matrix":diagnostic_rows,"diagnostic_rows_omitted":truth.0.len()-diagnostic_rows.len(),
        "diagnostic_matrix_requested":arguments.diagnostic_limit>0,
        "ownership_scope":concat!(
            "externally visible strong ELF or public executable COFF function definitions only; ",
            "local, hidden and weak definitions excluded"
        ),
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
            concat!("Names are selected by unique externally visible strong object definitions; ",
                "static, hidden and weak coverage is not measured.")
        ]
    });
    report["pe_strip_source_sha256"] = json!(digest(include_bytes!("../src/strip_pe.rs")));
    let metadata = report.as_object_mut().ok_or("corpus report is not an object")?;
    metadata.insert(
        "collector_ownership_sha256".into(),
        json!(digest(include_bytes!("signature_corpus_support/ownership.rs"))),
    );
    metadata.insert(
        "collector_linked_inputs_sha256".into(),
        json!(digest(include_bytes!("signature_corpus_support/linked_inputs.rs"))),
    );
    report["producer_range_source"] = json!(if reference_pdb.is_some() {
        "explicit_identity_matched_pdb_procedures"
    } else {
        "sized_linked_function_symbols"
    });
    report["reference_pdb_sha256"] =
        json!(reference_pdb.as_ref().map(|pdb| rampage_arch::hex::bytes(pdb.provenance.sha256())));
    report["target_pdb_sha256"] =
        json!(target_pdb.as_ref().map(|pdb| rampage_arch::hex::bytes(pdb.provenance.sha256())));
    report["baseline_source"] = json!(baseline_source);
    report["baseline_source_sha256"] = json!(starter.map(|source| digest(source.as_bytes())));
    if reference_pdb.is_some() {
        report["pe_procedure_ownership"] = json!(concat!(
            "Only producer-global PDB raw-name/address pairs can enter public-strong truth; ",
            "local procedures remain synthetic nonlibrary collision negatives; duplicate global names refuse scope"
        ));
    }
    report["ownership_scope_id"] = json!("public_strong");
    if let (Some(inputs), Some((reference_receipt, target_receipt))) = (&linked_inputs, &linked_ownership) {
        let metadata = report.as_object_mut().ok_or("corpus report is not an object")?;
        metadata.insert("ownership_scope".into(), json!("linked_artifact"));
        metadata.insert("ownership_scope_id".into(), json!("linked_artifact"));
        metadata.insert("member_receipts_sha256".into(), json!(inputs.receipt_sha256()));
        metadata.insert(
            "member_ordinal_basis".into(),
            json!("zero-based object 0.40 ArchiveFile::members order, after recognized leading ar index/name tables"),
        );
        metadata.insert("reference_map_path".into(), json!(arguments.reference_map));
        metadata.insert("target_map_path".into(), json!(arguments.target_map));
        metadata.insert("reference_map_sha256".into(), json!(reference_receipt.map_sha256));
        metadata.insert("target_map_sha256".into(), json!(target_receipt.map_sha256));
        metadata.insert("member_receipts_path".into(), json!(arguments.member_receipts));
        metadata.insert("reference_ownership".into(), json!(reference_receipt));
        metadata.insert("target_ownership".into(), json!(target_receipt));
        metadata.insert(
            "producer_range_source".into(),
            json!("producer_object_symbol_sizes_cross_checked_against_kept_map_and_linked_FUNC_symbols"),
        );
        let limitations =
            metadata.get_mut("limitations").and_then(Value::as_array_mut).ok_or("missing corpus limitations")?;
        limitations.pop();
        limitations.extend([
            json!("Only unambiguous kept ELF native definitions are measured; excluded/unresolved rows are explicit."),
            json!("Local archive/object receipts are unsigned claims, not publisher or source-release authentication."),
            json!("Linked native-member subset only; no full SDK/runtime or source-corpus coverage is claimed."),
            json!("Target symbols are truth/diagnostic-only, never inputs to held-out name lookup."),
        ]);
    }
    for path in [&arguments.output, &gzip_path, &arguments.report] {
        if path.try_exists().map_err(|error| error.to_string())? {
            return Err(format!("{}: refusing to overwrite an existing artifact", path.display()));
        }
    }
    reference.validate_backing_source().map_err(|error| error.to_string())?;
    target.validate_backing_source().map_err(|error| error.to_string())?;
    target_truth.validate_backing_source().map_err(|error| error.to_string())?;
    stripped.validate_backing_source().map_err(|error| error.to_string())?;
    if let Some(inputs) = &linked_inputs {
        inputs.validate_current()?;
    }
    for pdb in [reference_pdb, target_pdb].into_iter().flatten() {
        pdb.provenance.validate_current().map_err(|error| error.to_string())?;
    }
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

    #[allow(dead_code)]
    fn cli() -> Vec<&'static str> {
        vec![
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
        ]
    }

    #[test]
    fn linked_scope_requires_explicit_maps_and_receipts_without_changing_default() {
        let mut missing = cli();
        missing.extend(["--ownership-scope", "linked-artifact"]);
        assert!(Arguments::try_parse_from(&missing).is_err());
        missing.extend([
            "--reference-map",
            "reference.map",
            "--target-map",
            "target.map",
            "--member-receipts",
            "members.json",
        ]);
        let arguments = Arguments::try_parse_from(&missing).unwrap();
        assert_eq!(arguments.ownership_scope, OwnershipScope::LinkedArtifact);
        assert!(arguments.linked_paths().unwrap().is_some());
        missing.extend(["--pdb", "ref.pdb", "--target-pdb", "target.pdb"]);
        assert!(Arguments::try_parse_from(&missing).unwrap().linked_paths().is_err());
        let mut implicit = cli();
        implicit.extend(["--reference-map", "reference.map"]);
        assert!(Arguments::try_parse_from(&implicit).unwrap().linked_paths().is_err());
    }

    #[test]
    fn same_named_pdb_local_is_negative_evidence_not_public_truth_and_two_globals_refuse() {
        use fixture_support::{TempFiles, fixture, module_stream, stream_offset};
        let mut bytes = read(&fixture("fixture.pdb")).unwrap();
        let start = stream_offset(&bytes, module_stream(&bytes), 0);
        let name = bytes[start..start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
        let record = start + name - 39;
        assert_eq!(&bytes[record + 2..record + 4], &0x110fu16.to_le_bytes());
        bytes[start + name..start + name + 10].copy_from_slice(b"pdb_mix\0\0\0");
        let files = TempFiles::new();
        let path = files.write("local-global.pdb", &bytes);
        let mut image = Binary::open(fixture("fixture.exe")).unwrap();
        let evidence = load_procedures(&mut image, Some(&path)).unwrap().unwrap();
        let all_symbols = image.symbols.clone();
        assert_eq!(all_symbols.iter().filter(|symbol| symbol.name == "pdb_mix").count(), 2);
        let names = BTreeSet::from(["pdb_mix".to_owned()]);
        retain_owned(&mut image, &names, Some(&evidence)).unwrap();
        assert_eq!(image.symbols.len(), 1);
        assert_eq!((image.symbols[0].address, image.symbols[0].size), (0x140001000, 30));
        let owned_addresses = canonical_functions(&image).keys().copied().collect();
        append_collision_evidence(&mut image, all_symbols, &owned_addresses);
        assert!(image.symbols.iter().any(|symbol| {
            symbol.address == 0x140001020 && symbol.size == 15 && symbol.name.starts_with(NEGATIVE_PREFIX)
        }));
        bytes[record + 2..record + 4].copy_from_slice(&0x1110u16.to_le_bytes());
        let path = files.write("two-globals.pdb", &bytes);
        let evidence = load_procedures(&mut image, Some(&path)).unwrap().unwrap();
        assert!(retain_owned(&mut image, &names, Some(&evidence)).unwrap_err().contains("ambiguous global"));
    }

    #[test]
    fn changed_member_receipt_file_is_refused_before_publication() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin");
        let files = fixture_support::TempFiles::new();
        let object = read(&root.join("eval-program-corpus-x86_64.o")).unwrap();
        let object_path = files.write("lib.o", &object);
        let mut archive = b"!<arch>\n".to_vec();
        archive.extend_from_slice(
            format!("{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", "lib.o/", 0, 0, 0, 644, object.len()).as_bytes(),
        );
        archive.extend_from_slice(&object);
        if object.len() % 2 != 0 {
            archive.push(b'\n');
        }
        let archive_path = files.write("lib.a", &archive);
        let map = files.write("link.map", b"             VMA              LMA     Size Align Out     In      Symbol\n");
        let receipts = serde_json::to_vec(&json!([{
            "archive_path":archive_path, "archive_sha256":digest(&archive), "member_ordinal":0,
            "original_name":"lib.o", "object_path":object_path, "object_sha256":digest(&object), "size":object.len(),
        }]))
        .unwrap();
        let receipts_path = files.write("members.json", &receipts);
        let inputs = LinkedInputs::load(&[object_path], &map, &map, &receipts_path).unwrap();
        inputs.validate_current().unwrap();
        std::fs::write(&receipts_path, b"[]\n").unwrap();
        assert!(inputs.validate_current().unwrap_err().contains("changed before publication"));
    }

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
        assert_eq!(arguments.ownership_scope, OwnershipScope::PublicStrong);
        assert!(arguments.linked_paths().unwrap().is_none());
    }

    #[test]
    fn library_ownership_excludes_local_data_and_undefined_symbols_in_real_objects() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin");
        let object = root.join("eval-program-corpus-x86_64.o");
        let (names, hashes) =
            owned_names(std::slice::from_ref(&object), object::Architecture::X86_64, object::BinaryFormat::Elf)
                .unwrap();
        assert_eq!(names, BTreeSet::from(["main".to_owned()]));
        assert_eq!(hashes, vec![digest(&read(&object).unwrap())]);
        assert!(
            owned_names(std::slice::from_ref(&object), object::Architecture::X86_64, object::BinaryFormat::Coff)
                .is_err()
        );
        assert!(owned_names(&[object], object::Architecture::Aarch64, object::BinaryFormat::Elf).is_err());
        let mut image = Binary::open(root.join("eval-ref-x86_64.elf")).unwrap();
        assert!(image.symbols.iter().any(|symbol| symbol.name == "cmp"));
        retain_owned(&mut image, &BTreeSet::from(["main".into(), "cmp".into(), "sink".into()]), None).unwrap();
        assert_eq!(image.symbols.len(), 1);
        assert_eq!(image.symbols[0].name, "main");
    }

    #[test]
    fn coff_public_definitions_require_an_executable_code_section() {
        let mut bytes = vec![0u8; 83];
        bytes[..2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&61u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        bytes[20..25].copy_from_slice(b".text");
        bytes[36..40].copy_from_slice(&1u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&60u32.to_le_bytes());
        bytes[56..60].copy_from_slice(&0x60000020u32.to_le_bytes());
        bytes[60] = 0xc3;
        bytes[61..66].copy_from_slice(b"owned");
        bytes[73..75].copy_from_slice(&1u16.to_le_bytes());
        bytes[75..77].copy_from_slice(&0x20u16.to_le_bytes());
        bytes[77] = 2;
        bytes[79..83].copy_from_slice(&4u32.to_le_bytes());
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let symbol = file.symbols().next().unwrap();
        assert!(symbol.is_global() && !symbol.is_weak() && !symbol.is_undefined());
        assert_eq!(symbol.kind(), object::SymbolKind::Text);
        assert!(public_definition(&file, &symbol));
        bytes[56..60].copy_from_slice(&0x40000040u32.to_le_bytes());
        let file = object::File::parse(bytes.as_slice()).unwrap();
        assert!(!public_definition(&file, &file.symbols().next().unwrap()));
    }

    #[test]
    fn training_image_recognition_is_rejected_before_measurement_or_output() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin");
        let image = root.join("eval-ref-x86_64.elf");
        let error = run(Arguments {
            reference: image.clone(),
            pdb: None,
            target_pdb: None,
            target: image.clone(),
            stripped: image.clone(),
            objects: vec![root.join("eval-program-corpus-x86_64.o")],
            ownership_scope: OwnershipScope::PublicStrong,
            reference_map: None,
            target_map: None,
            member_receipts: None,
            output: image.clone(),
            report: image,
            diagnostic_limit: 0,
        })
        .unwrap_err();
        assert!(error.contains("different linked programs"), "{error}");
    }

    #[test]
    #[ignore = "requires RAMPAGE_SIGNATURE_LUA_OBJECT pointing to the compiled Lua lstate.c object"]
    fn hidden_library_internals_are_not_mistaken_for_missing_public_definitions() {
        let path = PathBuf::from(std::env::var_os("RAMPAGE_SIGNATURE_LUA_OBJECT").expect("explicit Lua object"));
        let (names, _) = owned_names(&[path], object::Architecture::X86_64, object::BinaryFormat::Elf).unwrap();
        assert!(names.contains("lua_newstate"));
        assert!(!names.contains("luaE_checkcstack"));
        assert!(!names.contains("close_state"));
    }
}
