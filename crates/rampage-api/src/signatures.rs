//! Library-function identification: build a signature database from a binary whose functions are named, and
//! apply one to name the matching functions of another binary (see `rampage-signatures`).

use std::collections::BTreeMap;

use rampage_analysis::discover::Program;
use rampage_loaders::Binary;
use rampage_signatures::{CallGraph, MaskContext, SignatureDb, identify_program_sources};
use serde::Serialize;

use crate::packs::BUILTIN_PACK;
use crate::workflows::is_default_name;
use crate::{ApiError, Project};

/// The [`SignatureMatch::source`] of a match from a database the caller supplied (`--db`, `database`).
pub const USER_SIGNATURES: &str = "user database";

/// The [`SignatureMatch::source`] of a name the bundled call graph gave: where an already-named caller calls the
/// function, as training builds of the same library do (`rampage_signatures::callgraph`). Firmware that gets the
/// embedded signature set propagates with the embedded firmware call graph instead of the host-library one
/// (`rampage_signatures::bundled_call_graph_for`).
pub const CALL_GRAPH: &str = "rampage-builtin call graph";

/// The [`SignatureMatch::source`] of a name the bundled embedded firmware set gave (newlib, libgcc, compiler-rt,
/// FreeRTOS, STM32F4 HAL), consulted for firmware-like Thumb targets only (`rampage_signatures::firmware_like`).
pub const EMBEDDED_SIGNATURES: &str = "rampage-builtin embedded";

/// The [`SignatureMatch::source`] of a name the embedded set's operand tier gave
/// (`rampage_signatures::bundled_embedded_operands_for`): a coarser match than [`EMBEDDED_SIGNATURES`], equal to a
/// library body up to load/store offsets and stack adjustments, consulted only where the embedded set has no answer.
pub const EMBEDDED_OPERAND_SIGNATURES: &str = "rampage-builtin embedded operands";

#[derive(Debug, Serialize)]
pub struct SignatureMatch {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// The name the signature database proposes.
    pub name: String,
    /// Whether the function is currently unnamed (a `sub_<hex>` default), so naming it adds information.
    pub unnamed: bool,
    /// The database that named it: [`USER_SIGNATURES`], the name of the data pack that holds it,
    /// [`BUILTIN_PACK`] for the corpus bundled with rampage, [`EMBEDDED_SIGNATURES`] for the bundled embedded
    /// firmware set, or [`CALL_GRAPH`] for a name the bundled call graph gave from an already-named caller.
    pub source: String,
}

impl SignatureMatch {
    /// The database that named the function, for prose: "the bundled signature corpus", "data pack `x`".
    pub fn origin(&self) -> String {
        signature_origin(&self.source)
    }
}

/// [`SignatureMatch::origin`] for a match `source`.
pub(crate) fn signature_origin(source: &str) -> String {
    match source {
        BUILTIN_PACK => "the bundled signature corpus".to_owned(),
        EMBEDDED_SIGNATURES => "the bundled embedded firmware signatures".to_owned(),
        EMBEDDED_OPERAND_SIGNATURES => {
            "the bundled embedded firmware signatures' operand tier (equal up to structure offsets and stack slots)"
                .to_owned()
        }
        CALL_GRAPH => "the bundled call graph (from an already-named caller)".to_owned(),
        USER_SIGNATURES => "the user-supplied database".to_owned(),
        pack => format!("data pack `{pack}`"),
    }
}

#[derive(Debug, Serialize)]
pub struct SignatureApplication {
    pub matched: usize,
    pub applied: usize,
    pub matches: Vec<SignatureMatch>,
    /// Data-pack problems bearing on signatures (a rejected pack, a signature database that did not load), so that
    /// a partly loaded set of databases is not taken for a complete one.
    pub warnings: Vec<String>,
}

impl Project {
    /// Builds a signature database from this binary's named functions, over both their symbol sizes and the
    /// extents discovery finds for them here. Identification hashes the extents discovery finds in a stripped
    /// target, which match these only where discovery cuts both copies of a function short in the same place.
    pub fn build_signatures(&self) -> SignatureDb {
        let extents = match self.analysis() {
            Ok(analysis) => {
                analysis.program.functions.iter().map(|function| (function.address, function.end())).collect()
            }
            Err(_) => BTreeMap::new(),
        };
        SignatureDb::from_binary_with_extents(&self.binary, &extents)
    }

    /// Identifies discovered functions against `database`. When `apply` is set, matches for functions that are
    /// still unnamed are saved as user names (existing names and user edits are never overwritten).
    pub fn apply_signatures(&self, database: &SignatureDb, apply: bool) -> Result<SignatureApplication, ApiError> {
        self.apply_layered_signatures(&[(USER_SIGNATURES, database)], apply)
    }

    /// Identifies discovered functions against each database in order; the first that names a function wins.
    /// Layering instead of merging lets databases built with different hash schemes coexist.
    fn apply_layered_signatures(
        &self,
        databases: &[(&str, &SignatureDb)],
        apply: bool,
    ) -> Result<SignatureApplication, ApiError> {
        self.apply_layered_signatures_with_preflight(databases, None, apply, Vec::new(), |_| Ok(()))
    }

    fn apply_layered_signatures_with_preflight(
        &self,
        databases: &[(&str, &SignatureDb)],
        call_graph: Option<&CallGraph>,
        apply: bool,
        warnings: Vec<String>,
        preflight: impl FnOnce(&SignatureApplication) -> Result<(), ApiError>,
    ) -> Result<SignatureApplication, ApiError> {
        for (_, database) in databases {
            database.ensure_byte_matching_supported().map_err(|error| ApiError::Invalid(error.to_string()))?;
        }
        if databases.is_empty() {
            let application = SignatureApplication { matched: 0, applied: 0, matches: Vec::new(), warnings };
            preflight(&application)?;
            return Ok(application);
        }
        let analysis = self.analysis()?;
        let bodies: Vec<(u64, &[u8])> = analysis
            .program
            .functions
            .iter()
            .filter_map(|function| Some((function.address, function.body(&self.binary)?)))
            .collect();
        let image = MaskContext::from_binary(&self.binary);
        let only: Vec<&SignatureDb> = databases.iter().map(|&(_, database)| database).collect();
        let names = identify_program_sources(&only, &self.binary.target(), &image, &bodies);
        let mut found: BTreeMap<u64, (String, String)> = names
            .into_iter()
            .map(|(address, (index, name))| (address, (name.into_owned(), databases[index].0.to_owned())))
            .collect();
        if let Some(graph) = call_graph {
            let named: BTreeMap<u64, String> =
                found.iter().map(|(address, (name, _))| (*address, name.clone())).collect();
            let existing = self.existing_names(&analysis.program);
            let calls = call_sequences(&self.binary, &analysis.program);
            let arch = self.binary.arch.to_string();
            for (address, name) in call_graph_names(graph, &arch, &calls, &named, &existing) {
                found.entry(address).or_insert((name, CALL_GRAPH.to_owned()));
            }
        }
        let mut matches = Vec::new();
        for (address, (name, source)) in found {
            let current = self.function_name(address);
            matches.push(SignatureMatch { address, name, unnamed: is_default_name(&current, address), source });
        }

        let mut application = SignatureApplication { matched: matches.len(), applied: 0, matches, warnings };
        preflight(&application)?;
        if apply {
            // Several matches can share a name: instances of one generic Zig declaration, once their counters
            // are dropped (`canonical_name`). Each later one is applied as `name@2`, `name@3`, in address order.
            let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
            for candidate in application.matches.iter().filter(|candidate| candidate.unnamed) {
                let count = seen.entry(candidate.name.as_str()).or_insert(0);
                *count += 1;
                let name = match *count {
                    1 => candidate.name.clone(),
                    count => format!("{}@{count}", candidate.name),
                };
                // Skip a name already in use elsewhere, so renaming cannot collide.
                if self.rename_if_default(candidate.address, &name).unwrap_or(false) {
                    application.applied += 1;
                }
            }
        }
        Ok(application)
    }

    /// Every discovered function's current name that is not a `sub_<hex>` default (loader symbols, exports, the
    /// analyst's), as identification reports names (`canonical_name`): what call-graph propagation starts from
    /// besides the signature matches.
    pub(crate) fn existing_names(&self, program: &Program) -> BTreeMap<u64, String> {
        program
            .functions
            .iter()
            .map(|function| (function.address, self.function_name(function.address)))
            .filter(|(address, name)| !is_default_name(name, *address))
            .map(|(address, name)| (address, rampage_signatures::canonical_name(&name).into_owned()))
            .collect()
    }

    /// The starter signature database bundled for this binary's architecture, or `None` when none ships for it.
    pub fn bundled_signatures(&self) -> Option<SignatureDb> {
        rampage_signatures::bundled(self.binary.arch)
    }

    /// Identifies functions against an optional `user` database first, then the data packs' databases for this
    /// architecture in pack order, then the bundled databases (so user names win). With no database,
    /// nothing matches.
    pub fn apply_signatures_default(
        &self,
        user: Option<&SignatureDb>,
        apply: bool,
    ) -> Result<SignatureApplication, ApiError> {
        self.identify_functions(user, true, apply)
    }

    /// Identifies functions against an optional `user` database first, then the data packs' databases for this
    /// architecture in pack order, then, with `bundled`, the bundled corpus and, for firmware, the embedded set. Leaving out the bundled
    /// database needs a `user` or pack one, so that the request is never silently empty.
    pub fn identify_functions(
        &self,
        user: Option<&SignatureDb>,
        bundled: bool,
        apply: bool,
    ) -> Result<SignatureApplication, ApiError> {
        self.identify_functions_with_preflight(user, bundled, apply, |_| Ok(()))
    }

    /// Plans the full identification, including pack warnings, then calls `preflight` once before any rename.
    /// A rejected preflight writes nothing. The callback never restricts which matches an apply considers.
    pub fn identify_functions_with_preflight(
        &self,
        user: Option<&SignatureDb>,
        bundled: bool,
        apply: bool,
        preflight: impl FnOnce(&SignatureApplication) -> Result<(), ApiError>,
    ) -> Result<SignatureApplication, ApiError> {
        let packs = self.packs();
        let packed: Vec<(&str, &SignatureDb)> = packs.signatures_for(self.binary.arch).collect();
        if !bundled && user.is_none() && packed.is_empty() {
            return Err(ApiError::Invalid(
                "leaving out the bundled signatures needs a signature database or a pack with one for this \
                 architecture"
                    .to_owned(),
            ));
        }
        let call_graph = if bundled { rampage_signatures::bundled_call_graph_for(&self.binary) } else { None };
        // The corpus, then (firmware) the embedded set and its operand tier: different hash schemes, so layered.
        let corpus = bundled.then(|| rampage_signatures::bundled_ref(self.binary.arch)).flatten();
        let embedded = bundled.then(|| rampage_signatures::bundled_embedded_for(&self.binary)).flatten();
        // Its operand tier (scheme 4) answers only where the embedded set has no answer.
        let operands = bundled.then(|| rampage_signatures::bundled_embedded_operands_for(&self.binary)).flatten();
        let user = user.map(|database| (USER_SIGNATURES, database));
        let bundled = corpus
            .map(|database| (BUILTIN_PACK, database))
            .into_iter()
            .chain(embedded.map(|database| (EMBEDDED_SIGNATURES, database)))
            .chain(operands.map(|database| (EMBEDDED_OPERAND_SIGNATURES, database)));
        let databases: Vec<(&str, &SignatureDb)> = user.into_iter().chain(packed).chain(bundled).collect();
        self.apply_layered_signatures_with_preflight(
            &databases,
            call_graph,
            apply,
            packs.problems_for("signatures"),
            preflight,
        )
    }
}

/// The names the call graph gives one binary, as identification reports them: new names, seeded with the signature
/// names and every name the binary already has (which are never handed out again); and, so a report is the same
/// after its names are applied, the names propagation from the signature names alone gives that a function already
/// has.
pub fn call_graph_names(
    graph: &CallGraph,
    arch: &str,
    calls: &BTreeMap<u64, Vec<u64>>,
    signatures: &BTreeMap<u64, String>,
    existing: &BTreeMap<u64, String>,
) -> BTreeMap<u64, String> {
    call_graph_names_excluding(graph, arch, calls, signatures, existing, None)
}

/// [`call_graph_names`] without the sequences seen only in the build `exclude`: a training binary measured leaving
/// its own build out of a graph made from the training split.
pub fn call_graph_names_excluding(
    graph: &CallGraph,
    arch: &str,
    calls: &BTreeMap<u64, Vec<u64>>,
    signatures: &BTreeMap<u64, String>,
    existing: &BTreeMap<u64, String>,
    exclude: Option<&str>,
) -> BTreeMap<u64, String> {
    let mut seeds = signatures.clone();
    seeds.extend(existing.iter().map(|(address, name)| (*address, name.clone())));
    let mut names = graph.propagate(arch, calls, &seeds, exclude);
    for (address, name) in graph.propagate(arch, calls, signatures, exclude) {
        if existing.get(&address) == Some(&name) {
            names.entry(address).or_insert(name);
        }
    }
    names
}

/// Each discovered function's direct call and unconditional tail-jump targets that start another discovered function,
/// in call-site order: the call sequences call-graph propagation compares with training.
pub fn call_sequences(binary: &Binary, program: &Program) -> BTreeMap<u64, Vec<u64>> {
    let starts: std::collections::BTreeSet<u64> = program.functions.iter().map(|function| function.address).collect();
    let mut calls = BTreeMap::new();
    let Ok(mut decoder) = binary.decoder() else { return calls };
    decoder.set_code_modes(&program.code_modes);
    for function in &program.functions {
        let mut targets = Vec::new();
        for block in &function.blocks {
            let Some(bytes) = block.end.checked_sub(block.start).and_then(|size| binary.read(block.start, size)) else {
                continue;
            };
            decoder.begin_run();
            let mut offset = 0usize;
            while offset < bytes.len() {
                let instruction = decoder.decode(&bytes[offset..], block.start + offset as u64);
                let size = usize::from(instruction.len);
                if size == 0 || size > bytes.len() - offset {
                    break;
                }
                match instruction.flow {
                    rampage_arch::Flow::Call(target) if starts.contains(&target) => targets.push(target),
                    rampage_arch::Flow::Jump(target)
                        if target != function.address && starts.contains(&target) && !function.contains(target) =>
                    {
                        targets.push(target)
                    }
                    _ => {}
                }
                offset += size;
            }
        }
        calls.insert(function.address, targets);
    }
    calls
}

#[cfg(test)]
mod call_graph_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use rampage_signatures::CallGraph;

    use super::call_sequences;
    use crate::Project;
    use crate::workflows::is_default_name;

    fn open(name: &str) -> Project {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/flywheel").join(name);
        Project::new(rampage_loaders::Binary::open(&path).unwrap())
    }

    #[test]
    fn call_sequences_name_callees_through_a_training_call_graph() {
        let twin = open("v1-a.twin.elf");
        let program = &twin.analysis().unwrap().program;
        let calls = call_sequences(&twin.binary, program);
        let starts: BTreeSet<u64> = program.functions.iter().map(|function| function.address).collect();
        assert_eq!(calls.keys().copied().collect::<BTreeSet<_>>(), starts);
        assert!(calls.values().flatten().all(|target| starts.contains(target)));
        assert!(calls.values().any(|targets| !targets.is_empty()));

        let names: BTreeMap<u64, String> = starts
            .iter()
            .map(|&address| (address, twin.function_name(address)))
            .filter(|(address, name)| !is_default_name(name, *address))
            .collect();
        let arch = twin.binary.arch.to_string();
        let mut graph = CallGraph::new("test", "MIT");
        for (caller, targets) in &calls {
            if let Some(name) = names.get(caller) {
                graph.insert(&arch, name, targets.iter().map(|target| names.get(target).cloned()).collect(), None);
            }
        }

        // The stripped copy has the same layout: name each caller alone and propagate from it.
        let stripped = open("v1-a.elf");
        let stripped_calls = call_sequences(&stripped.binary, &stripped.analysis().unwrap().program);
        assert_eq!(stripped_calls, calls);
        let mut total = 0;
        for caller in calls.keys().filter(|caller| names.contains_key(caller)) {
            let known = BTreeMap::from([(*caller, names[caller].clone())]);
            for (address, name) in graph.propagate(&arch, &stripped_calls, &known, None) {
                assert_eq!(names.get(&address), Some(&name), "{address:#x}");
                total += 1;
            }
        }
        assert!(total > 0, "propagation named nothing");
    }
}

/// The most members of a static library a signature database is built from; later ones are left out, counted.
pub const MAX_LIBRARY_MEMBERS: usize = 16_384;

/// What building signatures from a static library did.
#[derive(Debug, Serialize)]
pub struct LibrarySignatureReport {
    pub arch: Option<String>,
    pub members: usize,
    /// Members whose functions went into the database.
    pub members_used: usize,
    /// Members left out, counted by why (an import object, another architecture, not an object file, ...).
    pub skipped: BTreeMap<String, usize>,
    /// Named functions read from the members.
    pub functions: usize,
    /// Hash answers, callee keys and relocation-exact pattern records in the database.
    pub signatures: usize,
    pub callee_keys: usize,
    pub pat_records: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// A database built from a static library, and the report of how.
pub struct LibrarySignatures {
    pub database: SignatureDb,
    pub report: LibrarySignatureReport,
}

/// The bytes of a relocation's field within a function body that a pattern leaves out: what the relocation patched,
/// narrowed to a MIPS instruction's 16-bit immediate for the `%hi`/`%lo`/GOT and GP-relative types.
fn relocated_bytes(site: &rampage_loaders::relocatable::RelocationSite, big_endian: bool) -> std::ops::Range<u64> {
    let mips_immediate = matches!(
        site.kind.as_str(),
        "R_MIPS_HI16"
            | "R_MIPS_LO16"
            | "R_MIPS_GOT16"
            | "R_MIPS_CALL16"
            | "R_MIPS_GPREL16"
            | "R_MIPS_GOT_DISP"
            | "R_MIPS_GOT_PAGE"
            | "R_MIPS_GOT_OFST"
            | "R_MIPS_GOT_HI16"
            | "R_MIPS_GOT_LO16"
            | "R_MIPS_CALL_HI16"
            | "R_MIPS_CALL_LO16"
            | "R_MIPS_PC16"
    );
    if mips_immediate {
        let start = if big_endian { site.address + 2 } else { site.address };
        return start..start + 2;
    }
    let width = if site.field == 0 { 4 } else { u64::from(site.field) };
    site.address..site.address.saturating_add(width)
}

/// Relocation-exact pattern records for the named functions of `binary`, a relocatable object: each function's
/// bytes with the relocated fields left out, over its symbol size and over the extent discovery found for it.
fn object_patterns(binary: &Binary, extents: &BTreeMap<u64, u64>, lines: &mut Vec<String>) -> usize {
    let Some(relocated) = binary.relocated() else { return 0 };
    let functions = rampage_signatures::canonical_functions(binary);
    let big_endian = binary.target().big_endian;
    for symbol in functions.values() {
        let end = symbol.address.saturating_add(symbol.size);
        let discovered = extents.get(&symbol.address).copied().filter(|&found| found != end);
        for end in std::iter::once(end).chain(discovered) {
            let Some(length) = end.checked_sub(symbol.address).filter(|&length| length > 0) else { continue };
            let Some(bytes) = binary.read(symbol.address, length) else { continue };
            let mut body: Vec<Option<u8>> = bytes.iter().copied().map(Some).collect();
            for site in relocated.sites_in(symbol.address.saturating_sub(8)..end) {
                for address in relocated_bytes(site, big_endian) {
                    if let Some(index) = address.checked_sub(symbol.address).filter(|&index| index < length) {
                        body[index as usize] = None;
                    }
                }
            }
            // A field left unapplied holds the object's bytes, which a linked copy does not.
            for &(address, width) in &relocated.unapplied_widths {
                for byte in address..address.saturating_add(u64::from(width)) {
                    if let Some(index) = byte.checked_sub(symbol.address).filter(|&index| index < length) {
                        body[index as usize] = None;
                    }
                }
            }
            lines.extend(rampage_signatures::pat_record(&symbol.name, &body));
        }
    }
    functions.len()
}

/// Why a library member's bytes are no object to build signatures from, judged by its format before loading it.
fn member_skip_reason(bytes: &[u8]) -> Option<&'static str> {
    match object::FileKind::parse(bytes) {
        Ok(object::FileKind::CoffImport) => Some("short import object"),
        Ok(
            object::FileKind::Coff | object::FileKind::CoffBig | object::FileKind::MachO64 | object::FileKind::MachO32,
        ) => None,
        Ok(object::FileKind::Elf32 | object::FileKind::Elf64) => None,
        Ok(_) => Some("not an object file"),
        Err(_) if bytes.starts_with(&[0, 0]) && object::read::coff::CoffFile::<&[u8]>::parse(bytes).is_ok() => {
            Some("machine-independent COFF object (aliases only)")
        }
        Err(_) => Some("not an object file"),
    }
}

/// Builds a signature database from every relocatable object in the static library at `path` (an `ar` archive,
/// an MSVC `.lib`, or the `arch` slice of a universal library): masked-hash signatures as for a binary, plus
/// relocation-exact patterns, which leave out exactly the bytes a relocation patched, where the hashes can only
/// mask what an instruction's form says may move (MIPS `%hi`/`%lo` pairs they keep). Members are read in archive
/// order and the result is the same for the same library.
pub fn build_library_signatures(
    path: &std::path::Path,
    arch: Option<rampage_arch::Arch>,
    cancelled: &dyn Fn() -> bool,
) -> Result<LibrarySignatures, ApiError> {
    let load = |source| ApiError::Load { path: path.to_owned(), source };
    let data = rampage_loaders::ar::map(path).map_err(load)?;
    let library = rampage_loaders::ar::read_library(&data, arch).map_err(load)?;
    let mut report = LibrarySignatureReport {
        arch: None,
        members: library.archive.members.len(),
        members_used: 0,
        skipped: BTreeMap::new(),
        functions: 0,
        signatures: 0,
        callee_keys: 0,
        pat_records: 0,
        warnings: Vec::new(),
    };
    let mut skip = |reason: &str| *report.skipped.entry(reason.to_owned()).or_insert(0) += 1;
    let mut database: Option<SignatureDb> = None;
    let mut lines = Vec::new();
    let mut functions = 0;
    let wanted = arch.or(library.arch);
    let mut load_errors = Vec::new();
    for member in library.archive.members.iter().take(MAX_LIBRARY_MEMBERS) {
        if cancelled() {
            return Err(ApiError::Invalid("signature build cancelled; nothing was written".to_owned()));
        }
        let start = usize::try_from(member.offset).unwrap_or(usize::MAX);
        let bytes = data.get(start..start.saturating_add(usize::try_from(member.size).unwrap_or(usize::MAX)));
        if let Some(reason) = bytes.map_or(Some("truncated"), member_skip_reason) {
            skip(reason);
            continue;
        }
        let binary = match Binary::open_member(path, member.clone(), wanted) {
            Ok(binary) => binary,
            Err(error) => {
                skip("failed to load");
                if load_errors.len() < 4 {
                    load_errors.push(format!("{}: {error}", member.selector()));
                }
                continue;
            }
        };
        if binary.relocated().is_none() {
            skip("not a relocatable object");
            continue;
        }
        if database.as_ref().is_some_and(|database| database.arch() != binary.arch) {
            skip("another architecture");
            continue;
        }
        let project = Project::new(binary);
        let extents: BTreeMap<u64, u64> = match project.analysis() {
            Ok(analysis) => {
                analysis.program.functions.iter().map(|function| (function.address, function.end())).collect()
            }
            Err(_) => BTreeMap::new(),
        };
        match &mut database {
            Some(database) => database
                .try_extend_from_binary_with_extents(&project.binary, &extents)
                .map_err(|error| ApiError::Invalid(error.to_string()))?,
            None => database = Some(SignatureDb::from_binary_with_extents(&project.binary, &extents)),
        }
        let named = object_patterns(&project.binary, &extents, &mut lines);
        if named == 0 {
            skip("no named functions");
            continue;
        }
        functions += named;
        report.members_used += 1;
    }
    report.warnings.extend(load_errors.into_iter().map(|error| format!("member not loaded: {error}")));
    if functions == 0 && database.is_some() {
        return Err(ApiError::Invalid(format!(
            "the objects of {} hold no named function with a size, so no signatures were built ({} members: {})",
            path.display(),
            report.members,
            report.skipped.iter().map(|(reason, count)| format!("{count} {reason}")).collect::<Vec<_>>().join(", ")
        )));
    }
    if library.archive.members.len() > MAX_LIBRARY_MEMBERS {
        report.warnings.push(format!(
            "{} members past the first {MAX_LIBRARY_MEMBERS} were left out",
            library.archive.members.len() - MAX_LIBRARY_MEMBERS
        ));
    }
    let Some(mut database) = database else {
        return Err(ApiError::Invalid(format!(
            "no member of {} is a relocatable object rampage loads, so no signatures were built ({} members: {})",
            path.display(),
            report.members,
            report.skipped.iter().map(|(reason, count)| format!("{count} {reason}")).collect::<Vec<_>>().join(", ")
        )));
    };
    // Patterns within the PAT namespace's own bounds, in archive order.
    let mut text = String::new();
    let mut kept = 0;
    for line in &lines {
        if text.len() + line.len() + 8 > rampage_signatures::MAX_PAT_BYTES
            || kept + 2 > rampage_signatures::MAX_PAT_LINES
        {
            report
                .warnings
                .push(format!("{} pattern records past the PAT size bounds were left out", lines.len() - kept));
            break;
        }
        text.push_str(line);
        text.push('\n');
        kept += 1;
    }
    if kept > 0 {
        text.push_str("---\n");
        match rampage_signatures::PatternDb::parse(database.arch(), text.as_bytes()) {
            Ok(patterns) => {
                if let Err(error) = database.set_patterns(Some(patterns)) {
                    report.warnings.push(format!("pattern records not kept: {error}"));
                }
            }
            Err(error) => report.warnings.push(format!("pattern records not kept: {error}")),
        }
    }
    report.arch = Some(database.arch().to_string());
    report.functions = functions;
    report.signatures = database.len();
    report.callee_keys = database.callee_keys();
    report.pat_records = database.pat_records();
    Ok(LibrarySignatures { database, report })
}
