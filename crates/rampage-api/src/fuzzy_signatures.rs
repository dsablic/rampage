//! Read-only, explicitly secondary library-name evidence. No method here renames, appends annotations,
//! refreshes sidecars or treats a similarity score as permission to apply a name.

use std::collections::{BTreeMap, BTreeSet};

use rampage_analysis::discover::{DiscoveredFunction, Program};
use rampage_arch::Flow;
use rampage_loaders::{Binary, SymbolKind};
use rampage_signatures::fuzzy::{
    CalleeProvenance, CodeProjection, FuzzyDb, FuzzyMatchReport, FuzzyReference, KnownCallee, ReferenceProvenance,
    validated_production_flow,
};
use rampage_signatures::{MaskContext, SignatureDb, identify_program_sources};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::packs::BUILTIN_PACK;
use crate::{ApiError, Project, USER_SIGNATURES};

pub const MAX_FUZZY_BUILD_FUNCTIONS: usize = 4096;
pub const MAX_FUZZY_QUERY_FUNCTIONS: usize = 64;

#[derive(Debug, Serialize)]
pub struct FuzzyTarget {
    pub architecture: String,
    pub instruction_big_endian: bool,
    pub data_big_endian: bool,
    pub loader_thumb_ranges: usize,
    pub retained_code_modes: usize,
}

fn target_evidence(binary: &Binary, program: &Program) -> FuzzyTarget {
    let target = binary.target();
    FuzzyTarget {
        architecture: target.arch.to_string(),
        instruction_big_endian: target.big_endian,
        data_big_endian: target.data_big_endian,
        loader_thumb_ranges: target.thumb.len(),
        retained_code_modes: program.code_modes.len(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzyBuildRequest {
    pub provenance: ReferenceProvenance,
    /// Source/reference labels explicitly selected before target evaluation, never target debug gold.
    pub owned_names: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
pub struct FuzzyFeatureRejection {
    pub address: Option<u64>,
    pub source_name: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct FuzzyBuildReport {
    pub target: FuzzyTarget,
    pub image_sha256: String,
    pub executable_sha256: String,
    pub references: usize,
    /// None means no selected body passed the evidence gate; rejections are still returned.
    pub database: Option<FuzzyDb>,
    pub rejected: Vec<FuzzyFeatureRejection>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzySuggestRequest {
    /// An artifact/cohort ID distinct from the reference and calibration IDs stored in the database.
    pub cohort: String,
    /// Explicit discovered entries only. Interior addresses do not silently select a different function.
    pub addresses: Vec<u64>,
    pub candidates_per_function: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuzzyExactEvidence {
    pub name: String,
    pub source: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzySuggestionStatus {
    ExactPriority,
    ExistingNamePreserved,
    CandidateEvidence,
    FeatureRejected,
    NotDiscovered,
}

#[derive(Debug, Serialize)]
pub struct FuzzySuggestion {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub status: FuzzySuggestionStatus,
    pub existing_name: Option<String>,
    pub exact: Option<FuzzyExactEvidence>,
    pub report: Option<FuzzyMatchReport>,
    pub rejection: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FuzzySuggestions {
    pub target: FuzzyTarget,
    pub image_sha256: String,
    pub executable_sha256: String,
    pub read_only: bool,
    pub suggestions: Vec<FuzzySuggestion>,
    pub warnings: Vec<String>,
    pub limitations: &'static [&'static str],
}

impl Project {
    /// Build source-labeled fuzzy descriptors using production discovery and already-known call evidence.
    /// The returned database is in memory only. This does not save a database or create an annotation sidecar.
    pub fn build_fuzzy_signatures(&self, request: &FuzzyBuildRequest) -> Result<FuzzyBuildReport, ApiError> {
        if request.owned_names.is_empty() || request.owned_names.len() > MAX_FUZZY_BUILD_FUNCTIONS {
            return Err(ApiError::Invalid("fuzzy build needs 1..=4096 explicitly source-selected names".into()));
        }
        let program = &self.analysis()?.program;
        let image_sha256 = image_hash(&self.binary);
        let executable_sha256 = fuzzy_code_identity(&self.binary, program)?;
        let exact_db = self.build_signatures();
        let (exact, warnings) = exact_evidence(self, program, Some(&exact_db))?;
        let (_, callees) = name_snapshot(self, &exact)?;
        let mut selected: BTreeMap<&str, BTreeSet<u64>> = BTreeMap::new();
        for symbol in &self.binary.symbols {
            if symbol.kind == SymbolKind::Function && request.owned_names.contains(&symbol.name) {
                selected.entry(&symbol.name).or_default().insert(symbol.address);
            }
        }
        for export in &self.binary.exports {
            if request.owned_names.contains(&export.name) {
                selected.entry(&export.name).or_default().insert(export.address);
            }
        }
        let mut rejected = Vec::new();
        let mut references = Vec::new();
        let mut provenance = request.provenance.clone();
        provenance.image_sha256 = Some(image_sha256.clone());
        provenance.executable_sha256 = Some(executable_sha256.clone());
        for name in &request.owned_names {
            let Some(addresses) = selected.get(name.as_str()) else {
                rejected.push(FuzzyFeatureRejection {
                    address: None,
                    source_name: name.clone(),
                    reason: "source label absent".into(),
                });
                continue;
            };
            for &address in addresses {
                if references.len() + rejected.len() >= MAX_FUZZY_BUILD_FUNCTIONS {
                    return Err(ApiError::Invalid("fuzzy build exceeds 4096 selected bodies".into()));
                }
                let features = program
                    .function_at(address)
                    .ok_or_else(|| ApiError::Invalid("source entry not discovered".into()))
                    .and_then(|function| fuzzy_code_projection(&self.binary, program, function))
                    .and_then(|projection| {
                        rampage_signatures::fuzzy::extract_features(&self.binary, &projection, &callees)
                            .map_err(|error| ApiError::Invalid(error.to_string()))
                    });
                match features {
                    Ok(features) => {
                        references.push(FuzzyReference { name: name.clone(), provenance: provenance.clone(), features })
                    }
                    Err(error) => rejected.push(FuzzyFeatureRejection {
                        address: Some(address),
                        source_name: name.clone(),
                        reason: error.to_string(),
                    }),
                }
            }
        }
        let count = references.len();
        let database = if references.is_empty() {
            None
        } else {
            Some(FuzzyDb::new(references).map_err(|error| ApiError::Invalid(error.to_string()))?)
        };
        Ok(FuzzyBuildReport {
            target: target_evidence(&self.binary, program),
            image_sha256,
            executable_sha256,
            references: count,
            database,
            rejected,
            warnings,
        })
    }

    /// Suggest secondary candidates for explicit entries. Exact user, pack and built-in priority is unchanged.
    /// Already-named functions are preserved, and even a calibrated/qualified candidate is never auto-applied.
    pub fn suggest_fuzzy_signatures(
        &self,
        database: &FuzzyDb,
        user_exact: Option<&SignatureDb>,
        request: &FuzzySuggestRequest,
    ) -> Result<FuzzySuggestions, ApiError> {
        if request.addresses.is_empty()
            || request.addresses.len() > MAX_FUZZY_QUERY_FUNCTIONS
            || request.addresses.iter().collect::<BTreeSet<_>>().len() != request.addresses.len()
            || !(1..=16).contains(&request.candidates_per_function)
        {
            return Err(ApiError::Invalid("fuzzy query needs 1..=64 distinct entries and 1..=16 candidates".into()));
        }
        database.validate_query_cohort(&request.cohort).map_err(|error| ApiError::Invalid(error.to_string()))?;
        let program = &self.analysis()?.program;
        let executable_sha256 = fuzzy_code_identity(&self.binary, program)?;
        let (exact, warnings) = exact_evidence(self, program, user_exact)?;
        let (names, callees) = name_snapshot(self, &exact)?;
        let mut suggestions = Vec::with_capacity(request.addresses.len());
        for &address in &request.addresses {
            let mut suggestion = FuzzySuggestion {
                address,
                status: FuzzySuggestionStatus::NotDiscovered,
                existing_name: names.get(&address).cloned(),
                exact: exact.get(&address).cloned(),
                report: None,
                rejection: None,
            };
            if let Some(function) = program.function_at(address) {
                if suggestion.exact.is_some() {
                    suggestion.status = FuzzySuggestionStatus::ExactPriority;
                } else if suggestion.existing_name.is_some() {
                    suggestion.status = FuzzySuggestionStatus::ExistingNamePreserved;
                } else {
                    database
                        .validate_executable_cohort(&executable_sha256)
                        .map_err(|error| ApiError::Invalid(error.to_string()))?;
                    let features = fuzzy_code_projection(&self.binary, program, function).and_then(|projection| {
                        rampage_signatures::fuzzy::extract_features(&self.binary, &projection, &callees)
                            .map_err(|error| ApiError::Invalid(error.to_string()))
                    });
                    match features {
                        Ok(features) => {
                            suggestion.report = Some(
                                database
                                    .candidates(&features, &request.cohort, request.candidates_per_function)
                                    .map_err(|error| ApiError::Invalid(error.to_string()))?,
                            );
                            suggestion.status = FuzzySuggestionStatus::CandidateEvidence;
                        }
                        Err(error) => {
                            suggestion.status = FuzzySuggestionStatus::FeatureRejected;
                            suggestion.rejection = Some(error.to_string());
                        }
                    }
                }
            }
            suggestions.push(suggestion);
        }
        Ok(FuzzySuggestions {
            target: target_evidence(&self.binary, program),
            image_sha256: image_hash(&self.binary),
            executable_sha256,
            read_only: true,
            suggestions,
            warnings,
            limitations: &[
                "Scores are bounded similarity, not identity probabilities; no name changes or sidecar writes.",
                "Known call names use exact proposals, imports or analyst annotations, never target debug gold.",
                "Calibration is profile/cohort-specific evidence, not a population false-positive guarantee.",
                "CFG projection currently refuses delay-slot architectures and mixed effective instruction modes.",
            ],
        })
    }
}

fn image_hash(binary: &Binary) -> String {
    Sha256::digest(binary.image_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn exact_evidence(
    project: &Project,
    program: &Program,
    user: Option<&SignatureDb>,
) -> Result<(BTreeMap<u64, FuzzyExactEvidence>, Vec<String>), ApiError> {
    let packs = project.packs();
    let packed = packs.signatures_for(project.binary.arch);
    let builtin = rampage_signatures::bundled_ref(project.binary.arch).map(|db| (BUILTIN_PACK, db));
    let databases: Vec<_> = user.map(|db| (USER_SIGNATURES, db)).into_iter().chain(packed).chain(builtin).collect();
    for (_, database) in &databases {
        database.ensure_byte_matching_supported().map_err(|error| ApiError::Invalid(error.to_string()))?;
    }
    let bodies: Vec<_> = program
        .functions
        .iter()
        .filter_map(|function| Some((function.address, function.body(&project.binary)?)))
        .collect();
    let only: Vec<_> = databases.iter().map(|(_, db)| *db).collect();
    let names =
        identify_program_sources(&only, &project.binary.target(), &MaskContext::from_binary(&project.binary), &bodies)
            .into_iter()
            .map(|(address, (index, name))| {
                (address, FuzzyExactEvidence { name: name.into_owned(), source: databases[index].0.to_owned() })
            })
            .collect();
    Ok((names, packs.problems_for("signatures")))
}

type NameSnapshot = (BTreeMap<u64, String>, BTreeMap<u64, KnownCallee>);

/// Snapshot annotations briefly, then release the lock before any matching/decoding. Loader/debug names
/// preserve existing function labels but are deliberately not accepted as callee feature evidence.
fn name_snapshot(project: &Project, exact: &BTreeMap<u64, FuzzyExactEvidence>) -> Result<NameSnapshot, ApiError> {
    let analyst = match project.read_annotations_lock().try_read() {
        Ok(annotations) => annotations.names().clone(),
        Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner().names().clone(),
        Err(std::sync::TryLockError::WouldBlock) => return Err(ApiError::Unavailable("annotations are busy".into())),
    };
    let mut names: BTreeMap<_, _> =
        project.inventory_loader_names().map(|(address, name)| (address, name.to_owned())).collect();
    names.extend(analyst.clone());
    names.retain(|address, name| !rampage_analysis::functions::is_default_name(name, *address));
    let mut callees: BTreeMap<_, _> = exact
        .iter()
        .map(|(address, evidence)| {
            (
                *address,
                KnownCallee { name: evidence.name.clone(), provenance: CalleeProvenance::ExactSignatureProposal },
            )
        })
        .collect();
    for (address, name) in rampage_analysis::functions::stub_names(&project.binary) {
        callees.entry(address).or_insert(KnownCallee { name, provenance: CalleeProvenance::Import });
    }
    for slot in &project.binary.import_slots {
        callees
            .entry(slot.address)
            .or_insert(KnownCallee { name: slot.name.clone(), provenance: CalleeProvenance::Import });
    }
    for (address, name) in analyst {
        if !rampage_analysis::functions::is_default_name(&name, address) {
            callees.insert(address, KnownCallee { name, provenance: CalleeProvenance::Analyst });
        }
    }
    Ok((names, callees))
}

/// Project actual production-discovered blocks and final-instruction successors without consulting names.
/// Targets use `function.address..function.end()`, never producer/debug sizes or a linear sweep of gaps.
pub fn fuzzy_code_projection(
    binary: &Binary,
    program: &Program,
    function: &DiscoveredFunction,
) -> Result<CodeProjection, ApiError> {
    if binary.arch.delay_slots() != 0 {
        return Err(ApiError::Invalid("delay-slot fuzzy CFG projection is unsupported".into()));
    }
    let blocks: Vec<_> = function.blocks.iter().map(|block| block.start..block.end).collect();
    if blocks.len() > 512
        || function.instruction_count > 4096
        || function.end().checked_sub(function.address).is_none_or(|size| size > 1024 * 1024)
    {
        return Err(ApiError::Invalid("production CFG exceeds feature extraction bounds".into()));
    }
    let starts: BTreeMap<_, _> = blocks.iter().enumerate().map(|(index, block)| (block.start, index)).collect();
    let retained_code_modes: Vec<_> = program
        .code_modes
        .iter()
        .copied()
        .filter(|(address, _)| blocks.iter().any(|block| block.contains(address)))
        .collect();
    let resolved_flows: Vec<_> = program
        .resolved_flows
        .iter()
        .filter(|resolved| resolved.function == function.address)
        .map(|resolved| (resolved.address, resolved.flow))
        .collect();
    let resolutions: BTreeMap<_, _> = resolved_flows.iter().copied().collect();
    let mut decoder = binary.decoder()?;
    decoder.set_code_modes(&retained_code_modes);
    let mut edges = BTreeSet::new();
    let mut instructions = 0;
    for (index, block) in blocks.iter().enumerate() {
        let size = block.end.checked_sub(block.start).ok_or_else(|| ApiError::Invalid("invalid block range".into()))?;
        let bytes =
            binary.read(block.start, size).ok_or_else(|| ApiError::Invalid("block is not fully file-backed".into()))?;
        decoder.begin_run();
        let mut offset = 0usize;
        let mut last = None;
        while offset < bytes.len() {
            if instructions == 4096 {
                return Err(ApiError::Invalid("production CFG instruction bound".into()));
            }
            let instruction = decoder.decode(&bytes[offset..], block.start + offset as u64);
            let size = usize::from(instruction.len);
            if size == 0 || size > bytes.len() - offset || instruction.flow == Flow::Invalid {
                return Err(ApiError::Invalid("invalid instruction in production block".into()));
            }
            instructions += 1;
            offset += size;
            let flow = validated_production_flow(instruction.flow, resolutions.get(&instruction.address).copied())
                .map_err(|error| ApiError::Invalid(error.to_string()))?;
            last = Some((instruction, flow));
        }
        let (last, flow) = last.ok_or_else(|| ApiError::Invalid("empty production block".into()))?;
        let mut successors = Vec::new();
        match flow {
            Flow::Jump(target) => successors.push(target),
            Flow::ConditionalJump(target) => {
                successors.push(target);
                successors.push(block.end);
            }
            Flow::Next | Flow::Call(_) | Flow::IndirectCall if !program.is_noreturn_call(last.address) => {
                successors.push(block.end);
            }
            Flow::IndirectJump => successors.extend_from_slice(function.switch_cases(last.address).unwrap_or_default()),
            _ => {}
        }
        if last.conditional {
            successors.push(block.end);
        }
        for successor in successors {
            if let Some(to) = starts.get(&successor) {
                edges.insert((index, *to));
            }
        }
    }
    Ok(CodeProjection {
        extent: function.address..function.end(),
        blocks,
        edges: edges.into_iter().collect(),
        retained_code_modes,
        resolved_flows,
    })
}

/// Executable section contents, ISA, byte order and normalized retained mode evidence, excluding addresses,
/// section names, build IDs, debug information and other non-code file metadata. This is cohort evidence,
/// not authentication. Identical code at different load addresses has the same identity when bytes agree.
pub fn fuzzy_code_identity(binary: &Binary, program: &Program) -> Result<String, ApiError> {
    let target = binary.target();
    let mut hash = Sha256::new();
    hash.update(b"rampage fuzzy executable cohort v1\0");
    hash.update(target.arch.to_string().as_bytes());
    hash.update([u8::from(target.big_endian), u8::from(target.data_big_endian)]);
    let mut sections: Vec<_> = binary
        .sections
        .iter()
        .filter(|section| section.kind == rampage_loaders::SectionKind::Code && section.size != 0)
        .collect();
    sections.sort_by_key(|section| section.address);
    if sections.is_empty() {
        return Err(ApiError::Invalid("executable cohort identity requires file-backed code sections".into()));
    }
    for section in sections {
        let bytes = binary
            .section_file_bytes(section)
            .filter(|bytes| bytes.len() as u64 == section.size)
            .ok_or_else(|| ApiError::Invalid("executable cohort section is not fully file-backed".into()))?;
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
        let end = section
            .address
            .checked_add(section.size)
            .ok_or_else(|| ApiError::Invalid("code section address overflow".into()))?;
        let mut modes = BTreeMap::new();
        if target.arch == rampage_arch::Arch::Arm {
            modes.insert(0, target.is_thumb(section.address));
            for range in target.thumb.iter() {
                for (at, thumb) in [(range.start, true), (range.end, false)] {
                    if at >= section.address && at < end {
                        modes.insert(at - section.address, thumb);
                    }
                }
            }
            for &(at, thumb) in &program.code_modes {
                if at >= section.address && at < end {
                    modes.insert(at - section.address, thumb);
                }
            }
        }
        let mut previous = None;
        modes.retain(|_, thumb| {
            let changed = previous != Some(*thumb);
            previous = Some(*thumb);
            changed
        });
        hash.update((modes.len() as u64).to_le_bytes());
        for (offset, thumb) in modes {
            hash.update(offset.to_le_bytes());
            hash.update([u8::from(thumb)]);
        }
    }
    Ok(hash.finalize().iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
#[path = "effective_annotation_batch_tests.rs"]
mod effective_annotation_batch_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn binary(nop: bool, address: u64, provenance: &str) -> Binary {
        let mut bytes = vec![
            0xb8, 23, 0, 0, 0, 0x83, 0xc0, 37, 0x83, 0xf0, 90, 0x83, 0xc0, 7, 0x83, 0xe0, 17, 0x83, 0xc0, 13, 0x85,
            0xc0, 0x75, 0,
        ];
        if nop {
            bytes.push(0x90);
        }
        bytes.extend([0x83, 0xc0, 37, 0x83, 0xf0, 90, 0x83, 0xc0, 7, 0x83, 0xe0, 17, 0x85, 0xc0, 0xc3]);
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        Binary::from_snapshot_bytes(
            serde_json::to_vec(&serde_json::json!({
                "format": "rampage-snapshot-v1", "arch": "x86_64", "provenance": provenance,
                "regions": [{"name": "owned-code", "address": format!("{address:#x}"),
                    "permissions": "r-x", "bytes": hex}],
                "seeds": [format!("{address:#x}")]
            }))
            .unwrap(),
        )
        .unwrap()
    }

    fn source() -> Project {
        let mut binary = binary(false, 0x4000, "source only labels");
        binary.symbols.push(rampage_loaders::Symbol {
            name: "owned_library_function".into(),
            address: 0x4000,
            size: 39,
            kind: SymbolKind::Function,
        });
        Project::new(binary)
    }

    fn request() -> FuzzyBuildRequest {
        FuzzyBuildRequest {
            provenance: ReferenceProvenance {
                library: "owned fixture".into(),
                source: "source-only fixture, never executed".into(),
                cohort: "reference".into(),
                image_sha256: None,
                executable_sha256: None,
            },
            owned_names: BTreeSet::from(["owned_library_function".into()]),
        }
    }

    fn query() -> FuzzySuggestRequest {
        FuzzySuggestRequest { cohort: "heldout".into(), addresses: vec![0x4000], candidates_per_function: 1 }
    }

    #[test]
    fn fuzzy_api_build_and_suggest_are_read_only_and_preserve_analyst_names() {
        let source = source();
        let before = source.annotation_revision().unwrap();
        let built = source.build_fuzzy_signatures(&request()).unwrap();
        assert_eq!(built.references, 1, "{:?}", built.rejected);
        assert!(Arc::ptr_eq(&before, &source.annotation_revision().unwrap()));
        let db = built.database.unwrap();
        let target = Project::new(binary(true, 0x4000, "no target names"));
        let before = target.annotation_revision().unwrap();
        let result = target.suggest_fuzzy_signatures(&db, None, &query()).unwrap();
        assert!(matches!(result.suggestions[0].status, FuzzySuggestionStatus::CandidateEvidence));
        assert!(result.suggestions[0].report.as_ref().unwrap().threshold.is_none());
        assert!(Arc::ptr_eq(&before, &target.annotation_revision().unwrap()));
        assert!(target.annotations().persistent_path().is_none());
        target.rename(0x4000, Some("analyst_owned")).unwrap();
        let before = target.annotation_revision().unwrap();
        let result = target.suggest_fuzzy_signatures(&db, None, &query()).unwrap();
        assert!(matches!(result.suggestions[0].status, FuzzySuggestionStatus::ExistingNamePreserved));
        assert_eq!(target.function_name(0x4000), "analyst_owned");
        assert!(Arc::ptr_eq(&before, &target.annotation_revision().unwrap()));
    }

    #[test]
    fn fuzzy_api_exact_priority_and_query_refusals_do_not_mutate_annotations() {
        let source = source();
        let db = source.build_fuzzy_signatures(&request()).unwrap().database.unwrap();
        let exact = source.build_signatures();
        let target = Project::new(binary(false, 0x4000, "unnamed target"));
        let result = target.suggest_fuzzy_signatures(&db, Some(&exact), &query()).unwrap();
        assert!(matches!(result.suggestions[0].status, FuzzySuggestionStatus::ExactPriority));
        assert_eq!(result.suggestions[0].exact.as_ref().unwrap().source, USER_SIGNATURES);
        assert!(result.suggestions[0].report.is_none());
        let mut invalid = query();
        invalid.cohort = "reference".into();
        assert!(target.suggest_fuzzy_signatures(&db, None, &invalid).is_err());
        invalid = query();
        invalid.addresses.push(0x4000);
        assert!(target.suggest_fuzzy_signatures(&db, None, &invalid).is_err());
        let guard = target.annotations.write().unwrap();
        assert!(matches!(target.suggest_fuzzy_signatures(&db, None, &query()), Err(ApiError::Unavailable(_))));
        drop(guard);
    }

    #[test]
    fn fuzzy_refuses_user_and_pack_fid_before_returning_candidates_or_writing_annotations() {
        use rampage_signatures::fid::FidDb;
        let fid = FidDb::from_export(include_bytes!("../../../tests/fixtures/signatures/fid/native.export")).unwrap();
        let fid = SignatureDb::from_fid_db(rampage_arch::Arch::X86_64, fid).unwrap();
        let source = source();
        let fuzzy = source.build_fuzzy_signatures(&request()).unwrap().database.unwrap();
        let target = Project::new(binary(true, 0x4000, "no target gold"));
        let before = target.annotation_revision().unwrap();
        let error = target.suggest_fuzzy_signatures(&fuzzy, Some(&fid), &query()).unwrap_err();
        assert!(error.to_string().contains("FID"));
        assert!(Arc::ptr_eq(&before, &target.annotation_revision().unwrap()));

        struct TempPack(std::path::PathBuf);
        impl Drop for TempPack {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = std::env::temp_dir().join(format!("rampage-fuzzy-fid-pack-{}", std::process::id()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&directory).unwrap();
        let temp = TempPack(directory);
        std::fs::write(temp.0.join("fid.json"), fid.to_json()).unwrap();
        std::fs::write(
            temp.0.join("rampage-pack.toml"),
            r#"
name = "owned-fid-admission-test"
version = "1"
license = "Apache-2.0"
source = "owned generated fixture; no target execution"
description = "FID must not disappear from fuzzy exact priority"
[[contents]]
kind = "signatures"
path = "fid.json"
arch = "x86_64"
"#,
        )
        .unwrap();
        let packs = Arc::new(crate::Packs::load(std::slice::from_ref(&temp.0)));
        assert_eq!(packs.signatures_for(rampage_arch::Arch::X86_64).count(), 1);
        target.set_packs(Arc::clone(&packs));
        source.set_packs(packs);
        let before_source = source.annotation_revision().unwrap();
        assert!(target.suggest_fuzzy_signatures(&fuzzy, None, &query()).unwrap_err().to_string().contains("FID"));
        assert!(source.build_fuzzy_signatures(&request()).unwrap_err().to_string().contains("FID"));
        assert!(target.apply_signatures_default(None, true).is_err());
        assert!(Arc::ptr_eq(&before, &target.annotation_revision().unwrap()));
        assert!(Arc::ptr_eq(&before_source, &source.annotation_revision().unwrap()));
        assert!(target.annotations().persistent_path().is_none());
        assert!(source.annotations().persistent_path().is_none());
        drop(temp);
    }

    #[test]
    fn code_cohort_identity_ignores_metadata_and_relocation_but_changes_with_instruction_bytes() {
        let left = binary(false, 0x4000, "debug metadata one");
        let right = binary(false, 0x9000, "different debug metadata and load address");
        assert_ne!(Sha256::digest(left.file_bytes()), Sha256::digest(right.file_bytes()));
        let a = rampage_analysis::functions::analyze(&left).unwrap();
        let b = rampage_analysis::functions::analyze(&right).unwrap();
        assert_eq!(fuzzy_code_identity(&left, &a).unwrap(), fuzzy_code_identity(&right, &b).unwrap());
        let changed = binary(true, 0x4000, "instruction difference");
        let c = rampage_analysis::functions::analyze(&changed).unwrap();
        assert_ne!(fuzzy_code_identity(&left, &a).unwrap(), fuzzy_code_identity(&changed, &c).unwrap());
    }

    #[test]
    #[ignore = "requires explicit RAMPAGE_FUZZY_CORPUS_ROOT containing the generated owned ELF fixtures"]
    fn fuzzy_native_owned_elf_build_and_suggest_never_apply_names_or_write_sidecars() {
        let root = std::path::PathBuf::from(
            std::env::var_os("RAMPAGE_FUZZY_CORPUS_ROOT").expect("explicit generated corpus root"),
        );
        let source = Project::new(Binary::open(root.join("corpus/reference.elf")).unwrap());
        let before_source = source.annotation_revision().unwrap();
        let mut build = request();
        build.owned_names =
            ["corpus_crc32", "corpus_adler32", "corpus_runlength"].into_iter().map(str::to_owned).collect();
        let built = source.build_fuzzy_signatures(&build).unwrap();
        assert!(built.references > 0, "{:?}", built.rejected);
        assert_eq!(built.target.architecture, "x86_64");
        assert!(Arc::ptr_eq(&before_source, &source.annotation_revision().unwrap()));
        let db = match std::env::var_os("RAMPAGE_FUZZY_DATABASE") {
            Some(path) => FuzzyDb::load_json(&std::fs::read(path).unwrap()).unwrap(),
            None => built.database.unwrap(),
        };
        let target = Project::new(Binary::open(root.join("corpus/heldout.stripped.elf")).unwrap());
        let before = target.annotation_revision().unwrap();
        let addresses = target.analysis().unwrap().program.functions.iter().map(|function| function.address).collect();
        let result = target
            .suggest_fuzzy_signatures(
                &db,
                Some(&source.build_signatures()),
                &FuzzySuggestRequest { cohort: "native-heldout-query".into(), addresses, candidates_per_function: 16 },
            )
            .unwrap();
        assert!(result.read_only);
        assert!(result.suggestions.iter().any(|row| matches!(row.status, FuzzySuggestionStatus::CandidateEvidence)));
        assert!(Arc::ptr_eq(&before, &target.annotation_revision().unwrap()));
        assert!(target.annotations().persistent_path().is_none());
        assert!(source.annotations().persistent_path().is_none());
        for row in result.suggestions {
            for candidate in row.report.into_iter().flat_map(|report| report.candidates) {
                assert!(candidate.score.total.is_finite() && (0.0..=1.0).contains(&candidate.score.total));
            }
        }
    }
}
