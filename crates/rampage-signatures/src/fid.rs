//! Genuine Ghidra raw `.fidbf` ingestion through an explicitly configured, trusted host JVM.
//!
//! A `.fidbf` is a Ghidra paged database, not the private `RPFID001` bridge transport parsed here.
//! Packed `.fidb`, other schemas, and extra tables are explicitly unsupported. The raw-database Java bridge
//! uses Ghidra's read-only DBHandle and consistency checker for page/range/index validation. It never
//! loads programs, invokes analyzers, follows recorded source paths, or executes target code.
//!
//! Source: Ghidra 12.1.4, Apache-2.0, IP: GHIDRA:
//! <https://github.com/NationalSecurityAgency/ghidra/tree/Ghidra_12.1.4_build/Ghidra/Features/FunctionID>.
//! Table definitions, operand mixing and relation formulas derive from `db/{FunctionsTable,
//! LibrariesTable,RelationsTable,FidDBUtils}.java` and `hash/MessageDigestFidHasher.java`.
//! FNV's integer updates are big endian (`Framework/Generic/.../AbstractMessageDigest.java`).
//! These definitions are adapted under Apache-2.0; no upstream database data is redistributed.
//!
//! FID hashes are NOT Rampage scheme-1/2 hashes and are never cast to `FunctionHash`. Matching requires
//! Ghidra-compatible instruction masks, register-space offsets, operand objects/types, relocations,
//! extent order, and instruction-skipper decisions. `FidService` enumerates instructions in the
//! stored function body in ascending address order, not all bytes in a contiguous function range.
//! Raw p-code alone does not supply these facts.
//! No architecture decoder is implemented here: the semantic adapter must provide those features or
//! report unsupported. `hash_features` implements the actual digest once those facts are available.
//! `FidHostAdapter` is the separate explicit trusted-Ghidra static-analysis path, currently restricted
//! to Ghidra 12.1.4 and default x86/x86-64 ELF profiles. It is not an untrusted-host sandbox.

use rampage_arch::Arch;
use rampage_loaders::Binary;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_FILE: u64 = 128 << 20;
const MAX_WIRE: u64 = 128 << 20;
const MAX_STRING: usize = 4096;
const PRIME: u64 = 1_099_511_628_211;
const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const EXPORTER: &str = include_str!("../../../tools/fid-fixture/FidExport.java");
const PROGRAM_EXPORTER: &str = include_str!("../../../tools/fid-fixture/FidProgramExport.java");
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// The bridge transport version is 1; the actual Ghidra FID table schema is **6**.
pub const FID_SCHEMA_VERSION: u32 = 6;

#[derive(Debug, thiserror::Error)]
pub enum FidError {
    #[error("FID I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid or unsupported FID data: {0}")]
    Invalid(&'static str),
    #[error("FID reader exceeded its time or resource budget")]
    Budget,
    #[error("trusted Ghidra reader failed; no records were imported")]
    ReaderFailed,
    #[error("unsupported FID semantic adapter/profile: {0}")]
    Unsupported(&'static str),
}

/// Unauthenticated metadata recorded by a database producer, not publisher/source authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FidLibrary {
    pub id: u64,
    pub family: String,
    pub version: String,
    pub variant: String,
    pub ghidra_version: String,
    pub language_id: String,
    pub language_version: u32,
    pub language_minor_version: u32,
    pub compiler_spec_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FidHashQuad {
    /// Number of non-skipped code units minus call instructions, not byte length.
    pub code_unit_size: u16,
    pub full_hash: u64,
    /// Number of included scalar values, saturated at 127.
    pub specific_hash_additional_size: u8,
    pub specific_hash: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FidFunction {
    pub id: u64,
    pub hash: FidHashQuad,
    pub library_id: u64,
    pub name: String,
    pub entry_point: u64,
    /// Metadata only. Never opened or interpreted as a command.
    pub domain_path: String,
    /// Ghidra: terminator=1, auto-pass=2, auto-fail=4, force-specific=8, force-relation=16.
    pub flags: u8,
}

/// A validated independent FID index. No conversion to Rampage's SHA-256 signature scheme exists.
#[derive(Clone, Debug)]
pub struct FidDb {
    libraries: BTreeMap<u64, FidLibrary>,
    functions: BTreeMap<u64, FidFunction>,
    full_hash_index: BTreeMap<u64, Vec<u64>>,
    inferior_relations: BTreeSet<u64>,
    superior_relations: BTreeSet<u64>,
}

impl FidDb {
    /// Canonical replay transport preserving all imported matching constraints, not a `.fidbf` writer.
    pub fn to_export(&self) -> Result<Vec<u8>, FidError> {
        let mut out = b"RPFID001".to_vec();
        out.extend(FID_SCHEMA_VERSION.to_be_bytes());
        out.extend((self.libraries.len() as u32).to_be_bytes());
        for library in self.libraries.values() {
            out.extend(library.id.to_be_bytes());
            for value in
                [&library.family, &library.version, &library.variant, &library.ghidra_version, &library.language_id]
            {
                wire_text(&mut out, value)?;
            }
            out.extend(library.language_version.to_be_bytes());
            out.extend(library.language_minor_version.to_be_bytes());
            wire_text(&mut out, &library.compiler_spec_id)?;
        }
        out.extend((self.functions.len() as u32).to_be_bytes());
        for function in self.functions.values() {
            out.extend(function.id.to_be_bytes());
            out.extend(function.hash.code_unit_size.to_be_bytes());
            out.extend(function.hash.full_hash.to_be_bytes());
            out.push(function.hash.specific_hash_additional_size);
            out.extend(function.hash.specific_hash.to_be_bytes());
            out.extend(function.library_id.to_be_bytes());
            wire_text(&mut out, &function.name)?;
            out.extend(function.entry_point.to_be_bytes());
            wire_text(&mut out, &function.domain_path)?;
            out.push(function.flags);
            if out.len() as u64 > MAX_WIRE {
                return Err(FidError::Budget);
            }
        }
        for relations in [&self.inferior_relations, &self.superior_relations] {
            out.extend((relations.len() as u32).to_be_bytes());
            for relation in relations {
                out.extend(relation.to_be_bytes());
            }
        }
        if out.len() as u64 > MAX_WIRE {
            return Err(FidError::Budget);
        }
        Ok(out)
    }
    pub fn libraries(&self) -> impl Iterator<Item = &FidLibrary> {
        self.libraries.values()
    }

    pub fn functions(&self) -> impl Iterator<Item = &FidFunction> {
        self.functions.values()
    }

    pub fn library(&self, id: u64) -> Option<&FidLibrary> {
        self.libraries.get(&id)
    }

    /// Diagnostic lookup only: a full-hash hit alone MUST NOT assign a name.
    pub fn candidates(&self, full_hash: u64) -> impl Iterator<Item = &FidFunction> {
        self.full_hash_index.get(&full_hash).into_iter().flatten().filter_map(move |id| self.functions.get(id))
    }

    pub fn has_callee_relation(&self, caller_id: u64, callee_full_hash: u64) -> bool {
        self.superior_relations.contains(&(caller_id.wrapping_mul(PRIME) ^ callee_full_hash))
    }

    pub fn has_caller_relation(&self, callee_id: u64, caller_full_hash: u64) -> bool {
        self.inferior_relations.contains(&(callee_id.wrapping_mul(PRIME) ^ caller_full_hash))
    }

    /// Parse only the owned bridge's bounded, big-endian transport, never `.fidbf` bytes.
    /// Prefer `FidReader::import_file` for actual databases. All failures are transactional.
    pub fn from_export(bytes: &[u8]) -> Result<Self, FidError> {
        if bytes.len() as u64 > MAX_WIRE {
            return Err(FidError::Budget);
        }
        let mut input = Wire { bytes, position: 0 };
        if input.take(8)? != b"RPFID001" || input.u32()? != FID_SCHEMA_VERSION {
            return Err(FidError::Invalid("bridge magic or FID schema version"));
        }
        let mut db = Self {
            libraries: BTreeMap::new(),
            functions: BTreeMap::new(),
            full_hash_index: BTreeMap::new(),
            inferior_relations: BTreeSet::new(),
            superior_relations: BTreeSet::new(),
        };
        let count = input.count(10_000, 40)?;
        for _ in 0..count {
            let library = FidLibrary {
                id: input.u64()?,
                family: input.text()?,
                version: input.text()?,
                variant: input.text()?,
                ghidra_version: input.text()?,
                language_id: input.text()?,
                language_version: input.u32()?,
                language_minor_version: input.u32()?,
                compiler_spec_id: input.text()?,
            };
            if library.language_version > i32::MAX as u32
                || library.language_minor_version > i32::MAX as u32
                || library.language_id.is_empty()
                || library.compiler_spec_id.is_empty()
                || db.libraries.insert(library.id, library).is_some()
            {
                return Err(FidError::Invalid("library version, identity, or duplicate key"));
            }
        }
        let count = input.count(500_000, 52)?;
        for _ in 0..count {
            let function = FidFunction {
                id: input.u64()?,
                hash: FidHashQuad {
                    code_unit_size: input.u16()?,
                    full_hash: input.u64()?,
                    specific_hash_additional_size: input.u8()?,
                    specific_hash: input.u64()?,
                },
                library_id: input.u64()?,
                name: input.text()?,
                entry_point: input.u64()?,
                domain_path: input.text()?,
                flags: input.u8()?,
            };
            if function.hash.code_unit_size > i16::MAX as u16
                || function.hash.specific_hash_additional_size > 127
                || function.flags & !31 != 0
                || !db.libraries.contains_key(&function.library_id)
            {
                return Err(FidError::Invalid("function counts, flags, or library reference"));
            }
            db.full_hash_index.entry(function.hash.full_hash).or_default().push(function.id);
            if db.functions.insert(function.id, function).is_some() {
                return Err(FidError::Invalid("duplicate function key"));
            }
        }
        for relations in [&mut db.inferior_relations, &mut db.superior_relations] {
            let count = input.count(2_000_000, 8)?;
            for _ in 0..count {
                if !relations.insert(input.u64()?) {
                    return Err(FidError::Invalid("duplicate relation key"));
                }
            }
        }
        if input.position != bytes.len() {
            return Err(FidError::Invalid("trailing bridge bytes"));
        }
        Ok(db)
    }

    /// Conservative naming: exact quad, language/compiler identity, terminator, original confidence
    /// gate and non-thunk evidence, mandatory relations, and a single library/name/version identity.
    /// Auto-pass never bypasses the caller's confidence gate; auto-fail is always honored.
    pub fn identify<'a>(&'a self, query: &FidQuery<'_>) -> Option<&'a FidFunction> {
        if !query.discriminating_body
            || query.is_thunk
            || query.hash.code_unit_size < 4
            || query.hash.full_hash == 0
            || query.hash.specific_hash == 0
            || query.callee_full_hashes.len() > 100_000
            || query.caller_full_hashes.len() > 100_000
        {
            return None;
        }
        let candidates = self.full_hash_index.get(&query.hash.full_hash).map_or(0, Vec::len);
        if candidates.saturating_mul(1 + query.callee_full_hashes.len() + query.caller_full_hashes.len()) > 1_000_000 {
            return None;
        }
        let mut result: Option<&FidFunction> = None;
        for function in self.candidates(query.hash.full_hash) {
            let library = self.libraries.get(&function.library_id)?;
            if !self.eligible(function, query) {
                continue;
            }
            if let Some(previous) = result {
                let previous_library = self.libraries.get(&previous.library_id)?;
                if previous.name != function.name || previous_library != library {
                    return None;
                }
            }
            result = Some(function);
        }
        result
    }

    fn eligible(&self, function: &FidFunction, query: &FidQuery<'_>) -> bool {
        let Some(library) = self.libraries.get(&function.library_id) else { return false };
        query.discriminating_body
            && !query.is_thunk
            && query.hash.code_unit_size >= 4
            && query.hash.full_hash != 0
            && query.hash.specific_hash != 0
            && query.callee_full_hashes.len() <= 100_000
            && query.caller_full_hashes.len() <= 100_000
            && function.hash == query.hash
            && function.flags & 4 == 0
            && !function.name.is_empty()
            && (function.flags & 1 != 0) == query.has_terminator
            && library.language_id == query.language_id
            && library.language_version == query.language_version
            && library.language_minor_version == query.language_minor_version
            && library.compiler_spec_id == query.compiler_spec_id
            && (function.flags & 16 == 0
                || query
                    .callee_full_hashes
                    .iter()
                    .any(|hash| *hash != 0 && self.has_callee_relation(function.id, *hash))
                || query
                    .caller_full_hashes
                    .iter()
                    .any(|hash| *hash != 0 && self.has_caller_relation(function.id, *hash)))
    }
}

fn wire_text(out: &mut Vec<u8>, text: &str) -> Result<(), FidError> {
    if text.len() > MAX_STRING {
        return Err(FidError::Budget);
    }
    out.extend((text.len() as u32).to_be_bytes());
    out.extend(text.as_bytes());
    Ok(())
}

/// Persisted FID namespace v1. It stores canonical bounded bridge chunks and reparses every record
/// on JSON/gzip reload. Database IDs remain local to their archive: relations cannot cross-contaminate.
#[derive(Clone, Debug, Serialize)]
pub struct FidNamespace {
    version: u32,
    archives: Vec<FidArchive>,
}

#[derive(Clone, Debug, Serialize)]
struct FidArchive {
    wire_chunks: Vec<String>,
    suppressed: BTreeSet<u64>,
    #[serde(skip)]
    db: FidDb,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceWire {
    version: u32,
    #[serde(deserialize_with = "bounded_archives")]
    archives: Vec<FidArchive>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveWire {
    #[serde(deserialize_with = "bounded_chunks")]
    wire_chunks: Vec<String>,
    #[serde(deserialize_with = "bounded_suppressions")]
    suppressed: Vec<u64>,
}

fn bounded_chunks<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    bounded_sequence::<D, String, 32768>(deserializer)
}

fn bounded_suppressions<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u64>, D::Error> {
    bounded_sequence::<D, u64, 500000>(deserializer)
}

fn bounded_sequence<'de, D, T, const LIMIT: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Sequence<T, const LIMIT: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const LIMIT: usize> serde::de::Visitor<'de> for Sequence<T, LIMIT> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded FID sequence")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut access: A) -> Result<Vec<T>, A::Error> {
            let mut values = Vec::new();
            loop {
                if values.len() == LIMIT {
                    if access.next_element::<serde::de::IgnoredAny>()?.is_some() {
                        return Err(serde::de::Error::custom("FID sequence budget"));
                    }
                    break;
                }
                let Some(value) = access.next_element()? else { break };
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Sequence::<T, LIMIT>(std::marker::PhantomData))
}

fn bounded_archives<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<FidArchive>, D::Error> {
    struct Archives;
    impl<'de> serde::de::Visitor<'de> for Archives {
        type Value = Vec<FidArchive>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bounded validated FID archives")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut access: A) -> Result<Vec<FidArchive>, A::Error> {
            let mut archives = Vec::new();
            let mut records = 0usize;
            let mut bytes = 0usize;
            loop {
                if archives.len() == 64 {
                    if access.next_element::<serde::de::IgnoredAny>()?.is_some() {
                        return Err(serde::de::Error::custom("FID archive count budget"));
                    }
                    break;
                }
                let Some(archive) = access.next_element::<FidArchive>()? else { break };
                records += archive.db.functions.len();
                bytes += archive.wire_chunks.iter().map(String::len).sum::<usize>();
                if records > 1_000_000 || bytes > 128 << 20 {
                    return Err(serde::de::Error::custom("FID aggregate archive budget"));
                }
                archives.push(archive);
            }
            Ok(archives)
        }
    }
    deserializer.deserialize_seq(Archives)
}

impl<'de> Deserialize<'de> for FidArchive {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        archive_from_wire(ArchiveWire::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

pub(super) fn deserialize_namespace<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<FidNamespace>, D::Error> {
    Option::<NamespaceWire>::deserialize(deserializer)?
        .map(namespace_from_wire)
        .transpose()
        .map_err(serde::de::Error::custom)
}

fn namespace_from_wire(wire: NamespaceWire) -> Result<FidNamespace, FidError> {
    if wire.version != 1 {
        return Err(FidError::Invalid("FID namespace version"));
    }
    let namespace = FidNamespace { version: 1, archives: wire.archives };
    namespace.validate()?;
    Ok(namespace)
}

fn archive_from_wire(archive: ArchiveWire) -> Result<FidArchive, FidError> {
    let mut total = 0usize;
    let mut bytes = Vec::new();
    for chunk in &archive.wire_chunks {
        if chunk.is_empty() || chunk.len() > 4096 || chunk.len() % 2 != 0 {
            return Err(FidError::Invalid("FID wire chunk length"));
        }
        total = total.checked_add(chunk.len() / 2).ok_or(FidError::Budget)?;
        if total > 64 << 20 {
            return Err(FidError::Budget);
        }
        for pair in chunk.as_bytes().as_chunks::<2>().0 {
            let nibble = |value: u8| match value {
                b'0'..=b'9' => Ok(value - b'0'),
                b'a'..=b'f' => Ok(value - b'a' + 10),
                _ => Err(FidError::Invalid("noncanonical FID wire hex")),
            };
            bytes.push(nibble(pair[0])? * 16 + nibble(pair[1])?);
        }
    }
    let db = FidDb::from_export(&bytes)?;
    let mut suppressed = BTreeSet::new();
    for id in archive.suppressed {
        if !db.functions.contains_key(&id) || !suppressed.insert(id) {
            return Err(FidError::Invalid("invalid FID suppression ID"));
        }
    }
    let canonical = archive_from_db(db)?;
    if canonical.wire_chunks != archive.wire_chunks {
        return Err(FidError::Invalid("noncanonical FID archive chunks"));
    }
    Ok(FidArchive { suppressed, ..canonical })
}

fn archive_from_db(db: FidDb) -> Result<FidArchive, FidError> {
    let bytes = db.to_export()?;
    let mut wire_chunks = Vec::new();
    for chunk in bytes.chunks(2048) {
        let mut hex = String::with_capacity(chunk.len() * 2);
        const HEX: &[u8] = b"0123456789abcdef";
        for byte in chunk {
            hex.push(HEX[(byte >> 4) as usize] as char);
            hex.push(HEX[(byte & 15) as usize] as char);
        }
        wire_chunks.push(hex);
    }
    Ok(FidArchive { db, wire_chunks, suppressed: BTreeSet::new() })
}

impl FidNamespace {
    pub fn new(db: FidDb) -> Result<Self, FidError> {
        let namespace = Self { version: 1, archives: vec![archive_from_db(db)?] };
        namespace.validate()?;
        Ok(namespace)
    }

    pub fn records(&self) -> usize {
        self.archives.iter().map(|archive| archive.db.functions.len()).sum()
    }

    pub fn validate(&self) -> Result<(), FidError> {
        if self.version != 1
            || self.archives.is_empty()
            || self.archives.len() > 64
            || self.records() > 1_000_000
            || self.archives.iter().flat_map(|archive| &archive.wire_chunks).map(String::len).sum::<usize>() > 128 << 20
        {
            return Err(FidError::Budget);
        }
        Ok(())
    }

    pub fn validate_arch(&self, arch: Arch) -> Result<(), FidError> {
        for library in self.archives.iter().flat_map(|archive| archive.db.libraries()) {
            if language_arch(&library.language_id)? != arch {
                return Err(FidError::Invalid("FID namespace architecture mismatch"));
            }
        }
        Ok(())
    }

    /// Transactional collision-safe union. Exact archive repeats are deduplicated and suppressions
    /// unioned. Other archives retain all contradictory records for ambiguity checks at query time.
    pub fn merge(&mut self, other: &Self) -> Result<(), FidError> {
        let mut merged = self.clone();
        for incoming in &other.archives {
            if let Some(existing) =
                merged.archives.iter_mut().find(|archive| archive.wire_chunks == incoming.wire_chunks)
            {
                existing.suppressed.extend(&incoming.suppressed);
            } else {
                merged.archives.push(incoming.clone());
            }
        }
        merged.validate()?;
        *self = merged;
        Ok(())
    }

    /// Suppression never removes matching constraints or contradictory records.
    pub fn retain_names(&mut self, allowed: &BTreeSet<String>) {
        for archive in &mut self.archives {
            archive.suppressed.extend(
                archive.db.functions().filter(|function| !allowed.contains(&function.name)).map(|function| function.id),
            );
        }
    }

    pub fn identify<'a>(&'a self, query: &FidQuery<'_>) -> FidMatchState<'a> {
        if self
            .query_work(query.hash.full_hash, query.callee_full_hashes.len() + query.caller_full_hashes.len())
            .is_err()
        {
            return FidMatchState::ResourceLimit;
        }
        let mut result: Option<(&FidFunction, &FidLibrary)> = None;
        for archive in &self.archives {
            for function in archive.db.candidates(query.hash.full_hash) {
                if !archive.db.eligible(function, query) {
                    continue;
                }
                if archive.suppressed.contains(&function.id) {
                    return FidMatchState::Suppressed;
                }
                let library = &archive.db.libraries[&function.library_id];
                if let Some((previous, previous_library)) = result
                    && (previous.name != function.name || !same_library(previous_library, library))
                {
                    return FidMatchState::Ambiguous;
                }
                result = Some((function, library));
            }
        }
        match result {
            Some((function, library)) => FidMatchState::Named { function, library },
            None => FidMatchState::NoMatch,
        }
    }

    fn query_work(&self, hash: u64, relations: usize) -> Result<usize, FidError> {
        let candidates: usize =
            self.archives.iter().map(|archive| archive.db.full_hash_index.get(&hash).map_or(0, Vec::len)).sum();
        let work = candidates.checked_mul(relations.checked_add(1).ok_or(FidError::Budget)?).ok_or(FidError::Budget)?;
        if work > 1_000_000 {
            return Err(FidError::Budget);
        }
        Ok(work)
    }
}

fn same_library(left: &FidLibrary, right: &FidLibrary) -> bool {
    left.family == right.family
        && left.version == right.version
        && left.variant == right.variant
        && left.ghidra_version == right.ghidra_version
        && left.language_id == right.language_id
        && left.language_version == right.language_version
        && left.language_minor_version == right.language_minor_version
        && left.compiler_spec_id == right.compiler_spec_id
}

fn language_arch(language: &str) -> Result<Arch, FidError> {
    match language {
        "x86:LE:64:default" => Ok(Arch::X86_64),
        "x86:LE:32:default" => Ok(Arch::X86),
        _ => Err(FidError::Unsupported("host matching currently supports default little-endian x86/x86-64 only")),
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FidMatchState<'a> {
    Named { function: &'a FidFunction, library: &'a FidLibrary },
    NoMatch,
    Ambiguous,
    Suppressed,
    RejectedByGate,
    UnsupportedBody,
    ResourceLimit,
}

impl crate::SignatureDb {
    /// Imports genuine raw `.fidbf` through an explicitly trusted reader into a separately persisted
    /// FID namespace. v1 supports x86/x86-64 FID profiles, rejects mixed native/PAT/FID evidence, and
    /// reserves enough direct-JSON capacity for later suppression tombstones. No native hashes change.
    pub fn from_fidbf(arch: Arch, path: &Path, reader: &FidReader) -> Result<Self, FidError> {
        Self::from_fid_db(arch, reader.import_file(path)?)
    }

    pub fn from_fid_db(arch: Arch, fid: FidDb) -> Result<Self, FidError> {
        if fid.functions.is_empty() {
            return Err(FidError::Invalid("FID database contains no function records"));
        }
        let mut db = Self::empty(arch, crate::CURRENT_SCHEME);
        db.fid = Some(FidNamespace::new(fid)?);
        db.validate_fid_namespace()?;
        Ok(db)
    }

    /// Loader/admission guard: CLI/MCP callers MUST reject ordinary byte-only apply when true,
    /// unless the explicit trusted-host query path is selected. Merely loading JSON never runs Java.
    pub fn requires_fid_adapter(&self) -> bool {
        self.fid.is_some()
    }

    pub fn fid_records(&self) -> usize {
        self.fid.as_ref().map_or(0, FidNamespace::records)
    }

    pub fn ensure_byte_matching_supported(&self) -> Result<(), FidError> {
        if self.requires_fid_adapter() {
            return Err(FidError::Unsupported("FID database requires explicit trusted Ghidra semantic analysis"));
        }
        Ok(())
    }

    /// Fallible byte-only API for admission-sensitive callers; existing native/PAT results are unchanged.
    pub fn identify_in_checked(
        &self,
        target: &rampage_arch::Target,
        image: &crate::MaskContext,
        bytes: &[u8],
        address: u64,
    ) -> Result<Option<&str>, FidError> {
        self.ensure_byte_matching_supported()?;
        Ok(self.identify_in(target, image, bytes, address))
    }

    /// Read-only real-FID query; never annotates names. Mixed native/PAT/FID namespaces explicitly
    /// reject until a combined known-negative arbitration policy is implemented, so no native/PAT
    /// ambiguity or conflicting answer can be revived by this separate namespace.
    pub fn identify_fid_program<'a>(
        &'a self,
        binary: &Binary,
        native_extents: &BTreeMap<u64, u64>,
        features: &FidProgramFeatures,
    ) -> Result<Vec<FidProgramMatch<'a>>, FidError> {
        self.validate_fid_namespace()?;
        let fid = self.fid.as_ref().ok_or(FidError::Unsupported("database has no FID namespace"))?;
        fid.identify_program(binary, native_extents, features)
    }

    pub fn identify_fid_with_host<'a>(
        &'a self,
        binary: &Binary,
        native_extents: &BTreeMap<u64, u64>,
        host: &FidHostAdapter,
    ) -> Result<Vec<FidProgramMatch<'a>>, FidError> {
        self.validate_fid_namespace()?;
        if self.fid.is_none() {
            return Err(FidError::Unsupported("database has no FID namespace"));
        }
        let features = host.analyze(binary)?;
        self.identify_fid_program(binary, native_extents, &features)
    }

    fn has_non_fid_evidence(&self) -> bool {
        self.pat.is_some()
            || !self.entries.is_empty()
            || !self.exact.is_empty()
            || !self.calls.is_empty()
            || !self.ambiguous.is_empty()
            || !self.ambiguous_exact.is_empty()
            || !self.ambiguous_calls.is_empty()
            || !self.entry_exact.is_empty()
            || !self.entry_calls.is_empty()
    }

    pub(super) fn validate_fid_namespace(&self) -> Result<(), FidError> {
        let Some(fid) = &self.fid else { return Ok(()) };
        if fid.records() == 0 {
            return Err(FidError::Invalid("empty FID namespace"));
        }
        if self.scheme != crate::CURRENT_SCHEME || self.has_non_fid_evidence() {
            return Err(FidError::Unsupported("mixed native/PAT/FID namespaces are unsupported in v1"));
        }
        fid.validate()?;
        fid.validate_arch(self.arch)?;
        let reserve: usize = fid
            .archives
            .iter()
            .flat_map(|archive| {
                archive
                    .db
                    .functions()
                    .filter(|function| !archive.suppressed.contains(&function.id))
                    .map(|function| function.id.to_string().len() + 1)
            })
            .sum();
        let mut counter = SizeCounter { bytes: reserve, limit: crate::MAX_SIGNATURE_DB_BYTES };
        serde_json::to_writer(&mut counter, self).map_err(|_| FidError::Budget)?;
        Ok(())
    }

    pub(super) fn merged_fid(&self, other: &Self) -> Result<Option<FidNamespace>, FidError> {
        if self.fid.is_none() && other.fid.is_none() {
            return Ok(None);
        }
        if self.has_non_fid_evidence() || other.has_non_fid_evidence() {
            return Err(FidError::Unsupported("mixed native/PAT/FID composition is unsupported in v1"));
        }
        let fid = match (&self.fid, &other.fid) {
            (Some(left), Some(right)) => {
                let mut merged = left.clone();
                merged.merge(right)?;
                merged
            }
            (Some(fid), None) | (None, Some(fid)) => fid.clone(),
            (None, None) => return Ok(None),
        };
        let mut candidate = Self::empty(self.arch, self.scheme);
        candidate.fid = Some(fid);
        candidate.validate_fid_namespace()?;
        Ok(candidate.fid)
    }
}

struct SizeCounter {
    bytes: usize,
    limit: usize,
}
impl Write for SizeCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.checked_add(bytes.len()).ok_or_else(|| std::io::Error::other("FID JSON budget"))?;
        if self.bytes > self.limit {
            return Err(std::io::Error::other("FID JSON budget"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Trusted-host feature result bound to exact input bytes. Target names are deliberately absent.
/// Public accessors expose evidence; construction always validates the owned bridge protocol.
#[derive(Clone, Debug)]
pub struct FidProgramFeatures {
    source_sha256: [u8; 32],
    ghidra_version: String,
    language_id: String,
    language_version: u32,
    language_minor_version: u32,
    compiler_spec_id: String,
    functions: BTreeMap<u64, FidProgramFunction>,
}

#[derive(Clone, Debug)]
pub struct FidProgramFunction {
    pub address: u64,
    pub hash: FidHashQuad,
    pub has_terminator: bool,
    pub is_thunk: bool,
    pub body_ranges: Vec<std::ops::Range<u64>>,
    /// Addresses only, resolved by static call references, never by producer/target function names.
    pub callees: Vec<u64>,
}

impl FidProgramFeatures {
    pub fn functions(&self) -> impl Iterator<Item = &FidProgramFunction> {
        self.functions.values()
    }
    pub fn source_sha256(&self) -> [u8; 32] {
        self.source_sha256
    }
    pub fn language_id(&self) -> &str {
        &self.language_id
    }

    pub fn from_export(bytes: &[u8]) -> Result<Self, FidError> {
        if bytes.len() as u64 > MAX_WIRE {
            return Err(FidError::Budget);
        }
        let mut input = Wire { bytes, position: 0 };
        if input.take(8)? != b"RPFPG001" || input.u32()? != FID_SCHEMA_VERSION {
            return Err(FidError::Invalid("program feature bridge/version"));
        }
        let source_sha256 = input.take(32)?.try_into().map_err(|_| FidError::Invalid("source SHA-256"))?;
        let mut program = Self {
            source_sha256,
            ghidra_version: input.text()?,
            language_id: {
                if input.text()? != "ghidra-12.1.4-x86-elf-minimal-v1" {
                    return Err(FidError::Unsupported("owned no-external-analysis host profile is required"));
                }
                input.text()?
            },
            language_version: input.u32()?,
            language_minor_version: input.u32()?,
            compiler_spec_id: input.text()?,
            functions: BTreeMap::new(),
        };
        if program.ghidra_version != "12.1.4" {
            return Err(FidError::Unsupported("Ghidra host must be 12.1.4"));
        }
        language_arch(&program.language_id)?;
        if program.compiler_spec_id.is_empty()
            || program.language_version > i32::MAX as u32
            || program.language_minor_version > i32::MAX as u32
        {
            return Err(FidError::Invalid("program language/compiler profile"));
        }
        let mut total_ranges = 0usize;
        let mut total_edges = 0usize;
        for _ in 0..input.count(100_000, 36)? {
            let address = input.u64()?;
            let hash = FidHashQuad {
                code_unit_size: input.u16()?,
                full_hash: input.u64()?,
                specific_hash_additional_size: input.u8()?,
                specific_hash: input.u64()?,
            };
            let flags = input.u8()?;
            if hash.code_unit_size > i16::MAX as u16 || hash.specific_hash_additional_size > 127 || flags & !3 != 0 {
                return Err(FidError::Invalid("program feature counts/flags"));
            }
            let count = input.count(4096, 16)?;
            total_ranges += count;
            if count == 0 || total_ranges > 1_000_000 {
                return Err(FidError::Budget);
            }
            let mut ranges = Vec::new();
            for _ in 0..count {
                let start = input.u64()?;
                let end = input.u64()?;
                if start >= end || ranges.last().is_some_and(|previous: &std::ops::Range<u64>| previous.end > start) {
                    return Err(FidError::Invalid("program body ranges"));
                }
                ranges.push(start..end);
            }
            if !ranges.iter().any(|range| range.contains(&address)) {
                return Err(FidError::Invalid("function entry/body"));
            }
            let count = input.count(100_000, 8)?;
            total_edges += count;
            if total_edges > 1_000_000 {
                return Err(FidError::Budget);
            }
            let mut callees = BTreeSet::new();
            for _ in 0..count {
                if !callees.insert(input.u64()?) {
                    return Err(FidError::Invalid("duplicate call reference"));
                }
            }
            let function = FidProgramFunction {
                address,
                hash,
                has_terminator: flags & 1 != 0,
                is_thunk: flags & 2 != 0,
                body_ranges: ranges,
                callees: callees.into_iter().collect(),
            };
            if program.functions.insert(address, function).is_some() {
                return Err(FidError::Invalid("duplicate program function"));
            }
        }
        if input.position != bytes.len()
            || program
                .functions
                .values()
                .flat_map(|function| &function.callees)
                .any(|address| !program.functions.contains_key(address))
        {
            return Err(FidError::Invalid("trailing bytes or dangling program call reference"));
        }
        Ok(program)
    }

    fn validate_binary(&self, binary: &Binary) -> Result<(), FidError> {
        binary
            .validate_available_backing_source()
            .map_err(|_| FidError::Invalid("native backing source changed during FID analysis"))?;
        if language_arch(&self.language_id)? != binary.arch
            || binary.big_endian
            || binary.embedded.is_some()
            || Sha256::digest(binary.image_bytes()).as_slice() != self.source_sha256
        {
            return Err(FidError::Invalid("program features do not bind this exact native binary/profile"));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct FidProgramMatch<'a> {
    pub address: u64,
    pub state: FidMatchState<'a>,
}

impl FidNamespace {
    /// Native consumer for real Ghidra hashes. Extents MUST come from independent native discovery,
    /// never copied from these host features. Mismatched/discontiguous extents remain explicitly
    /// unsupported; native confidence/thunk rejection precedes FID name lookup. No annotation occurs.
    pub fn identify_program<'a>(
        &'a self,
        binary: &Binary,
        native_extents: &BTreeMap<u64, u64>,
        features: &FidProgramFeatures,
    ) -> Result<Vec<FidProgramMatch<'a>>, FidError> {
        features.validate_binary(binary)?;
        self.validate_arch(binary.arch)?;
        if self
            .archives
            .iter()
            .flat_map(|archive| archive.db.libraries())
            .any(|library| library.ghidra_version != features.ghidra_version)
        {
            return Err(FidError::Unsupported("FID producer/host Ghidra profiles differ"));
        }
        let mut callers: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for function in features.functions.values() {
            for callee in &function.callees {
                callers.entry(*callee).or_default().push(function.hash.full_hash);
            }
        }
        let image = crate::MaskContext::from_binary(binary);
        let mut matches = Vec::new();
        let mut work = 0usize;
        for function in features.functions.values() {
            let mut state = FidMatchState::UnsupportedBody;
            if function.body_ranges.len() == 1 {
                let range = &function.body_ranges[0];
                if range.start == function.address
                    && native_extents.get(&function.address) == Some(&range.end)
                    && let Some(body) = binary.read(range.start, range.end - range.start)
                {
                    state = if function.is_thunk
                        || crate::function_hash_in(&binary.target(), &image, body, function.address).is_none()
                    {
                        FidMatchState::RejectedByGate
                    } else {
                        let callees: Vec<_> =
                            function.callees.iter().map(|address| features.functions[address].hash.full_hash).collect();
                        let parents: &[u64] = callers.get(&function.address).map_or(&[], Vec::as_slice);
                        work = work
                            .checked_add(self.query_work(function.hash.full_hash, callees.len() + parents.len())?)
                            .ok_or(FidError::Budget)?;
                        if work > 1_000_000 {
                            return Err(FidError::Budget);
                        }
                        self.identify(&FidQuery {
                            hash: function.hash,
                            language_id: &features.language_id,
                            language_version: features.language_version,
                            language_minor_version: features.language_minor_version,
                            compiler_spec_id: &features.compiler_spec_id,
                            has_terminator: function.has_terminator,
                            discriminating_body: true,
                            is_thunk: function.is_thunk,
                            callee_full_hashes: &callees,
                            caller_full_hashes: parents,
                        })
                    };
                }
            }
            matches.push(FidProgramMatch { address: function.address, state });
        }
        features.validate_binary(binary)?;
        Ok(matches)
    }
}

/// Explicit operator-selected trusted host JVM/Ghidra installation. Runs only the embedded fixed
/// exporter under Ghidra's static headless analyzer in a fresh private project. No target runs.
/// v1 supports static x86/x86-64 executable ELF images without recognized external/debug locators; other input
/// profiles return Unsupported rather than silently losing FID matching.
pub struct FidHostAdapter {
    pub java_executable: PathBuf,
    pub ghidra_home: PathBuf,
    pub temporary_root: PathBuf,
    pub timeout: Duration,
}

impl FidHostAdapter {
    pub fn analyze(&self, binary: &Binary) -> Result<FidProgramFeatures, FidError> {
        if !self.java_executable.is_absolute()
            || !self.ghidra_home.is_absolute()
            || !self.temporary_root.is_absolute()
            || self.ghidra_home.to_str().is_none()
            || self.temporary_root.to_str().is_none()
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(600)
        {
            return Err(FidError::Invalid("explicit absolute UTF-8 host roots and timeout <=600 seconds required"));
        }
        if !matches!(binary.arch, Arch::X86 | Arch::X86_64)
            || binary.big_endian
            || !binary.image_bytes().starts_with(b"\x7fELF")
            || binary.embedded.is_some()
            || !matches!(&binary.details, rampage_loaders::Details::Elf(details)
                if details.kind == "executable" && details.build_id.is_none()
                    && details.interpreter.is_none() && details.needed.is_empty())
            || binary.sections.iter().any(|section| external_debug_section(&section.name))
        {
            return Err(FidError::Unsupported("host v1 requires standalone x86 ELF without external/debug metadata"));
        }
        if binary.image_bytes().is_empty() || binary.image_bytes().len() as u64 > MAX_FILE {
            return Err(FidError::Budget);
        }
        let java = fs::canonicalize(&self.java_executable)?;
        regular_file(&java, u64::MAX)?;
        let utility = self.ghidra_home.join("Ghidra/Framework/Utility/lib/Utility.jar");
        regular_file(&utility, MAX_FILE)?;
        let stage = Stage::create(&self.temporary_root)?;
        let result = (|| {
            let input = stage.0.join("input.elf");
            let output = stage.0.join("features");
            let stdout = stage.0.join("stdout");
            let stderr = stage.0.join("stderr");
            new_file(&input)?.write_all(binary.image_bytes())?;
            new_file(&stage.0.join("FidProgramExport.java"))?.write_all(PROGRAM_EXPORTER.as_bytes())?;
            let mut command = Command::new(java);
            command
                .current_dir(&stage.0)
                .env_clear()
                .env("HOME", &stage.0)
                .env("TMPDIR", &stage.0)
                .arg("-Xmx512m")
                .arg("-XX:ActiveProcessorCount=1")
                .arg("-Xshare:off")
                .arg("-Djava.system.class.loader=ghidra.GhidraClassLoader")
                .arg("-Djava.awt.headless=true")
                .arg("-Djavax.xml.accessExternalDTD=")
                .arg("-Djavax.xml.accessExternalSchema=")
                .arg("-Djavax.xml.accessExternalStylesheet=")
                .arg(format!("-Duser.home={}", stage.0.display()))
                .arg(format!("-Djava.io.tmpdir={}", stage.0.display()))
                .arg(format!("-Dapplication.settingsdir={}/settings", stage.0.display()))
                .arg(format!("-Dapplication.cachedir={}/cache", stage.0.display()))
                .arg("-cp")
                .arg(utility)
                .arg("ghidra.Ghidra")
                .arg("ghidra.app.util.headless.AnalyzeHeadless")
                .arg(&stage.0)
                .arg("owned")
                .arg("-import")
                .arg(&input)
                .arg("-noanalysis")
                .arg("-loader")
                .arg("ElfLoader")
                .arg("-loader-loadLibraries")
                .arg("false")
                .arg("-loader-linkExistingProjectLibraries")
                .arg("false")
                .arg("-analysisTimeoutPerFile")
                .arg(self.timeout.as_secs().max(1).to_string())
                .arg("-max-cpu")
                .arg("1")
                .arg("-scriptPath")
                .arg(&stage.0)
                .arg("-postScript")
                .arg(stage.0.join("FidProgramExport.java"))
                .arg("features")
                .arg(&output)
                .arg(self.timeout.as_secs().max(1).to_string())
                .arg("-deleteProject");
            run_host(command, &stdout, &stderr, self.timeout, Some(&stage.0))?;
            let mut bytes = Vec::new();
            open_input(&output)?.take(MAX_WIRE + 1).read_to_end(&mut bytes)?;
            let features = FidProgramFeatures::from_export(&bytes)?;
            features.validate_binary(binary)?;
            Ok(features)
        })();
        stage.cleanup()?;
        result
    }
}

fn external_debug_section(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [".debug", ".zdebug", ".gnu_debug", ".stab", ".note", ".gdb", ".dwo", ".btf", ".ctf"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || name.ends_with(".dwo")
        || name == ".gnu.build.attributes"
}

fn run_host(
    mut command: Command,
    stdout: &Path,
    stderr: &Path,
    timeout: Duration,
    stage: Option<&Path>,
) -> Result<(), FidError> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(new_file(stdout)?))
        .stderr(Stdio::from(new_file(stderr)?))
        .spawn()?;
    let started = Instant::now();
    let result = loop {
        if let Err(error) = completed_budget(started, timeout, stdout, stderr) {
            break Err(error);
        }
        if let Some(root) = stage
            && let Err(error) = stage_budget(root)
        {
            break Err(error);
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(_)) => break Err(FidError::ReaderFailed),
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(error) => break Err(FidError::Io(error)),
        }
    };
    if result.is_err() {
        let _ = child.kill();
    }
    let waited = child.wait();
    result?;
    waited?;
    completed_budget(started, timeout, stdout, stderr)?;
    if let Some(root) = stage {
        stage_budget(root)?;
    }
    Ok(())
}

fn stage_budget(root: &Path) -> Result<(), FidError> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0usize;
    let mut bytes = 0u64;
    while let Some(directory) = pending.pop() {
        let contents = match fs::read_dir(directory) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in contents {
            let entry = entry?;
            entries += 1;
            if entries > 50_000 {
                return Err(FidError::Budget);
            }
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if metadata.is_symlink() {
                return Err(FidError::Invalid("host stage created an unexpected symlink"));
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                bytes = bytes.checked_add(metadata.len()).ok_or(FidError::Budget)?;
                if bytes > 512 << 20 {
                    return Err(FidError::Budget);
                }
            } else {
                return Err(FidError::Invalid("unexpected host stage file type"));
            }
        }
    }
    Ok(())
}

/// The native matcher must supply an exact, supported Ghidra semantic adapter and retain Rampage's
/// existing body-confidence gate. This API does not assert that such an adapter exists for any ISA.
pub struct FidQuery<'a> {
    pub hash: FidHashQuad,
    pub language_id: &'a str,
    pub language_version: u32,
    pub language_minor_version: u32,
    pub compiler_spec_id: &'a str,
    pub has_terminator: bool,
    pub discriminating_body: bool,
    pub is_thunk: bool,
    pub callee_full_hashes: &'a [u64],
    pub caller_full_hashes: &'a [u64],
}

struct Wire<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Wire<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], FidError> {
        let end = self.position.checked_add(length).ok_or(FidError::Budget)?;
        let value = self.bytes.get(self.position..end).ok_or(FidError::Invalid("truncated bridge"))?;
        self.position = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, FidError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, FidError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| FidError::Invalid("u16"))?))
    }
    fn u32(&mut self) -> Result<u32, FidError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| FidError::Invalid("u32"))?))
    }
    fn u64(&mut self) -> Result<u64, FidError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| FidError::Invalid("u64"))?))
    }
    fn count(&mut self, maximum: usize, minimum_record: usize) -> Result<usize, FidError> {
        let count = self.u32()? as usize;
        if count > maximum || count > (self.bytes.len() - self.position) / minimum_record {
            return Err(FidError::Budget);
        }
        Ok(count)
    }
    fn text(&mut self) -> Result<String, FidError> {
        let length = self.u32()? as usize;
        if length > MAX_STRING {
            return Err(FidError::Budget);
        }
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| FidError::Invalid("UTF-8"))
    }
}

/// Explicit operator configuration. No installation discovery, downloads, shell commands, target
/// execution, plugin discovery, or arbitrary scripts. The embedded owned source is host-compiled by
/// Java source-file mode against only the configured installation's DB/Generic/Utility jars.
pub struct FidReader {
    pub java_executable: PathBuf,
    pub ghidra_home: PathBuf,
    pub temporary_root: PathBuf,
    pub timeout: Duration,
}

impl FidReader {
    pub fn import_file(&self, input: &Path) -> Result<FidDb, FidError> {
        if !self.java_executable.is_absolute()
            || !self.ghidra_home.is_absolute()
            || !self.temporary_root.is_absolute()
            || self.ghidra_home.to_str().is_none()
            || self.temporary_root.to_str().is_none()
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(120)
        {
            return Err(FidError::Invalid("explicit absolute UTF-8 host roots and timeout required"));
        }
        // Operator-selected host tools may be installation symlinks. Resolve only this trusted
        // executable, never paths recorded by an imported database.
        let java_executable = fs::canonicalize(&self.java_executable)?;
        regular_file(&java_executable, u64::MAX)?;
        let input_file = open_input(input)?;
        let stage = Stage::create(&self.temporary_root)?;
        let result = (|| {
            let source = stage.0.join("FidExport.java");
            let database = stage.0.join("input.fidbf");
            let stdout = stage.0.join("stdout");
            let stderr = stage.0.join("stderr");
            new_file(&source)?.write_all(EXPORTER.as_bytes())?;
            let mut snapshot = new_file(&database)?;
            let opened_metadata = input_file.metadata()?;
            if !opened_metadata.is_file() || opened_metadata.len() == 0 || opened_metadata.len() > MAX_FILE {
                return Err(FidError::Invalid("opened input is not a bounded regular file"));
            }
            let copied = std::io::copy(&mut input_file.take(MAX_FILE + 1), &mut snapshot)?;
            if copied == 0 || copied > MAX_FILE {
                return Err(FidError::Budget);
            }
            drop(snapshot);
            let mut jars = Vec::new();
            for module in ["DB", "Generic", "Utility"] {
                let lib = self.ghidra_home.join("Ghidra/Framework").join(module).join("lib");
                regular_file(&lib.join(format!("{module}.jar")), MAX_FILE)?;
                // Wildcards are expanded by the trusted JVM, not a shell. Only framework jars, never
                // target paths or extension/plugin directories, enter the host classpath.
                jars.push(lib.join("*"));
            }
            let classpath = std::env::join_paths(jars).map_err(|_| FidError::Invalid("host classpath"))?;
            let mut command = Command::new(java_executable);
            command
                .env_clear()
                .env("HOME", &stage.0)
                .env("TMPDIR", &stage.0)
                .arg("-Xmx256m")
                .arg("-XX:ActiveProcessorCount=1")
                .arg(format!("-Djava.io.tmpdir={}", stage.0.display()))
                .arg(format!("-Duser.home={}", stage.0.display()))
                .arg(format!("-Dapplication.settingsdir={}/settings", stage.0.display()))
                .arg(format!("-Dapplication.cachedir={}/cache", stage.0.display()))
                .arg("--class-path")
                .arg(classpath)
                .arg(&source)
                .arg("export")
                .arg(&database);
            run_host(command, &stdout, &stderr, self.timeout, Some(&stage.0))?;
            let mut bytes = Vec::new();
            File::open(stdout)?.take(MAX_WIRE + 1).read_to_end(&mut bytes)?;
            FidDb::from_export(&bytes)
        })();
        stage.cleanup()?;
        result
    }
}

fn regular_file(path: &Path, maximum: u64) -> Result<(), FidError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(FidError::Invalid("expected nonempty bounded regular file, not symlink/device"));
    }
    Ok(())
}

fn new_file(path: &Path) -> Result<File, FidError> {
    Ok(OpenOptions::new().write(true).create_new(true).open(path)?)
}

/// Only the final path component is required not to be a symlink. Operator-selected ancestor
/// directories may be symlinks. The opened descriptor, never a prior pathname stat, is authoritative.
fn open_input(path: &Path) -> Result<File, FidError> {
    let file = open_input_descriptor(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_FILE {
        return Err(FidError::Invalid("opened input is not a nonempty bounded regular file"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(FidError::Invalid("input reparse points are unsupported"));
        }
    }
    Ok(file)
}

#[cfg(unix)]
fn open_input_descriptor(path: &Path) -> Result<File, FidError> {
    use rustix::fs::{Mode, OFlags, open};
    let descriptor = open(path, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())
        .map_err(std::io::Error::from)?;
    Ok(File::from(descriptor))
}

#[cfg(windows)]
fn open_input_descriptor(path: &Path) -> Result<File, FidError> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "GetFileType"]
        fn get_file_type(handle: *mut std::ffi::c_void) -> u32;
    }
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_TYPE_DISK: u32 = 1;
    let file = OpenOptions::new().read(true).share_mode(1).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path)?;
    // SAFETY: the live File owns this handle. Reject non-disk handles before any data read.
    if unsafe { get_file_type(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(FidError::Invalid("input is not a disk file"));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_input_descriptor(_path: &Path) -> Result<File, FidError> {
    Err(FidError::Invalid("safe FID file admission is unsupported on this host"))
}

fn completed_budget(started: Instant, timeout: Duration, stdout: &Path, stderr: &Path) -> Result<(), FidError> {
    if started.elapsed() >= timeout
        || fs::metadata(stdout)?.len() > MAX_WIRE
        || fs::metadata(stderr)?.len() > (64 << 10)
    {
        return Err(FidError::Budget);
    }
    Ok(())
}

struct Stage(PathBuf);
impl Stage {
    fn create(root: &Path) -> Result<Self, FidError> {
        for _ in 0..128 {
            let counter = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("rampage-fid-{}-{counter}", std::process::id()));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(FidError::Invalid("temporary directory collision budget"))
    }

    fn cleanup(self) -> Result<(), FidError> {
        // This exact 0700 directory was exclusively created by Stage, never supplied as a cleanup
        // target. remove_dir_all does not follow symlinks within it; host-created cache trees belong
        // to this stage too. Drop is only a best-effort fallback for errors/panics.
        fs::remove_dir_all(&self.0)?;
        Ok(())
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Operand objects from Ghidra's instruction prototype, NOT disassembly-text tokens or p-code IDs.
#[derive(Clone, Debug)]
pub enum FidOperandObject {
    /// `relocated` means a relocation intersects the operand mask's trimmed nonzero-byte range;
    /// `whole_operand`/`address` are Ghidra OperandType.isScalar/isAddress, not textual guesses.
    Scalar {
        signed_value: i64,
        relocated: bool,
        whole_operand: bool,
        address: bool,
    },
    Register {
        register_space_offset: u32,
    },
    Address,
    Other,
}

#[derive(Clone, Debug)]
pub struct FidOperand {
    /// Original zero-based instruction operand index (including operands without value masks).
    pub index: u16,
    pub has_value_mask: bool,
    pub objects: Vec<FidOperandObject>,
}

#[derive(Clone, Debug)]
pub struct FidCodeUnit {
    /// Original instruction bytes ANDed with the exact Ghidra instruction mask. A missing
    /// instruction mask is represented by 0xa5 repeated to the actual read size. Ghidra's default
    /// function extent contains instructions only, not data or padding between them.
    pub masked_bytes: Vec<u8>,
    pub operands: Vec<FidOperand>,
    pub is_call: bool,
    /// The selected Ghidra InstructionSkipper's result on the ORIGINAL, unmasked instruction bytes.
    pub skipped: bool,
}

/// Exact Ghidra FNV-1a digest/mixing over a previously decoded Ghidra-compatible feature stream.
/// Unsupported or untrusted feature extraction must not call this as a raw-byte normalizer.
/// Extent order, relocations and skipper selection belong to the architecture/language adapter.
pub fn hash_features(units: &[FidCodeUnit]) -> Result<Option<FidHashQuad>, FidError> {
    if units.len() > 100_000 {
        return Err(FidError::Budget);
    }
    if units.len() < 4 {
        return Ok(None);
    }
    let mut full = OFFSET;
    let mut specific = OFFSET;
    let mut code_unit_index = -1i32;
    let mut calls = 0u16;
    let mut scalar_count = 0u32;
    for unit in units {
        code_unit_index += 1;
        // Match Ghidra's increment-before-limit check, including its counted final un-hashed unit.
        if code_unit_index >= 32_766 {
            break;
        }
        if unit.masked_bytes.is_empty() || unit.masked_bytes.len() > 110_000 || unit.operands.len() > 256 {
            return Err(FidError::Invalid("code-unit/operand budget"));
        }
        if unit.skipped {
            code_unit_index -= 1;
            continue;
        }
        calls += u16::from(unit.is_call);
        let mut previous_index = None;
        for operand in &unit.operands {
            if operand.index > 255
                || operand.objects.len() > 256
                || previous_index.is_some_and(|index| index >= operand.index)
            {
                return Err(FidError::Invalid("operand indices or objects"));
            }
            previous_index = Some(operand.index);
            if !operand.has_value_mask {
                continue;
            }
            let mut full_update = (u32::from(operand.index) + 1).wrapping_mul(7777);
            let mut specific_update = full_update;
            for object in &operand.objects {
                match object {
                    FidOperandObject::Scalar { signed_value, relocated, whole_operand, address } => {
                        let include = !relocated
                            && if *whole_operand { !address } else { *signed_value > -256 && *signed_value < 256 };
                        let value = if include {
                            scalar_count += 1;
                            *signed_value as u32
                        } else {
                            0xfeed_dead
                        };
                        specific_update =
                            specific_update.wrapping_add(value.wrapping_add(1_234_567).wrapping_mul(67_999));
                        full_update = full_update.wrapping_add(0xfeed_dead);
                    }
                    FidOperandObject::Register { register_space_offset } => {
                        let value = register_space_offset.wrapping_add(7_654_321).wrapping_mul(98_777);
                        full_update = full_update.wrapping_add(value);
                        specific_update = specific_update.wrapping_add(value);
                    }
                    FidOperandObject::Address => {
                        specific_update =
                            specific_update.wrapping_add(0xfeed_deadu32.wrapping_add(1_234_567).wrapping_mul(67_999));
                        full_update = full_update.wrapping_add(0xfeed_dead);
                    }
                    FidOperandObject::Other => {}
                }
            }
            fnv_update(&mut full, &full_update.to_be_bytes());
            fnv_update(&mut specific, &specific_update.to_be_bytes());
        }
        fnv_update(&mut full, &unit.masked_bytes);
        fnv_update(&mut specific, &unit.masked_bytes);
    }
    let count = (code_unit_index + 1) as u16;
    if count < 4 {
        return Ok(None);
    }
    Ok(Some(FidHashQuad {
        code_unit_size: count - calls,
        full_hash: full,
        specific_hash_additional_size: scalar_count.min(127) as u8,
        specific_hash: specific,
    }))
}

fn fnv_update(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash = (*hash ^ u64::from(*byte)).wrapping_mul(PRIME);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNED_EXPORT: &[u8] = include_bytes!("../../../tests/fixtures/signatures/fid/owned.export");

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/signatures/fid").join(name)
    }

    fn test_stage() -> Stage {
        let root = std::env::var_os("RAMPAGE_FID_TEMP_ROOT").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        Stage::create(&root).unwrap()
    }

    fn native_extents() -> BTreeMap<u64, u64> {
        // Independent Rampage list_functions analysis on the stripped held-out ELF, NOT Ghidra ranges.
        BTreeMap::from([(0x201130, 0x201147), (0x201150, 0x201176), (0x201180, 0x2011a2)])
    }

    #[test]
    fn actual_native_fid_import_persists_and_matches_stripped_holdout() {
        let binary = Binary::open(fixture("native-heldout.elf")).unwrap();
        assert!(binary.symbols.iter().all(|symbol| !symbol.name.starts_with("owned_fid_")));
        let features = FidProgramFeatures::from_export(include_bytes!(
            "../../../tests/fixtures/signatures/fid/native-heldout.features"
        ))
        .unwrap();
        let fid = FidDb::from_export(include_bytes!("../../../tests/fixtures/signatures/fid/native.export")).unwrap();
        let db = crate::SignatureDb::from_fid_db(Arch::X86_64, fid).unwrap();
        assert_eq!(db.fid_records(), 2);
        assert!(db.requires_fid_adapter());
        assert!(db.ensure_byte_matching_supported().is_err());
        for restored in [
            crate::SignatureDb::from_json(&db.to_json()).unwrap(),
            crate::SignatureDb::from_gzip(&db.to_gzip().unwrap()).unwrap(),
        ] {
            let matched = restored.identify_fid_program(&binary, &native_extents(), &features).unwrap();
            let names: BTreeSet<_> = matched
                .iter()
                .filter_map(|matched| match &matched.state {
                    FidMatchState::Named { function, .. } => Some(function.name.as_str()),
                    _ => None,
                })
                .collect();
            assert_eq!(names, BTreeSet::from(["owned_fid_leaf", "owned_fid_mix"]));
        }
        let mut wrong_extents = native_extents();
        wrong_extents.insert(0x201130, 0x201146);
        let matched = db.identify_fid_program(&binary, &wrong_extents, &features).unwrap();
        assert!(matches!(
            matched.iter().find(|matched| matched.address == 0x201130).unwrap().state,
            FidMatchState::UnsupportedBody
        ));
        let negative = Binary::open(fixture("native-negative.elf")).unwrap();
        assert!(db.identify_fid_program(&negative, &native_extents(), &features).is_err());
        let negative_features = FidProgramFeatures::from_export(include_bytes!(
            "../../../tests/fixtures/signatures/fid/native-negative.features"
        ))
        .unwrap();
        assert!(
            db.identify_fid_program(&negative, &native_extents(), &negative_features)
                .unwrap()
                .iter()
                .all(|matched| !matches!(matched.state, FidMatchState::Named { .. }))
        );
    }

    #[test]
    fn fid_suppression_unknown_constraints_and_mixed_namespaces_fail_closed() {
        let fid = FidDb::from_export(include_bytes!("../../../tests/fixtures/signatures/fid/native.export")).unwrap();
        let mut db = crate::SignatureDb::from_fid_db(Arch::X86_64, fid).unwrap();
        let binary = Binary::open(fixture("native-heldout.elf")).unwrap();
        let features = FidProgramFeatures::from_export(include_bytes!(
            "../../../tests/fixtures/signatures/fid/native-heldout.features"
        ))
        .unwrap();
        db.retain_names(&BTreeSet::new());
        let mut restored = crate::SignatureDb::from_gzip(&db.to_gzip().unwrap()).unwrap();
        restored.combine(&db).unwrap();
        assert!(
            restored
                .identify_fid_program(&binary, &native_extents(), &features)
                .unwrap()
                .iter()
                .all(|matched| !matches!(matched.state, FidMatchState::Named { .. }))
        );
        let mut json: serde_json::Value = serde_json::from_str(&db.to_json()).unwrap();
        json["fid"]["archives"][0]["unknown_constraint"] = true.into();
        assert!(crate::SignatureDb::from_json(&json.to_string()).is_err());
        let mut json: serde_json::Value = serde_json::from_str(&db.to_json()).unwrap();
        json["entries"]["aa".repeat(32)] = "contradiction".into();
        assert!(crate::SignatureDb::from_json(&json.to_string()).is_err());
        let reference = Binary::open(fixture("native-reference.elf")).unwrap();
        let native = crate::SignatureDb::from_binary(&reference);
        assert!(!native.is_empty(), "owned named source must provide real qualifying native signatures");
        assert!(!db.can_merge(&native));
        assert!(db.combine(&native).is_err());
        let before = db.to_json();
        assert!(db.try_extend_from_binary_with_extents(&binary, &native_extents()).is_err());
        assert_eq!(db.to_json(), before);
        assert!(db.try_extend_from_binary(&reference).is_err());
        assert_eq!(db.to_json(), before);
        for (mut left, right) in [(db.clone(), native.clone()), (native.clone(), db.clone())] {
            let before = left.to_json();
            assert!(left.try_merge(&right).is_err());
            assert_eq!(left.to_json(), before);
            assert!(crate::SignatureDb::from_json(&left.to_json()).is_ok());
            assert!(crate::SignatureDb::from_gzip(&left.to_gzip().unwrap()).is_ok());
        }
    }

    #[test]
    fn namespace_node_budgets_and_suppression_constraints_reject_json_and_gzip() {
        let fid = FidDb::from_export(OWNED_EXPORT).unwrap();
        let db = crate::SignatureDb::from_fid_db(Arch::X86_64, fid).unwrap();
        assert!(db.entries.is_empty() && db.exact.is_empty() && db.calls.is_empty());
        let original: serde_json::Value = serde_json::from_str(&db.to_json()).unwrap();
        let rejects = |value: &serde_json::Value| {
            let json = value.to_string();
            assert!(crate::SignatureDb::from_json(&json).is_err());
            let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            gzip.write_all(json.as_bytes()).unwrap();
            assert!(crate::SignatureDb::from_gzip(&gzip.finish().unwrap()).is_err());
        };
        let mut unknown = original.clone();
        unknown["fid"]["version"] = 2.into();
        rejects(&unknown);
        let mut unknown = original.clone();
        unknown["fid"]["archives"][0]["suppressed"] = serde_json::json!([999]);
        rejects(&unknown);
        let mut duplicate = original.clone();
        duplicate["fid"]["archives"][0]["suppressed"] = serde_json::json!([100, 100]);
        rejects(&duplicate);
        let mut excessive = original.clone();
        excessive["fid"]["archives"] = vec![original["fid"]["archives"][0].clone(); 65].into();
        rejects(&excessive);
        let mut malformed = original;
        malformed["fid"]["archives"][0]["wire_chunks"][0] = "ff".into();
        rejects(&malformed);
    }

    #[test]
    fn private_stage_cleanup_removes_cache_tree_but_not_symlink_target() {
        let outer = test_stage();
        let outside = outer.0.join("outside");
        new_file(&outside).unwrap().write_all(b"keep").unwrap();
        let inner = Stage::create(&outer.0).unwrap();
        let inner_path = inner.0.clone();
        fs::create_dir_all(inner.0.join("user-ghidra/cache/scripts/nested")).unwrap();
        new_file(&inner.0.join("user-ghidra/cache/scripts/nested/payload")).unwrap().write_all(b"owned").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, inner.0.join("link")).unwrap();
        inner.cleanup().unwrap();
        assert!(!inner_path.exists());
        assert_eq!(fs::read(outside).unwrap(), b"keep");
        outer.cleanup().unwrap();
    }

    #[test]
    fn trusted_host_test_child() {
        if std::env::var_os("RAMPAGE_FID_TEST_CHILD_STDERR").is_some() {
            std::io::stderr().write_all(&vec![b'x'; 65_537]).unwrap();
        }
        #[cfg(unix)]
        if let Some(path) = std::env::var_os("RAMPAGE_FID_TEST_CHILD_FIFO") {
            assert!(open_input(Path::new(&path)).is_err());
        }
    }

    #[test]
    fn successful_host_exit_still_checks_stderr_and_deadline() {
        let stage = test_stage();
        let stdout = stage.0.join("stdout");
        let stderr = stage.0.join("stderr");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "fid::tests::trusted_host_test_child", "--nocapture"])
            .env("RAMPAGE_FID_TEST_CHILD_STDERR", "1");
        assert!(matches!(run_host(command, &stdout, &stderr, Duration::from_secs(10), None), Err(FidError::Budget)));
        let expired = Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
        fs::write(&stderr, []).unwrap();
        assert!(matches!(completed_budget(expired, Duration::from_secs(1), &stdout, &stderr), Err(FidError::Budget)));
        stage.cleanup().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_admission_rejects_swapped_symlink_and_fifo_without_waiting() {
        let stage = test_stage();
        let path = stage.0.join("input");
        let real = stage.0.join("real");
        fs::write(&path, b"preview").unwrap();
        fs::write(&real, b"real").unwrap();
        assert!(fs::symlink_metadata(&path).unwrap().is_file());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        assert!(open_input(&path).is_err());
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"preview").unwrap();
        assert!(fs::symlink_metadata(&path).unwrap().is_file());
        fs::remove_file(&path).unwrap();
        assert!(Command::new("/usr/bin/mkfifo").arg(&path).status().unwrap().success());
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "fid::tests::trusted_host_test_child", "--nocapture"])
            .env("RAMPAGE_FID_TEST_CHILD_FIFO", &path);
        run_host(command, &stage.0.join("stdout"), &stage.0.join("stderr"), Duration::from_secs(10), None).unwrap();
        stage.cleanup().unwrap();
    }

    #[test]
    fn external_debug_locators_are_unsupported_before_any_host_launch() {
        for name in [
            ".debug_info",
            ".gnu_debugaltlink",
            ".note.gnu.build-id",
            ".stab",
            ".stabstr",
            ".stab.exclstr",
            ".debug_gdb_scripts",
            ".BTF",
            ".gdb_index",
        ] {
            let mut binary = Binary::open(fixture("native-heldout.elf")).unwrap();
            binary.sections[0].name = name.to_owned();
            let host = FidHostAdapter {
                java_executable: PathBuf::from("/nonexistent/explicit-java"),
                ghidra_home: PathBuf::from("/nonexistent/explicit-ghidra"),
                temporary_root: std::env::temp_dir(),
                timeout: Duration::from_secs(30),
            };
            assert!(matches!(host.analyze(&binary), Err(FidError::Unsupported(_))), "allowed {name}");
        }
    }

    #[test]
    #[ignore = "requires explicitly selected trusted Ghidra 12.1.4/JDK and temporary root"]
    fn configured_real_fid_host_query() {
        let java_executable: PathBuf = std::env::var_os("RAMPAGE_FID_JAVA").unwrap().into();
        let ghidra_home: PathBuf = std::env::var_os("RAMPAGE_FID_GHIDRA_HOME").unwrap().into();
        let temporary_root: PathBuf = std::env::var_os("RAMPAGE_FID_TEMP_ROOT").unwrap().into();
        let stage_prefix = format!("rampage-fid-{}-", std::process::id());
        let own_stages = || {
            fs::read_dir(&temporary_root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(&stage_prefix))
                .map(|entry| entry.path())
                .collect::<BTreeSet<_>>()
        };
        let before = own_stages();
        let reader = FidReader {
            java_executable: java_executable.clone(),
            ghidra_home: ghidra_home.clone(),
            temporary_root: temporary_root.clone(),
            timeout: Duration::from_secs(30),
        };
        let database = crate::SignatureDb::from_fidbf(Arch::X86_64, &fixture("native.fidbf"), &reader).unwrap();
        let host = FidHostAdapter {
            java_executable,
            ghidra_home,
            temporary_root: temporary_root.clone(),
            timeout: Duration::from_secs(90),
        };
        let binary = Binary::open(fixture("native-heldout.elf")).unwrap();
        let matched = database.identify_fid_with_host(&binary, &native_extents(), &host).unwrap();
        let names: BTreeSet<_> = matched
            .iter()
            .filter_map(|matched| match matched.state {
                FidMatchState::Named { function, .. } => Some(function.name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(names, BTreeSet::from(["owned_fid_leaf", "owned_fid_mix"]));
        assert_eq!(own_stages(), before, "trusted-host execution left a private stage behind");
    }

    #[test]
    fn genuine_ghidra_export_keeps_hashes_and_relations() {
        let db = FidDb::from_export(OWNED_EXPORT).unwrap();
        assert_eq!(db.libraries().count(), 1);
        assert_eq!(db.functions().count(), 2);
        let function = db.candidates(0x9a12_3456_7812_3456).next().unwrap();
        assert_eq!(function.hash.specific_hash, 0xbc12_3456_7812_3456);
        assert_eq!(function.domain_path, "/untrusted/not-opened.c");
        assert!(db.has_callee_relation(100, 0x9a12_3456_7812_3457));
        assert!(db.has_caller_relation(101, 0x9a12_3456_7812_3456));
        assert!(!db.has_callee_relation(100, 0));
    }

    #[test]
    fn every_truncated_export_and_trailing_bytes_are_rejected() {
        for end in 0..OWNED_EXPORT.len() {
            assert!(FidDb::from_export(&OWNED_EXPORT[..end]).is_err(), "accepted truncation {end}");
        }
        let mut bytes = OWNED_EXPORT.to_vec();
        bytes.push(0);
        assert!(FidDb::from_export(&bytes).is_err());
        bytes[8..12].copy_from_slice(&7u32.to_be_bytes());
        assert!(FidDb::from_export(&bytes).is_err());
        assert!(FidDb::from_export(b"{\"functions\":[]}").is_err());
    }

    #[test]
    fn required_relation_and_confidence_cannot_be_bypassed() {
        let db = FidDb::from_export(OWNED_EXPORT).unwrap();
        let hash = db.functions.get(&100).unwrap().hash;
        let mut query = FidQuery {
            hash,
            language_id: "x86:LE:64:default",
            language_version: 4,
            language_minor_version: 6,
            compiler_spec_id: "gcc",
            has_terminator: true,
            discriminating_body: true,
            is_thunk: false,
            callee_full_hashes: &[],
            caller_full_hashes: &[],
        };
        assert!(db.identify(&query).is_none());
        query.callee_full_hashes = &[0x9a12_3456_7812_3457];
        assert_eq!(db.identify(&query).unwrap().name, "owned_fid_mix");
        query.discriminating_body = false;
        assert!(db.identify(&query).is_none());
        query.discriminating_body = true;
        query.is_thunk = true;
        assert!(db.identify(&query).is_none());
        query.is_thunk = false;
        query.language_version = 5;
        assert!(db.identify(&query).is_none());
    }

    #[test]
    fn full_hash_is_scalar_insensitive_but_specific_hash_is_not() {
        let mut units = vec![
            FidCodeUnit {
                masked_bytes: vec![0x90],
                is_call: false,
                skipped: false,
                operands: vec![FidOperand {
                    index: 0,
                    has_value_mask: true,
                    objects: vec![FidOperandObject::Scalar {
                        signed_value: 7,
                        relocated: false,
                        whole_operand: true,
                        address: false,
                    }],
                }],
            };
            4
        ];
        let first = hash_features(&units).unwrap().unwrap();
        units[0].operands[0].objects[0] =
            FidOperandObject::Scalar { signed_value: 9, relocated: false, whole_operand: true, address: false };
        let second = hash_features(&units).unwrap().unwrap();
        assert_eq!(first.full_hash, second.full_hash);
        assert_ne!(first.specific_hash, second.specific_hash);
        assert_eq!(first.specific_hash_additional_size, 4);
        units[0].skipped = true;
        assert!(hash_features(&units).unwrap().is_none());
    }

    #[test]
    fn actual_ghidra_hasher_oracle_vectors() {
        // Produced by FidHashOracle.java invoking Ghidra 12.1.4's MessageDigestFidHasher.
        // These are synthetic semantic-feature vectors, not claimed instruction-decoder fixtures.
        for (value, specific) in [
            (7, 0x05bf_bdda_5271_f50d),
            (9, 0xe1f3_9635_6fad_2099),
            (-256, 0x3f1e_cd9f_96fc_5321),
            (256, 0x4222_486c_603b_49a5),
        ] {
            let units = vec![
                FidCodeUnit {
                    masked_bytes: vec![0x90],
                    is_call: false,
                    skipped: false,
                    operands: vec![FidOperand {
                        index: 0,
                        has_value_mask: true,
                        objects: vec![FidOperandObject::Scalar {
                            signed_value: value,
                            relocated: false,
                            whole_operand: true,
                            address: false,
                        }],
                    }],
                };
                4
            ];
            assert_eq!(
                hash_features(&units).unwrap().unwrap(),
                FidHashQuad {
                    code_unit_size: 4,
                    full_hash: 0xe3ed_466a_b764_cc65,
                    specific_hash_additional_size: 4,
                    specific_hash: specific,
                }
            );
        }
    }

    #[test]
    fn malformed_bridge_counts_utf8_and_foreign_keys_fail_closed() {
        let mut bytes = OWNED_EXPORT.to_vec();
        bytes[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(FidDb::from_export(&bytes).is_err());
        let mut bytes = OWNED_EXPORT.to_vec();
        bytes[28] = 0xff; // First library-family UTF-8 byte.
        assert!(FidDb::from_export(&bytes).is_err());
        let mut input = Wire { bytes: OWNED_EXPORT, position: 12 };
        assert_eq!(input.u32().unwrap(), 1);
        input.u64().unwrap();
        for _ in 0..5 {
            input.text().unwrap();
        }
        input.u32().unwrap();
        input.u32().unwrap();
        input.text().unwrap();
        assert_eq!(input.u32().unwrap(), 2);
        let function_start = input.position;
        let mut bytes = OWNED_EXPORT.to_vec();
        bytes[function_start + 27..function_start + 35].copy_from_slice(&999u64.to_be_bytes());
        assert!(FidDb::from_export(&bytes).is_err());
        let mut bytes = OWNED_EXPORT.to_vec();
        bytes[function_start + 18] = 128;
        assert!(FidDb::from_export(&bytes).is_err());
    }

    #[test]
    fn ambiguous_names_versions_and_zero_hashes_do_not_name() {
        let mut db = FidDb::from_export(OWNED_EXPORT).unwrap();
        let original = db.functions.get(&101).unwrap().clone();
        let mut query = FidQuery {
            hash: original.hash,
            language_id: "x86:LE:64:default",
            language_version: 4,
            language_minor_version: 6,
            compiler_spec_id: "gcc",
            has_terminator: true,
            discriminating_body: true,
            is_thunk: false,
            callee_full_hashes: &[],
            caller_full_hashes: &[],
        };
        assert!(db.identify(&query).is_some());
        let mut alias = original.clone();
        alias.id = 102;
        alias.name = "different_name".into();
        db.functions.insert(102, alias);
        db.full_hash_index.get_mut(&original.hash.full_hash).unwrap().push(102);
        assert!(db.identify(&query).is_none());
        let mut library = db.library(1).unwrap().clone();
        library.id = 2;
        library.version = "2.0".into();
        db.libraries.insert(2, library);
        let alias = db.functions.get_mut(&102).unwrap();
        alias.name = original.name;
        alias.library_id = 2;
        assert!(db.identify(&query).is_none());
        db.functions.remove(&102);
        db.full_hash_index.get_mut(&query.hash.full_hash).unwrap().retain(|id| *id != 102);
        query.hash.specific_hash ^= 1;
        assert!(db.identify(&query).is_none());
        query.hash = original.hash;
        db.functions.get_mut(&101).unwrap().flags |= 4;
        assert!(db.identify(&query).is_none());
        db.functions.get_mut(&101).unwrap().flags &= !4;
        query.hash.full_hash = 0;
        assert!(db.identify(&query).is_none());
    }

    #[test]
    #[ignore = "requires explicit RAMPAGE_FID_JAVA, RAMPAGE_FID_GHIDRA_HOME and RAMPAGE_FID_TEMP_ROOT"]
    fn configured_real_fidbf_executor() {
        let reader = FidReader {
            java_executable: std::env::var_os("RAMPAGE_FID_JAVA").unwrap().into(),
            ghidra_home: std::env::var_os("RAMPAGE_FID_GHIDRA_HOME").unwrap().into(),
            temporary_root: std::env::var_os("RAMPAGE_FID_TEMP_ROOT").unwrap().into(),
            timeout: Duration::from_secs(30),
        };
        let input = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/signatures/fid/owned.fidbf");
        let db = reader.import_file(&input).unwrap();
        assert_eq!(db.functions().count(), 2);
        assert!(db.has_callee_relation(100, 0x9a12_3456_7812_3457));
    }
}
