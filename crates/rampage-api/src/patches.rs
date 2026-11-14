//! Bounded, original-image-bound patches and immutable effective analysis snapshots.
//!
//! A held `Project` never changes its binary. Acquire `Project::effective_snapshot` before a read operation;
//! patch/revert return that snapshot explicitly. Original mapped bytes and the annotation log remain authoritative.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use rampage_arch::Arch;
use rampage_loaders::{Binary, Format};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::annotations::{Annotations, Field};
use crate::{ApiError, Project};

pub const MAX_PATCH_BYTES: usize = 4096;
pub const MAX_ACTIVE_PATCHES: usize = 256;
pub const MAX_TOTAL_PATCH_BYTES: usize = 64 * 1024;
pub const MAX_PATCH_SOURCE_BYTES: usize = 256 * 1024 * 1024;
const MAX_PATCH_VALUE_BYTES: usize = 18 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BytePatch {
    pub version: u32,
    pub source_sha256: String,
    pub arch: String,
    pub image_offset: u64,
    pub image_length: u64,
    #[serde(
        serialize_with = "rampage_arch::hex::address",
        deserialize_with = "rampage_arch::hex::deserialize_address"
    )]
    pub address: u64,
    pub file_offset: u64,
    pub original_hex: String,
    pub replacement_hex: String,
    pub allow_data: bool,
    pub preimage_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PatchReceipt {
    pub source_sha256: String,
    pub effective_sha256: String,
    pub revision_sha256: String,
    pub active_ranges: usize,
    pub changed_bytes: usize,
    /// Owned effective bytes are not an original-file identity or producer-proof claim.
    pub original_backing_identity: bool,
}

pub struct PatchOutcome {
    pub project: Arc<Project>,
    pub receipt: PatchReceipt,
    pub changed: bool,
    /// Process-local authority nonce after transaction refresh and before this operation's edit. Compare with
    /// `Arc::ptr_eq`; a mismatch with a bound run is external attribution, not a reason to roll back this outcome.
    pub before_annotation_revision: Arc<()>,
    /// Committed authority nonce captured in the same transaction and shared by `project`'s frozen read view.
    /// A no-op has equal before/after nonces. This does not attest freshness after the transaction unlocks.
    pub after_annotation_revision: Arc<()>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatchExport {
    pub path: PathBuf,
    pub receipt: PatchReceipt,
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::Invalid(message.into())
}

fn hex(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(bytes)
}

fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

struct ExportStaging {
    directory: PathBuf,
    directory_file: File,
    path: PathBuf,
    file: File,
}

fn same_file(path: &Path, file: &File) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::symlink_metadata(path), file.metadata()) {
            (Ok(path), Ok(held)) => {
                !path.file_type().is_symlink() && (path.dev(), path.ino()) == (held.dev(), held.ino())
            }
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, file);
        false
    }
}

impl Drop for ExportStaging {
    fn drop(&mut self) {
        if same_file(&self.directory, &self.directory_file) {
            if same_file(&self.path, &self.file) {
                let _ = std::fs::remove_file(&self.path);
            }
            let _ = std::fs::remove_dir(&self.directory);
        }
    }
}

pub(crate) fn publish_export(
    output: &Path,
    bytes: &[u8],
    write: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
) -> Result<(), ApiError> {
    #[cfg(not(unix))]
    return Err(invalid("patch export requires Unix file-identity checks"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let parent = output.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let directory = (0..32)
            .find_map(|_| {
                let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = parent.join(format!(".rampage-patch-{}-{nonce}", std::process::id()));
                match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => Some(Ok(path)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .ok_or_else(|| invalid("cannot reserve private patch export staging"))?
            .map_err(|error| invalid(format!("create private patch export staging: {error}")))?;
        let directory_file = File::open(&directory).map_err(|error| invalid(error.to_string()))?;
        let path = directory.join("image");
        let file = match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(file) => file,
            Err(error) => {
                if same_file(&directory, &directory_file) {
                    let _ = std::fs::remove_dir(&directory);
                }
                return Err(invalid(format!("create patch export staging file: {error}")));
            }
        };
        let mut staging = ExportStaging { directory, directory_file, path, file };
        write(&mut staging.file, bytes)
            .map_err(|error| invalid(format!("write/sync patch export staging: {error}")))?;
        if !same_file(&staging.directory, &staging.directory_file) || !same_file(&staging.path, &staging.file) {
            return Err(invalid("private patch export staging identity changed"));
        }
        std::fs::hard_link(&staging.path, output)
            .map_err(|error| invalid(format!("publish new patch export {}: {error}", output.display())))?;
        if !same_file(output, &staging.file) {
            return Err(invalid("patch export destination was externally replaced"));
        }
        Ok(())
    }
}

fn lowercase_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_review_tokens(source_sha256: &str, revision: &str) -> Result<(), ApiError> {
    if !lowercase_hex(source_sha256, 32) || !lowercase_hex(revision, 32) {
        return Err(invalid("reviewed patch operations require lowercase 64-digit source SHA-256 and revision tokens"));
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() > MAX_PATCH_BYTES * 2 || !lowercase_hex(value, value.len() / 2) {
        return Err("patch bytes require 1..=4096 bytes of even-length lowercase hexadecimal".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| if byte <= b'9' { byte - b'0' } else { byte - b'a' + 10 };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}

fn preimage_digest(patch: &BytePatch) -> String {
    let mut hash = Sha256::new();
    hash.update(b"rampage-byte-patch-v1\0");
    hash.update(patch.source_sha256.as_bytes());
    hash.update(patch.arch.as_bytes());
    for value in [patch.image_offset, patch.image_length, patch.address, patch.file_offset] {
        hash.update(value.to_le_bytes());
    }
    hash.update([u8::from(patch.allow_data)]);
    hash.update(patch.original_hex.as_bytes());
    hex(&hash.finalize())
}

/// Record version of a patch to a whole-file ELF64 image; `file_offset` is a file offset.
const ELF_PATCH_VERSION: u32 = 1;
/// Record version of a patch to a Raw project; `source_sha256` is its interpretation identity and `file_offset`
/// the offset in its owned region bytes.
const RAW_PATCH_VERSION: u32 = 2;

fn validate_patch(patch: &BytePatch) -> Result<(), String> {
    let arch = match patch.version {
        ELF_PATCH_VERSION => matches!(patch.arch.as_str(), "x86_64" | "aarch64"),
        RAW_PATCH_VERSION => {
            (1..=32).contains(&patch.arch.len())
                && patch.arch.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        }
        _ => false,
    };
    if !arch
        || !lowercase_hex(&patch.source_sha256, 32)
        || !lowercase_hex(&patch.preimage_sha256, 32)
        || patch.image_offset != 0
        || patch.image_length == 0
        || patch.image_length > MAX_PATCH_SOURCE_BYTES as u64
    {
        return Err(
            "patch requires a version-1 whole-file ELF64 or version-2 Raw source identity and supported architecture"
                .into(),
        );
    }
    let original = decode_hex(&patch.original_hex)?;
    let replacement = decode_hex(&patch.replacement_hex)?;
    if original.len() != replacement.len() || original == replacement {
        return Err("patch must replace an equal, nonzero number of bytes with different bytes".into());
    }
    patch.address.checked_add(original.len() as u64).ok_or("patch address overflow")?;
    if patch.file_offset.checked_add(original.len() as u64).is_none_or(|end| end > patch.image_length) {
        return Err("patch file range exceeds its original image".into());
    }
    if preimage_digest(patch) != patch.preimage_sha256 {
        return Err("patch preimage fingerprint mismatch".into());
    }
    Ok(())
}

pub(crate) fn parse_patch(value: &str) -> Result<BytePatch, String> {
    if value.len() > MAX_PATCH_VALUE_BYTES {
        return Err("patch annotation exceeds its bounded value budget".into());
    }
    let patch: BytePatch = serde_json::from_str(value).map_err(|error| format!("invalid patch annotation: {error}"))?;
    validate_patch(&patch)?;
    Ok(patch)
}

pub(crate) fn encode_patch(patch: &BytePatch) -> Result<String, String> {
    validate_patch(patch)?;
    serde_json::to_string(patch).map_err(|error| error.to_string())
}

#[derive(Default)]
pub(crate) struct PatchLogShape {
    pub patch: bool,
    batch: bool,
    edits: bool,
    value: bool,
    previous: bool,
}

fn patch_kind_token(token: &[u8]) -> bool {
    if let Ok(value) = serde_json::from_slice::<String>(token) {
        return value == "patch";
    }
    let mut completed = token.to_vec();
    completed.push(b'"');
    if let Ok(prefix) = serde_json::from_slice::<String>(&completed) {
        return !prefix.is_empty() && "patch".starts_with(&prefix);
    }
    let raw = token.strip_prefix(b"\"").unwrap_or(token).trim_ascii_end();
    let prefix = raw.split(|byte| *byte == b'\\').next().unwrap_or_default();
    prefix.is_empty() || b"patch".starts_with(prefix) || prefix.starts_with(b"patch")
}

/// Bounded lexical classification precedes serde so duplicate keys, wrappers and torn patch values cannot turn
/// a patch-bearing record into an ignored legacy fragment. Only bounded key/value tokens are decoded.
pub(crate) fn patch_log_shape(line: &[u8]) -> PatchLogShape {
    let mut shape = PatchLogShape::default();
    let mut depth = 0usize;
    let mut at = 0usize;
    while at < line.len() {
        match line[at] {
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                at += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                at += 1;
            }
            b'"' => {
                let start = at;
                at += 1;
                while at < line.len() {
                    if line[at] == b'\\' {
                        at = (at + 2).min(line.len());
                    } else if line[at] == b'"' {
                        at += 1;
                        break;
                    } else {
                        at += 1;
                    }
                }
                if at - start > 1024 {
                    continue;
                }
                let Ok(key) = serde_json::from_slice::<String>(&line[start..at]) else { continue };
                if depth > 1 && key == "patch" {
                    shape.patch = true;
                }
                let mut next = at;
                while line.get(next).is_some_and(u8::is_ascii_whitespace) {
                    next += 1;
                }
                if line.get(next) != Some(&b':') {
                    continue;
                }
                match key.as_str() {
                    "batch" if depth <= 1 => shape.batch = true,
                    "edits" if depth <= 1 => shape.edits = true,
                    "value" if depth <= 1 => shape.value = true,
                    "previous" if depth <= 1 => shape.previous = true,
                    "field" => {
                        next += 1;
                        while line.get(next).is_some_and(u8::is_ascii_whitespace) {
                            next += 1;
                        }
                        if line.get(next) != Some(&b'"') {
                            continue;
                        }
                        let value_start = next;
                        next += 1;
                        while next < line.len() {
                            if line[next] == b'\\' {
                                next = (next + 2).min(line.len());
                            } else if line[next] == b'"' {
                                next += 1;
                                break;
                            } else {
                                next += 1;
                            }
                        }
                        let token = &line[value_start..next];
                        if token.len() <= 1024 {
                            shape.patch |= patch_kind_token(token);
                        }
                    }
                    _ => {}
                }
            }
            _ => at += 1,
        }
    }
    shape
}

fn validate_batch_id(batch: &str) -> Result<(), String> {
    if batch.is_empty() || batch.len() > 128 || batch.chars().any(char::is_control) {
        return Err("annotation batch IDs require 1..=128 non-control bytes".into());
    }
    Ok(())
}

pub(crate) fn validate_patch_log_line(line: &[u8]) -> Result<(), String> {
    validate_log_record_root(line)?;
    let shape = patch_log_shape(line);
    if !shape.patch && !shape.batch && !shape.edits {
        return Ok(());
    }
    if shape.edits {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Header {
            batch: String,
            edits: usize,
        }
        let header: Header = serde_json::from_slice(line).map_err(|error| error.to_string())?;
        validate_batch_id(&header.batch)?;
        if !(1..=8192).contains(&header.edits) {
            return Err("annotation batch count requires 1..=8192".into());
        }
        return Ok(());
    }
    if shape.patch && line.len() > 2 * MAX_PATCH_VALUE_BYTES + 1024 {
        return Err("patch log record exceeds its bounded envelope budget".into());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        #[serde(deserialize_with = "deserialize_log_field")]
        field: Field,
        #[serde(deserialize_with = "rampage_arch::hex::deserialize_address")]
        address: u64,
        value: Option<String>,
        previous: Option<String>,
        batch: Option<String>,
    }
    let envelope: Envelope = serde_json::from_slice(line).map_err(|error| error.to_string())?;
    let _ = envelope.address;
    if !shape.value || !shape.previous || shape.patch && envelope.field != Field::Patch {
        return Err("patch/batch records require an exact edit envelope".into());
    }
    if shape.batch {
        validate_batch_id(envelope.batch.as_deref().ok_or("annotation batch ID must be a string, not null")?)?;
    }
    if envelope.field == Field::Patch {
        for value in [&envelope.value, &envelope.previous].into_iter().flatten() {
            parse_patch(value)?;
        }
    }
    Ok(())
}

fn deserialize_log_field<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Field, D::Error> {
    let field = String::deserialize(deserializer)?;
    Field::deserialize(serde::de::value::StringDeserializer::<D::Error>::new(field))
}

pub(crate) fn validate_log_record_root(line: &[u8]) -> Result<(), String> {
    if !has_object_root(line)? {
        return Ok(());
    }
    let mut deserializer = serde_json::Deserializer::from_slice(line);
    serde::de::IgnoredAny::deserialize(&mut deserializer).map_err(record_syntax_error)?;
    deserializer.end().map_err(record_syntax_error)
}

pub(crate) fn validate_log_record_tail(tail: &[u8]) -> Result<(), String> {
    if !has_object_root(tail)? {
        return Ok(());
    }
    let mut deserializer = serde_json::Deserializer::from_slice(tail);
    match serde::de::IgnoredAny::deserialize(&mut deserializer) {
        Ok(_) => deserializer.end().map_err(record_syntax_error),
        Err(error) if error.is_eof() => Ok(()),
        Err(error) => Err(record_syntax_error(error)),
    }
}

fn has_object_root(bytes: &[u8]) -> Result<bool, String> {
    match bytes.iter().find(|byte| !byte.is_ascii_whitespace()) {
        None => Ok(false),
        Some(b'{') => Ok(true),
        Some(_) => Err("annotation records require an object root; arrays and scalar records are refused".into()),
    }
}

fn record_syntax_error(error: serde_json::Error) -> String {
    format!("annotation records require exactly one complete JSON object with no trailing tokens: {error}")
}

pub(crate) fn validate_patch_collection(values: &BTreeMap<u64, String>) -> Result<(), String> {
    if values.len() > MAX_ACTIVE_PATCHES {
        return Err("at most 256 active patch ranges are supported".into());
    }
    let mut total = 0usize;
    let mut previous_end = 0u64;
    let mut file_ranges = Vec::new();
    let mut identity = None;
    for (&address, value) in values {
        let patch = parse_patch(value)?;
        if address != patch.address || address < previous_end {
            return Err("patch keys must match their addresses and active virtual ranges must not overlap".into());
        }
        let length = patch.original_hex.len() / 2;
        total = total.checked_add(length).ok_or("patch byte budget overflow")?;
        if total > MAX_TOTAL_PATCH_BYTES {
            return Err("active patches are limited to 64 KiB".into());
        }
        previous_end = address.checked_add(length as u64).ok_or("patch address overflow")?;
        let range = patch.file_offset..patch.file_offset + length as u64;
        if file_ranges.iter().any(|existing| overlaps(existing, &range)) {
            return Err("active patches must not overlap in file offsets".into());
        }
        file_ranges.push(range);
        let current = (patch.source_sha256, patch.arch, patch.image_offset, patch.image_length);
        if identity.as_ref().is_some_and(|identity| identity != &current) {
            return Err("all active patches must belong to the same original source and selection".into());
        }
        identity = Some(current);
    }
    Ok(())
}

fn overlaps(left: &Range<u64>, right: &Range<u64>) -> bool {
    left.start < right.end && right.start < left.end
}

fn checked_range(start: u64, length: u64, limit: usize) -> Result<Range<u64>, String> {
    let end = start.checked_add(length).ok_or("ELF range overflow")?;
    if end > limit as u64 {
        return Err("ELF file range exceeds the original source".into());
    }
    Ok(start..end)
}

fn uint(bytes: &[u8], offset: usize, width: usize) -> Result<u64, String> {
    let end = offset.checked_add(width).ok_or("ELF field overflow")?;
    let bytes = bytes.get(offset..end).ok_or("truncated ELF field")?;
    let mut value = [0u8; 8];
    value[..width].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(value))
}

struct ElfSection {
    name: String,
    kind: u64,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    entry_size: u64,
}

struct ElfProgram {
    kind: u64,
    flags: u64,
    address: u64,
    offset: u64,
    file_size: u64,
    memory_size: u64,
}

struct ElfPayload {
    programs: Vec<ElfProgram>,
    sections: Vec<ElfSection>,
    protected: Vec<Range<u64>>,
}

impl ElfPayload {
    fn parse(bytes: &[u8], arch: Arch) -> Result<Self, String> {
        if bytes.len() > MAX_PATCH_SOURCE_BYTES
            || bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01")
            || uint(bytes, 52, 2)? != 64
            || uint(bytes, 16, 2)? != 2
            || uint(bytes, 20, 4)? != 1
            || uint(bytes, 18, 2)? != if arch == Arch::X86_64 { 62 } else { 183 }
        {
            return Err("V1 patches require a bounded static ET_EXEC little-endian ELF64 x86-64/AArch64 image".into());
        }
        let phoff = uint(bytes, 32, 8)?;
        let shoff = uint(bytes, 40, 8)?;
        let phnum = uint(bytes, 56, 2)?;
        let shnum = uint(bytes, 60, 2)?;
        let shstr = uint(bytes, 62, 2)?;
        if !(1..=1024).contains(&phnum)
            || !(1..=4096).contains(&shnum)
            || shstr == 0
            || shstr >= shnum
            || uint(bytes, 54, 2)? != 56
            || uint(bytes, 58, 2)? != 64
        {
            return Err("patches require bounded ordinary ELF program/section tables and section names".into());
        }
        let mut protected =
            vec![0..64, checked_range(phoff, phnum * 56, bytes.len())?, checked_range(shoff, shnum * 64, bytes.len())?];
        let name_header = (shoff + shstr * 64) as usize;
        if uint(bytes, name_header + 4, 4)? != 3 {
            return Err("ELF section-name table is not a string table".into());
        }
        let names = checked_range(uint(bytes, name_header + 24, 8)?, uint(bytes, name_header + 32, 8)?, bytes.len())?;
        protected.push(names.clone());
        let names = &bytes[names.start as usize..names.end as usize];
        let mut sections = Vec::new();
        for index in 0..shnum {
            let at = (shoff + index * 64) as usize;
            let name_offset = uint(bytes, at, 4)? as usize;
            let name = names.get(name_offset..).ok_or("invalid ELF section name offset")?;
            let end = name.iter().position(|byte| *byte == 0).ok_or("unterminated ELF section name")?;
            if end > 256 {
                return Err("ELF section name exceeds patch admission budget".into());
            }
            let section = ElfSection {
                name: String::from_utf8(name[..end].to_vec()).map_err(|_| "non-UTF-8 ELF section name")?,
                kind: uint(bytes, at + 4, 4)?,
                flags: uint(bytes, at + 8, 8)?,
                address: uint(bytes, at + 16, 8)?,
                offset: uint(bytes, at + 24, 8)?,
                size: uint(bytes, at + 32, 8)?,
                entry_size: uint(bytes, at + 56, 8)?,
            };
            section.address.checked_add(section.size).ok_or("ELF section address overflow")?;
            if section.kind != 8 {
                checked_range(section.offset, section.size, bytes.len())?;
            }
            sections.push(section);
        }
        let mut programs = Vec::new();
        for index in 0..phnum {
            let at = (phoff + index * 56) as usize;
            let program = ElfProgram {
                kind: uint(bytes, at, 4)?,
                flags: uint(bytes, at + 4, 4)?,
                offset: uint(bytes, at + 8, 8)?,
                address: uint(bytes, at + 16, 8)?,
                file_size: uint(bytes, at + 32, 8)?,
                memory_size: uint(bytes, at + 40, 8)?,
            };
            if matches!(program.kind, 2 | 3) {
                return Err("V1 patches refuse PT_DYNAMIC and PT_INTERP images".into());
            }
            let range = checked_range(program.offset, program.file_size, bytes.len())?;
            program.address.checked_add(program.memory_size).ok_or("ELF program address overflow")?;
            if program.file_size > program.memory_size {
                return Err("ELF program file size exceeds memory size".into());
            }
            if program.kind != 1 && !range.is_empty() {
                protected.push(range);
            }
            programs.push(program);
        }
        if sections.iter().any(|section| {
            matches!(section.kind, 6 | 11)
                || matches!(section.name.as_str(), ".dynamic" | ".dynsym" | ".dynstr" | ".interp")
        }) {
            return Err("V1 patches refuse dynamic loader metadata and payload lookalikes".into());
        }
        Ok(Self { programs, sections, protected })
    }

    fn file_offset(&self, bytes: &[u8], address: u64, length: usize, allow_data: bool) -> Result<u64, String> {
        let end = address.checked_add(length as u64).ok_or("patch address overflow")?;
        let virtual_range = address..end;
        let mappings: Vec<_> = self
            .programs
            .iter()
            .filter(|program| program.kind == 1)
            .filter(|program| overlaps(&(program.address..program.address + program.memory_size), &virtual_range))
            .collect();
        let [mapping] = mappings.as_slice() else {
            return Err("patch must have exactly one non-ambiguous mapped segment".into());
        };
        if address < mapping.address || end > mapping.address + mapping.file_size {
            return Err("patch must be wholly file-backed; zero-fill and boundary crossings are refused".into());
        }
        let offset = mapping.offset.checked_add(address - mapping.address).ok_or("patch file offset overflow")?;
        let file_range = checked_range(offset, length as u64, bytes.len())?;
        if self.protected.iter().any(|range| overlaps(range, &file_range)) {
            return Err("patch overlaps an ELF header, loader control range or table".into());
        }
        if self
            .programs
            .iter()
            .filter(|program| program.kind == 1)
            .filter(|program| overlaps(&(program.offset..program.offset + program.file_size), &file_range))
            .count()
            != 1
        {
            return Err("patch file bytes have multiple virtual mappings".into());
        }
        let sections: Vec<_> = self
            .sections
            .iter()
            .filter(|section| section.kind != 8 && section.size != 0)
            .filter(|section| overlaps(&(section.offset..section.offset + section.size), &file_range))
            .collect();
        let [section] = sections.as_slice() else {
            return Err("patch must have exactly one file-backed payload section without file aliases".into());
        };
        if section.kind != 1
            || section.flags & !(1 | 2 | 4 | 16 | 32) != 0
            || section.flags & 2 == 0
            || address < section.address
            || end > section.address + section.size
            || offset < section.offset
            || file_range.end > section.offset + section.size
            || offset - section.offset != address - section.address
        {
            return Err("patch section and segment mappings disagree or do not describe allocated payload".into());
        }
        let code = section.flags & 4 != 0
            && mapping.flags & 1 != 0
            && (section.name == ".text" || section.name.starts_with(".text."));
        let data = section.flags & 4 == 0
            && mapping.flags & 1 == 0
            && allow_data
            && (section.name == ".data"
                || section.name.starts_with(".data.")
                || section.name == ".rodata"
                || section.name.starts_with(".rodata."))
            && !section.name.starts_with(".data.rel");
        if !code && !data {
            return Err("only .text code payload is admitted by default; plain .data/.rodata require allow_data".into());
        }
        if self.sections.iter().any(|section| {
            section.flags & 2 != 0
                && section.size != 0
                && !std::ptr::eq(sections[0], section)
                && overlaps(&(section.address..section.address + section.size), &virtual_range)
        }) {
            return Err("patch virtual range has overlapping section descriptions".into());
        }
        let mut relocation_entries = 0u64;
        for section in &self.sections {
            if section.kind == 19 {
                return Err("ELF RELR loader relocations are not supported by patch admission".into());
            }
            if !matches!(section.kind, 4 | 9) || section.size == 0 {
                continue;
            }
            let stride = if section.kind == 4 { 24 } else { 16 };
            relocation_entries =
                relocation_entries.checked_add(section.size / stride).ok_or("ELF relocation count overflow")?;
            if section.entry_size != stride || section.size % stride != 0 || relocation_entries > 65536 {
                return Err("ELF relocation table exceeds patch admission limits".into());
            }
            for index in 0..section.size / stride {
                let target = uint(bytes, (section.offset + index * stride) as usize, 8)?;
                let end = target.checked_add(16).ok_or("ELF relocation target overflow")?;
                if overlaps(&(target..end), &virtual_range) {
                    return Err("patch overlaps a loader relocation target".into());
                }
            }
        }
        Ok(offset)
    }
}

/// What a patch's `file_offset` indexes: an admitted ELF64 file, or a Raw project's owned region bytes.
enum PatchTarget {
    Elf(ElfPayload),
    Raw,
}

impl PatchTarget {
    fn version(&self) -> u32 {
        match self {
            PatchTarget::Elf(_) => ELF_PATCH_VERSION,
            PatchTarget::Raw => RAW_PATCH_VERSION,
        }
    }
}

/// The owned-bytes offset of a Raw patch: wholly inside one backed region whose bytes the export can write back
/// (not decoder output); code regions by default, data and RAM initial values only with `allow_data`.
fn raw_patch_offset(binary: &Binary, address: u64, length: usize, allow_data: bool) -> Result<u64, String> {
    let raw = binary.raw_code_image().ok_or("Raw project has no retained admission facts")?;
    let end = address.checked_add(length as u64).ok_or("patch address overflow")?;
    let region = raw
        .regions()
        .iter()
        .find(|region| region.range().contains(&address))
        .ok_or("patch address lies outside every mapped Raw region")?;
    if end > region.range().end || !region.backed() {
        return Err(format!("patch must lie wholly inside the backed bytes of Raw region {}", region.name));
    }
    if matches!(region.source, Some(rampage_loaders::RawRegionSource::Decoded { .. })) {
        return Err(format!("Raw region {} is decoder output, which cannot be written back to its file", region.name));
    }
    if region.kind != rampage_loaders::RawRegionKind::Code && !allow_data {
        return Err(format!("Raw region {} is not code; patching it requires allow_data", region.name));
    }
    Ok(region.data_range().start as u64 + (address - region.base_address))
}

impl Project {
    fn patch_target(&self) -> Result<PatchTarget, String> {
        if self.binary.format == Format::Raw {
            return Ok(PatchTarget::Raw);
        }
        ElfPayload::parse(self.binary.file_bytes(), self.binary.arch).map(PatchTarget::Elf)
    }

    fn patch_file_offset(
        &self,
        target: &PatchTarget,
        address: u64,
        length: usize,
        allow_data: bool,
    ) -> Result<u64, String> {
        match target {
            PatchTarget::Elf(elf) => elf.file_offset(self.binary.file_bytes(), address, length, allow_data),
            PatchTarget::Raw => raw_patch_offset(&self.binary, address, length, allow_data),
        }
    }

    /// Mapped-file freshness for native sources; a Raw project's bytes are owned and bound by their identity.
    fn check_patch_backing(&self) -> Result<(), String> {
        if self.binary.format == Format::Raw {
            return Ok(());
        }
        self.binary.validate_backing_source().map_err(|error| error.to_string())
    }

    pub(crate) fn validate_patch_context(&self, annotations: &Annotations) -> Result<(), ApiError> {
        if &self.byte_patches != annotations.patches() {
            return Err(invalid(
                "held project byte revision is stale; acquire effective_snapshot before native mutation",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_patch_authority(&self, annotations: &Annotations) -> Result<(), String> {
        let source = self.patch_origin.as_deref().unwrap_or(self);
        if annotations.patches().is_empty() && source.patch_source_sha256.get().is_none() {
            return Ok(());
        }
        source.materialize_patches(annotations).map(|_| ())
    }

    pub(crate) fn patch_validation_project(&self, annotations: &Annotations) -> Result<Project, String> {
        let source = self.patch_origin.as_deref().unwrap_or(self);
        let (binary, _) = source.materialize_patches(annotations)?;
        let mut project = Project::with_annotations(binary, annotations.read_snapshot());
        project.byte_patches = annotations.patches().clone();
        project.frozen_annotations = Arc::new(std::sync::OnceLock::new());
        let _ = project.frozen_annotations.set(RwLock::new(annotations.read_snapshot()));
        project.set_packs(self.packs());
        Ok(project)
    }

    fn original_patch_project(self: &Arc<Self>) -> Arc<Self> {
        self.patch_origin.as_ref().map_or_else(|| Arc::clone(self), Arc::clone)
    }

    /// The original (unpatched) project this effective view was materialized from, or itself.
    pub(crate) fn patch_source(self: &Arc<Self>) -> Arc<Self> {
        self.original_patch_project()
    }

    /// Records the file a Raw project was read from, so an export can rewrite its original container. Only the
    /// first call takes effect.
    pub fn set_raw_source(&self, path: &Path) {
        let _ = self.raw_source.set(path.to_owned());
    }

    fn validate_patch_source(&self) -> Result<[u8; 32], String> {
        if self.binary.format == Format::Raw {
            let identity = self
                .binary
                .raw_interpretation_identity()
                .map_err(|error| error.to_string())?
                .ok_or("Raw project has no interpretation identity")?;
            if self.binary.image_bytes().len() > MAX_PATCH_SOURCE_BYTES || identity.sha256.len() != 64 {
                return Err("Raw patch source exceeds the patch admission budget".into());
            }
            let mut hash = [0u8; 32];
            for (index, byte) in hash.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&identity.sha256[2 * index..2 * index + 2], 16)
                    .map_err(|_| "Raw interpretation identity is not hexadecimal")?;
            }
            if *self.patch_source_sha256.get_or_init(|| hash) != hash {
                return Err("original patch source digest changed since admission".into());
            }
            return Ok(hash);
        }
        if self.binary.format != Format::Elf
            || !matches!(self.binary.arch, Arch::X86_64 | Arch::Aarch64)
            || self.binary.big_endian
            || self.binary.embedded.is_some()
            || self.binary.slices.len() != 1
            || self.binary.file_bytes().len() > MAX_PATCH_SOURCE_BYTES
            || self.binary.image_bytes().len() != self.binary.file_bytes().len()
        {
            return Err("patches require an original mapped whole-file little-endian ELF64 x86-64/AArch64 image".into());
        }
        if matches!(&self.binary.details, rampage_loaders::Details::Elf(details)
            if details.interpreter.is_some()
                || !details.needed.is_empty()
                || details.soname.is_some()
                || details.pie)
        {
            return Err("V1 patches refuse ELF interpreters, dynamic dependencies, SONAME and PIE images".into());
        }
        self.binary.validate_backing_source().map_err(|error| error.to_string())?;
        let hash: [u8; 32] = Sha256::digest(self.binary.file_bytes()).into();
        self.binary.validate_backing_source().map_err(|error| error.to_string())?;
        ElfPayload::parse(self.binary.file_bytes(), self.binary.arch)?;
        self.binary.validate_backing_source().map_err(|error| error.to_string())?;
        if *self.patch_source_sha256.get_or_init(|| hash) != hash {
            return Err("original patch source digest changed since admission".into());
        }
        Ok(hash)
    }

    fn validate_patch_metadata(annotations: &Annotations) -> Result<(), String> {
        if annotations.patches().is_empty() {
            return Ok(());
        }
        if !annotations.operand_types().is_empty()
            || !annotations.debug_types().is_empty()
            || !annotations.type_hints().is_empty()
            || annotations.types().values().chain(annotations.signatures().values()).any(|value| value.starts_with('!'))
            || annotations.type_library().values().any(|value| {
                crate::annotations::parse_type_library(value).map_or(true, |entries| {
                    entries.iter().any(|entry| {
                        entry
                            .source
                            .as_ref()
                            .is_some_and(|source| !matches!(source.kind.as_str(), "profile" | "header"))
                    })
                })
            })
        {
            return Err(concat!(
                "patches cannot coexist with byte-bound operands, derived hints or image-sealed producer layouts; ",
                "clear incompatible metadata first"
            )
            .into());
        }
        Ok(())
    }

    fn materialize_patches(&self, annotations: &Annotations) -> Result<(Binary, PatchReceipt), String> {
        validate_patch_collection(annotations.patches())?;
        Self::validate_patch_metadata(annotations)?;
        let source_hash = self.validate_patch_source()?;
        let original = self.binary.file_bytes();
        let target = self.patch_target()?;
        let mut bytes = original.to_vec();
        self.check_patch_backing()?;
        if target.version() == ELF_PATCH_VERSION && Sha256::digest(&bytes).as_slice() != source_hash {
            return Err("original source changed while copying patch materialization".into());
        }
        let mut total = 0usize;
        let mut revision = Sha256::new();
        revision.update(b"rampage-effective-patches-v1\0");
        revision.update(source_hash);
        for (&address, value) in annotations.patches() {
            let patch = parse_patch(value)?;
            let original_bytes = decode_hex(&patch.original_hex)?;
            let replacement = decode_hex(&patch.replacement_hex)?;
            let offset = self.patch_file_offset(&target, address, original_bytes.len(), patch.allow_data)?;
            if patch.version != target.version()
                || patch.source_sha256 != hex(&source_hash)
                || patch.arch != self.binary.arch.to_string()
                || patch.image_length != original.len() as u64
                || patch.file_offset != offset
                || original.get(offset as usize..offset as usize + original_bytes.len())
                    != Some(original_bytes.as_slice())
            {
                return Err("patch original identity, selection, unique mapping or preimage bytes do not match".into());
            }
            bytes[offset as usize..offset as usize + replacement.len()].copy_from_slice(&replacement);
            total += replacement.len();
            revision.update(address.to_le_bytes());
            revision.update(encode_patch(&patch)?.as_bytes());
        }
        self.check_patch_backing()?;
        if self.validate_patch_source()? != source_hash {
            return Err("original patch source changed during materialization".into());
        }
        let effective_sha256 = digest(&bytes);
        let binary = match target {
            PatchTarget::Raw => self.binary.with_raw_bytes(bytes),
            PatchTarget::Elf(_) => Binary::from_owned_native_bytes(bytes, self.binary.arch),
        }
        .map_err(|error| error.to_string())?;
        if binary.format != self.binary.format
            || binary.arch != self.binary.arch
            || binary.entry != self.binary.entry
            || binary.segments != self.binary.segments
            || binary.sections != self.binary.sections
            || binary.imports != self.binary.imports
            || binary.import_slots != self.binary.import_slots
            || binary.exports != self.binary.exports
            || binary.big_endian != self.binary.big_endian
            || binary.details != self.binary.details
            || binary.inventory_source_context() != self.binary.inventory_source_context()
        {
            return Err("patch changed admitted native image layout or loader metadata".into());
        }
        let receipt = PatchReceipt {
            source_sha256: hex(&source_hash),
            effective_sha256,
            revision_sha256: hex(&revision.finalize()),
            active_ranges: annotations.patches().len(),
            changed_bytes: total,
            original_backing_identity: false,
        };
        Ok((binary, receipt))
    }

    fn install_patch_validator(self: &Arc<Self>) {
        let source = Arc::downgrade(self);
        self.annotations.write().expect("annotations lock").set_patch_validator(Arc::new(move |annotations| {
            let source = source.upgrade().ok_or("original patch source is no longer retained")?;
            if annotations.patches().is_empty() && source.patch_source_sha256.get().is_none() {
                return Ok(());
            }
            source.materialize_patches(annotations).map(|_| ())
        }));
    }

    /// Returns an immutable byte revision with a frozen annotation read view and fresh analysis/native caches.
    /// Existing `&Project` reads continue to describe their held revision, not later patch edits. Mutations share
    /// the original annotation writer; acquire this snapshot again after any edit, undo, redo or refresh.
    pub fn effective_snapshot(self: &Arc<Self>) -> Result<Arc<Self>, ApiError> {
        let source = self.original_patch_project();
        source.install_patch_validator();
        let snapshot = {
            let mut annotations = source.annotations.write().expect("annotations lock");
            annotations.refresh_validated(|candidate| source.validate_patch_authority(candidate)).map_err(invalid)?;
            annotations.validate_patches().map_err(invalid)?;
            annotations.snapshot()
        };
        if snapshot.patches().is_empty() && source.patch_source_sha256.get().is_none() {
            return Ok(source);
        }
        if self.patch_origin.is_some() && Arc::ptr_eq(&self.annotations().revision(), &snapshot.revision()) {
            return Ok(Arc::clone(self));
        }
        let (binary, _) = source.materialize_patches(&snapshot).map_err(invalid)?;
        Ok(self.make_effective_project(&source, snapshot, binary))
    }

    fn make_effective_project(
        self: &Arc<Self>,
        source: &Arc<Self>,
        snapshot: Annotations,
        binary: Binary,
    ) -> Arc<Self> {
        let mut project = Project::with_annotations(binary, Annotations::in_memory());
        project.annotations = Arc::clone(&source.annotations);
        project.byte_patches = snapshot.patches().clone();
        let _ = project.frozen_annotations.set(RwLock::new(snapshot.read_snapshot()));
        project.patch_origin = Some(Arc::clone(source));
        project.set_packs(self.packs());
        {
            let old = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
            let mut state = project.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
            state.options = old.options.clone();
            state.worker = old.worker.clone();
        }
        Arc::new(project)
    }

    /// Explicit unreviewed mutation for trusted callers. User-facing review workflows must use
    /// `patch_bytes_reviewed`, which checks the source and revision inside the commit transaction.
    pub fn patch_bytes(
        self: &Arc<Self>,
        address: u64,
        original: &[u8],
        replacement: &[u8],
        allow_data: bool,
    ) -> Result<PatchOutcome, ApiError> {
        self.patch_bytes_inner(address, original, replacement, allow_data, None)
    }

    /// Checks source/revision consent under the same authoritative log transaction as the patch commit.
    pub fn patch_bytes_reviewed(
        self: &Arc<Self>,
        address: u64,
        original: &[u8],
        replacement: &[u8],
        allow_data: bool,
        source_sha256: &str,
        expected_revision: &str,
    ) -> Result<PatchOutcome, ApiError> {
        validate_review_tokens(source_sha256, expected_revision)?;
        self.patch_bytes_inner(address, original, replacement, allow_data, Some((source_sha256, expected_revision)))
    }

    fn validate_patch_review(&self, annotations: &Annotations, review: Option<(&str, &str)>) -> Result<(), ApiError> {
        if let Some((source_sha256, expected_revision)) = review {
            let (_, receipt) = self.materialize_patches(annotations).map_err(invalid)?;
            if receipt.source_sha256 != source_sha256 || receipt.revision_sha256 != expected_revision {
                return Err(invalid("patch source or revision changed since review; acquire a new receipt"));
            }
        }
        Ok(())
    }

    fn patch_bytes_inner(
        self: &Arc<Self>,
        address: u64,
        original: &[u8],
        replacement: &[u8],
        allow_data: bool,
        review: Option<(&str, &str)>,
    ) -> Result<PatchOutcome, ApiError> {
        if original.is_empty()
            || original.len() > MAX_PATCH_BYTES
            || original.len() != replacement.len()
            || original == replacement
        {
            return Err(invalid("patch requires different equal-length original/replacement bytes, 1..=4096 bytes"));
        }
        let source = self.original_patch_project();
        source.install_patch_validator();
        let source_sha256 = source.validate_patch_source().map_err(invalid)?;
        let target = source.patch_target().map_err(invalid)?;
        let file_offset = source.patch_file_offset(&target, address, original.len(), allow_data).map_err(invalid)?;
        if source.binary.file_bytes().get(file_offset as usize..file_offset as usize + original.len()) != Some(original)
        {
            return Err(invalid("expected original bytes do not match the original source (not the effective view)"));
        }
        let mut patch = BytePatch {
            version: target.version(),
            source_sha256: hex(&source_sha256),
            arch: source.binary.arch.to_string(),
            image_offset: 0,
            image_length: source.binary.file_bytes().len() as u64,
            address,
            file_offset,
            original_hex: hex(original),
            replacement_hex: hex(replacement),
            allow_data,
            preimage_sha256: String::new(),
        };
        patch.preimage_sha256 = preimage_digest(&patch);
        let value = encode_patch(&patch).map_err(invalid)?;
        let (changed, snapshot, binary, receipt, before_annotation_revision, after_annotation_revision) =
            source.annotations.write().expect("annotations lock").locked_staged_checked(|annotations| {
                let before_annotation_revision = annotations.revision();
                source.validate_patch_review(annotations, review)?;
                if let Some(previous) = annotations.patches().get(&address) {
                    let previous = parse_patch(previous).map_err(invalid)?;
                    if previous.original_hex != patch.original_hex || previous.file_offset != patch.file_offset {
                        return Err(invalid("an exact-key update must retain the same original range and preimage"));
                    }
                }
                let mut materialized = None;
                let changed = annotations
                    .set_validated(Field::Patch, address, Some(value), |candidate| {
                        materialized = Some(source.materialize_patches(candidate)?);
                        Ok(())
                    })
                    .map_err(invalid)?;
                let (binary, receipt) = match materialized {
                    Some(result) => result,
                    None => source.materialize_patches(annotations).map_err(invalid)?,
                };
                let after_annotation_revision = annotations.revision();
                Ok((
                    changed,
                    annotations.snapshot(),
                    binary,
                    receipt,
                    before_annotation_revision,
                    after_annotation_revision,
                ))
            })?;
        let project = self.make_effective_project(&source, snapshot, binary);
        Ok(PatchOutcome { project, receipt, changed, before_annotation_revision, after_annotation_revision })
    }

    /// Explicit unreviewed removal; user-facing review workflows must use `revert_patch_reviewed`.
    pub fn revert_patch(self: &Arc<Self>, address: u64) -> Result<PatchOutcome, ApiError> {
        self.revert_patch_inner(address, None)
    }

    pub fn revert_patch_reviewed(
        self: &Arc<Self>,
        address: u64,
        source_sha256: &str,
        expected_revision: &str,
    ) -> Result<PatchOutcome, ApiError> {
        validate_review_tokens(source_sha256, expected_revision)?;
        self.revert_patch_inner(address, Some((source_sha256, expected_revision)))
    }

    fn revert_patch_inner(
        self: &Arc<Self>,
        address: u64,
        review: Option<(&str, &str)>,
    ) -> Result<PatchOutcome, ApiError> {
        let source = self.original_patch_project();
        source.install_patch_validator();
        let (changed, snapshot, binary, receipt, before_annotation_revision, after_annotation_revision) =
            source.annotations.write().expect("annotations lock").locked_staged_checked(|annotations| {
                let before_annotation_revision = annotations.revision();
                source.validate_patch_review(annotations, review)?;
                let mut materialized = None;
                let changed = annotations
                    .set_validated(Field::Patch, address, None, |candidate| {
                        materialized = Some(source.materialize_patches(candidate)?);
                        Ok(())
                    })
                    .map_err(invalid)?;
                let (binary, receipt) = match materialized {
                    Some(result) => result,
                    None => source.materialize_patches(annotations).map_err(invalid)?,
                };
                let after_annotation_revision = annotations.revision();
                Ok((
                    changed,
                    annotations.snapshot(),
                    binary,
                    receipt,
                    before_annotation_revision,
                    after_annotation_revision,
                ))
            })?;
        let project = self.make_effective_project(&source, snapshot, binary);
        Ok(PatchOutcome { project, receipt, changed, before_annotation_revision, after_annotation_revision })
    }

    pub fn list_patches(&self) -> Result<Vec<BytePatch>, ApiError> {
        self.annotations().patches().values().map(|value| parse_patch(value).map_err(invalid)).collect()
    }

    /// Process-local byte-patch identity for `Arc::ptr_eq`, independent of name/comment revisions.
    /// This is not a persisted digest or a source-freshness attestation; use `patch_receipt` for export review.
    pub fn patch_revision(&self) -> Arc<()> {
        self.annotations().patches_revision()
    }

    /// Receipt for this held byte/annotation view, matching `list_patches`; this does not refresh authority.
    /// The reviewed mutation APIs compare its token with current authority again under the commit lock.
    pub fn patch_receipt(self: &Arc<Self>) -> Result<PatchReceipt, ApiError> {
        let source = self.original_patch_project();
        source.materialize_patches(&self.annotations()).map(|(_, receipt)| receipt).map_err(invalid)
    }

    /// Creates a new file only, never truncates or writes the mapped source, and never copies its annotation log.
    /// The expected revision binds export consent to a reviewed patch set. Cooperative log writers are locked
    /// through validation and creation; source checks do not claim atomicity against arbitrary external writers.
    pub fn export_patched(self: &Arc<Self>, path: &Path, expected_revision: &str) -> Result<PatchExport, ApiError> {
        let source = self.original_patch_project();
        source.install_patch_validator();
        source.annotations.write().expect("annotations lock").locked_staged_checked(|annotations| {
            let (binary, receipt) = source.materialize_patches(annotations).map_err(invalid)?;
            if receipt.revision_sha256 != expected_revision {
                return Err(invalid("patch revision changed since export review; acquire a new receipt"));
            }
            source.validate_patch_source().map_err(invalid)?;
            publish_export(path, binary.file_bytes(), |file, bytes| {
                file.write_all(bytes)?;
                file.sync_all()
            })?;
            Ok(PatchExport { path: path.to_owned(), receipt })
        })
    }
}

#[cfg(test)]
mod tests;
