//! Bounded import and native matching of user-supplied FLIRT PAT text, not hash conversion.
//!
//! Supported grammar (one record per line, followed by a required `---` line):
//! `PATTERN32 CRCLEN CRC16 MODULELEN (:OFFSET[@] NAME)+ [TAILPATTERN]`.
//! Bytes are two hex digits or `..`; lengths and offsets are hexadecimal. The initial pattern is
//! exactly 32 bytes, with wildcard padding beyond a short module. The optional contiguous tail starts
//! at `32 + CRCLEN`. Public and local names are retained, but only public names at offset zero can
//! name an already discovered function. `?` is an unknown name, never an answer. Aliases are not
//! arbitrarily canonicalized: different offset-zero names withhold the answer.
//!
//! References (`^OFFSET NAME`), negative offsets, name flags other than local `@`, and dumpsig's
//! `(OFFSET: BYTE)` tuples are explicitly unsupported. Import is atomic, including unsupported
//! records after otherwise valid ones. This is a useful subset, not a claim of full PAT support.
//!
//! Format facts were checked against the Apache-2.0 lancelot sources (not its database examples):
//! <https://github.com/williballenthin/lancelot/blob/master/flirt/src/pat/mod.rs> and
//! <https://github.com/williballenthin/lancelot/blob/master/flirt/src/lib.rs>.
//! This independently written parser copies no reference patterns or implementation code. CRC is
//! CRC-16/IBM-SDLC with the final value byte-swapped for PAT, as those sources specify; its independent
//! check vector is documented at <https://reveng.sourceforge.io/crc-catalogue/16.htm#crc.cat.crc-16-ibm-sdlc>.
//!
//! Integration: keep this database separate from scheme-1/2 hash entries, and pass the complete,
//! independently discovered body to `identify_in`. It requires exact module size and available body
//! bytes, the existing scheme-2 instruction/content gate, and sufficient explicit PAT content. It
//! never changes annotations. The caller must preserve analyst names and supply architecture from
//! the import request because PAT text has no architecture header. API file admission (regular file,
//! bounded read) remains the caller's responsibility; parsing itself is bounded and filesystem-free.

use std::collections::BTreeSet;
use std::fmt::Write;

use rampage_arch::{Arch, Target};
use serde::de::{DeserializeSeed, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{MIN_CONTENT_BYTES, MaskContext, function_hash_in};

/// Maximum UTF-8 PAT input, including comments, whitespace and the terminator.
pub const MAX_PAT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum physical lines, including comments and blank lines.
pub const MAX_PAT_LINES: usize = 100_000;
/// Maximum tokens per record and maximum bytes in any one token.
pub const MAX_PAT_FIELDS: usize = 4096;

const PREFIX_BYTES: usize = 32;

/// A line-numbered rejection; no database is returned on any error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("PAT line {line}: {reason}")]
pub struct PatError {
    /// One-based physical line, or zero for a whole-input/merge error.
    pub line: usize,
    pub reason: PatErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatErrorKind {
    #[error("input exceeds the PAT resource limit")]
    Limit,
    #[error("input is not valid UTF-8")]
    Utf8,
    #[error("invalid control character")]
    Control,
    #[error("missing --- terminator")]
    MissingTerminator,
    #[error("content after --- terminator")]
    TrailingContent,
    #[error("expected 32-byte pattern, CRC length, CRC16, module length and symbols")]
    Header,
    #[error("invalid hexadecimal field or byte pattern")]
    Hex,
    #[error("numeric overflow")]
    Overflow,
    #[error("constraint lies outside the module")]
    Range,
    #[error("zero-length CRC must have value 0000")]
    EmptyCrc,
    #[error("references require validated target-reference evidence and are not supported")]
    UnsupportedReference,
    #[error("dumpsig tail tuples are not PAT contiguous tail patterns and are not supported")]
    UnsupportedTailTuple,
    #[error("unsupported offset or symbol flags")]
    UnsupportedSymbol,
    #[error("missing or invalid symbol name")]
    Name,
    #[error("unexpected field or multiple tail patterns")]
    ExtraField,
    #[error("cannot combine PAT databases for different architectures")]
    Architecture,
}

fn error(line: usize, reason: PatErrorKind) -> PatError {
    PatError { line, reason }
}

/// One initial/tail byte constraint. Wildcards are whole bytes, never nibbles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PatternByte {
    Fixed(u8),
    Wildcard,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PatternName {
    pub offset: usize,
    pub name: String,
    /// Local labels are metadata, not function-name candidates.
    pub local: bool,
}

/// Validated PAT module constraints; accessors expose no mutable invariant-bearing storage.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PatternRecord {
    prefix: [PatternByte; PREFIX_BYTES],
    crc_len: u8,
    crc16: u16,
    module_len: usize,
    names: Vec<PatternName>,
    tail: Vec<PatternByte>,
    answer_allowed: bool,
}

impl PatternRecord {
    fn same_constraints(&self, other: &Self) -> bool {
        self.prefix == other.prefix
            && self.crc_len == other.crc_len
            && self.crc16 == other.crc16
            && self.module_len == other.module_len
            && self.names == other.names
            && self.tail == other.tail
    }

    fn write_pat(&self, text: &mut String) {
        fn write_bytes(text: &mut String, pattern: &[PatternByte]) {
            for byte in pattern {
                match byte {
                    PatternByte::Fixed(byte) => write!(text, "{byte:02X}").unwrap(),
                    PatternByte::Wildcard => text.push_str(".."),
                }
            }
        }
        write_bytes(text, &self.prefix);
        write!(text, " {:02X} {:04X} {:04X}", self.crc_len, self.crc16, self.module_len).unwrap();
        for name in &self.names {
            write!(text, " :{:04X}{} {}", name.offset, if name.local { "@" } else { "" }, name.name).unwrap();
        }
        if !self.tail.is_empty() {
            text.push(' ');
            write_bytes(text, &self.tail);
        }
    }

    pub fn prefix(&self) -> &[PatternByte; PREFIX_BYTES] {
        &self.prefix
    }

    pub fn crc_len(&self) -> u8 {
        self.crc_len
    }

    pub fn crc16(&self) -> u16 {
        self.crc16
    }

    pub fn module_len(&self) -> usize {
        self.module_len
    }

    pub fn names(&self) -> &[PatternName] {
        &self.names
    }

    pub fn tail(&self) -> &[PatternByte] {
        &self.tail
    }

    /// Number of explicit exact bytes, excluding wildcard padding and the CRC (only 16 bits).
    pub fn fixed_bytes(&self) -> usize {
        self.prefix[..self.module_len.min(PREFIX_BYTES)]
            .iter()
            .chain(self.tail.iter())
            .filter(|byte| matches!(byte, PatternByte::Fixed(_)))
            .count()
    }

    /// At least the existing fixed-content floor and at least half the explicit pattern positions.
    /// A CRC over a long wildcard-heavy module cannot supply missing fixed-byte confidence.
    pub fn has_discriminating_pattern(&self) -> bool {
        let positions = self.module_len.min(PREFIX_BYTES) + self.tail.len();
        let fixed = self.fixed_bytes();
        fixed >= MIN_CONTENT_BYTES && fixed * 2 >= positions
    }

    fn matches(&self, body: &[u8]) -> bool {
        if body.len() != self.module_len {
            return false;
        }
        let prefix_len = body.len().min(PREFIX_BYTES);
        if !match_bytes(&self.prefix[..prefix_len], &body[..prefix_len]) {
            return false;
        }
        if self.crc_len > 0 {
            let end = PREFIX_BYTES + usize::from(self.crc_len);
            if !body.get(PREFIX_BYTES..end).is_some_and(|bytes| flirt_crc16(bytes) == self.crc16) {
                return false;
            }
        }
        if self.tail.is_empty() {
            return true;
        }
        let start = PREFIX_BYTES + usize::from(self.crc_len);
        body.get(start..start + self.tail.len()).is_some_and(|bytes| match_bytes(&self.tail, bytes))
    }
}

/// All matching records are considered before producing an answer; record order never selects a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternMatch<'a> {
    NoMatch,
    RejectedByGate,
    Unique {
        name: &'a str,
        matching_records: usize,
    },
    /// Includes records with unknown/no public offset-zero names. Candidates can therefore be empty.
    Ambiguous {
        candidates: Vec<&'a str>,
        matching_records: usize,
    },
}

/// A validated user database. PAT constraints remain native patterns, never fabricated hash entries.
#[derive(Debug, Clone)]
pub struct PatternDb {
    arch: Arch,
    records: Vec<PatternRecord>,
    input_bytes: usize,
    input_lines: usize,
}

impl PatternDb {
    /// Parse the entire byte input atomically. No lossy UTF-8 conversion or accepted prefix on error.
    pub fn parse(arch: Arch, input: &[u8]) -> Result<Self, PatError> {
        if input.len() > MAX_PAT_BYTES {
            return Err(error(0, PatErrorKind::Limit));
        }
        let text = std::str::from_utf8(input).map_err(|_| error(0, PatErrorKind::Utf8))?;
        let mut records = Vec::new();
        let mut terminated = false;
        let mut input_lines = 0;
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            if line > MAX_PAT_LINES {
                return Err(error(line, PatErrorKind::Limit));
            }
            input_lines = line;
            if raw.chars().any(|ch| ch.is_control() && ch != '\t') {
                return Err(error(line, PatErrorKind::Control));
            }
            let raw = raw.trim_matches([' ', '\t']);
            if raw.is_empty() {
                continue;
            }
            if terminated {
                return Err(error(line, PatErrorKind::TrailingContent));
            }
            // Explicit comment extension, also used by open-source PAT producers for licensing.
            if raw.starts_with('#') {
                continue;
            }
            if raw == "---" {
                terminated = true;
                continue;
            }
            records.push(parse_record(raw, line)?);
        }
        if !terminated {
            return Err(error(input_lines.max(1), PatErrorKind::MissingTerminator));
        }
        let mut db = Self { arch, records, input_bytes: input.len(), input_lines };
        db.normalize();
        Ok(db)
    }

    pub fn arch(&self) -> Arch {
        self.arch
    }

    pub fn records(&self) -> &[PatternRecord] {
        &self.records
    }

    fn normalize(&mut self) {
        self.records.sort();
        self.records.dedup_by(|later, earlier| {
            if later.same_constraints(earlier) {
                earlier.answer_allowed &= later.answer_allowed;
                true
            } else {
                false
            }
        });
    }

    /// Preserve all constraints as negative evidence, disabling rather than deleting other answers.
    pub(crate) fn retain_names(&mut self, allowed: &BTreeSet<String>) {
        for record in &mut self.records {
            record.answer_allowed &= record
                .names
                .iter()
                .filter(|name| !name.local && name.offset == 0)
                .all(|name| allowed.contains(&name.name));
        }
    }

    pub(crate) fn can_merge(&self, other: &Self) -> bool {
        self.arch == other.arch
            && self.input_bytes.checked_add(other.input_bytes).is_some_and(|bytes| bytes <= MAX_PAT_BYTES)
            && self.input_lines.checked_add(other.input_lines).is_some_and(|lines| lines <= MAX_PAT_LINES)
    }

    /// Preserve every collision/unknown record when combining inputs, with no precedence override.
    /// Limits and architecture are checked before mutation. Unlike hash overlays, aliases never win.
    pub fn merge(&mut self, other: &Self) -> Result<(), PatError> {
        if self.arch != other.arch {
            return Err(error(0, PatErrorKind::Architecture));
        }
        let bytes = self.input_bytes.checked_add(other.input_bytes).ok_or(error(0, PatErrorKind::Limit))?;
        let lines = self.input_lines.checked_add(other.input_lines).ok_or(error(0, PatErrorKind::Limit))?;
        if bytes > MAX_PAT_BYTES || lines > MAX_PAT_LINES {
            return Err(error(0, PatErrorKind::Limit));
        }
        self.records.extend_from_slice(&other.records);
        self.input_bytes = bytes;
        self.input_lines = lines;
        self.normalize();
        Ok(())
    }

    /// Look up an independently bounded function. `body` must be exactly its discovered extent, not
    /// an image suffix; this enforces module size and never infers nonzero public-name boundaries.
    /// `image` is used by the existing hash confidence gate, not to normalize PAT literal bytes.
    pub fn match_in<'a>(&'a self, target: &Target, image: &MaskContext, body: &[u8], address: u64) -> PatternMatch<'a> {
        if target.arch != self.arch || address.checked_add(body.len() as u64).is_none() {
            return PatternMatch::NoMatch;
        }
        if function_hash_in(target, image, body, address).is_none() {
            return PatternMatch::RejectedByGate;
        }
        let mut candidates = BTreeSet::new();
        let mut matching_records = 0;
        let mut unnamed = false;
        let mut rejected_by_gate = false;
        for record in &self.records {
            if !record.matches(body) {
                continue;
            }
            // Weak matching records remain negative evidence; ignoring one would let a stronger
            // record name the same body despite the known collision.
            if !record.has_discriminating_pattern() {
                rejected_by_gate = true;
            }
            matching_records += 1;
            unnamed |= !record.answer_allowed;
            let mut record_named = false;
            for public in record.names.iter().filter(|name| !name.local && name.offset == 0) {
                if public.name == "?" {
                    unnamed = true;
                } else {
                    candidates.insert(public.name.as_str());
                    record_named = true;
                }
            }
            unnamed |= !record_named;
        }
        if matching_records == 0 {
            PatternMatch::NoMatch
        } else if rejected_by_gate {
            PatternMatch::RejectedByGate
        } else if candidates.len() == 1 && !unnamed {
            PatternMatch::Unique { name: candidates.into_iter().next().unwrap(), matching_records }
        } else {
            PatternMatch::Ambiguous { candidates: candidates.into_iter().collect(), matching_records }
        }
    }

    /// Only a gate-passing unique answer. The caller must not overwrite an analyst-supplied name.
    pub fn identify_in<'a>(
        &'a self,
        target: &Target,
        image: &MaskContext,
        body: &[u8],
        address: u64,
    ) -> Option<&'a str> {
        match self.match_in(target, image, body, address) {
            PatternMatch::Unique { name, .. } => Some(name),
            _ => None,
        }
    }
}

fn parse_record(raw: &str, line: usize) -> Result<PatternRecord, PatError> {
    let mut fields = Vec::new();
    for field in raw.split([' ', '\t']).filter(|field| !field.is_empty()) {
        if fields.len() == MAX_PAT_FIELDS || field.len() > MAX_PAT_FIELDS {
            return Err(error(line, PatErrorKind::Limit));
        }
        fields.push(field);
    }
    if fields.len() < 6 || fields[0].len() != PREFIX_BYTES * 2 {
        return Err(error(line, PatErrorKind::Header));
    }
    let prefix: [PatternByte; PREFIX_BYTES] =
        parse_bytes(fields[0], line)?.try_into().map_err(|_| error(line, PatErrorKind::Header))?;
    let crc_len = parse_hex(fields[1], 2, 2, line)? as u8;
    let crc16 = parse_hex(fields[2], 4, 4, line)? as u16;
    let module_len = parse_hex(fields[3], 4, 16, line)?;
    if module_len == 0 {
        return Err(error(line, PatErrorKind::Range));
    }
    if crc_len == 0 && crc16 != 0 {
        return Err(error(line, PatErrorKind::EmptyCrc));
    }
    let tail_start = PREFIX_BYTES + usize::from(crc_len);
    if crc_len > 0 && tail_start > module_len {
        return Err(error(line, PatErrorKind::Range));
    }
    if prefix.iter().skip(module_len).any(|byte| matches!(byte, PatternByte::Fixed(_))) {
        return Err(error(line, PatErrorKind::Range));
    }
    let mut names = Vec::new();
    let mut tail = Vec::new();
    let mut index = 4;
    while index < fields.len() {
        let field = fields[index];
        if field.starts_with('^') {
            return Err(error(line, PatErrorKind::UnsupportedReference));
        }
        if field.starts_with('(') {
            return Err(error(line, PatErrorKind::UnsupportedTailTuple));
        }
        if let Some(offset) = field.strip_prefix(':') {
            if !tail.is_empty() {
                return Err(error(line, PatErrorKind::ExtraField));
            }
            let local = offset.ends_with('@');
            let offset = offset.strip_suffix('@').unwrap_or(offset);
            if offset.starts_with('-') || offset.contains(['@', '?', '+']) {
                return Err(error(line, PatErrorKind::UnsupportedSymbol));
            }
            let offset = parse_hex(offset, 4, 16, line)?;
            if offset >= module_len {
                return Err(error(line, PatErrorKind::Range));
            }
            let name = fields.get(index + 1).ok_or(error(line, PatErrorKind::Name))?;
            if name.starts_with([':', '^', '(']) || name.chars().any(char::is_whitespace) {
                return Err(error(line, PatErrorKind::Name));
            }
            names.push(PatternName { offset, name: (*name).to_owned(), local });
            index += 2;
        } else {
            if names.is_empty() || !tail.is_empty() {
                return Err(error(line, PatErrorKind::ExtraField));
            }
            tail = parse_bytes(field, line)?;
            if tail_start.checked_add(tail.len()).is_none_or(|end| end > module_len) {
                return Err(error(line, PatErrorKind::Range));
            }
            index += 1;
        }
    }
    if names.is_empty() {
        return Err(error(line, PatErrorKind::Name));
    }
    Ok(PatternRecord { prefix, crc_len, crc16, module_len, names, tail, answer_allowed: true })
}

// Versioned JSON namespace: canonical PAT text in <=4096-byte UTF-8 chunks, plus indices of
// withheld records. Constraints are reparsed on every load; no unchecked AST can enter a database.
// Chunking keeps the existing gzip string preflight bound unchanged. Comments/formatting are not
// retained; all supported matching constraints and suppression evidence are. Total text <=16 MiB.
impl Serialize for PatternDb {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            version: u8,
            #[serde(with = "crate::arch_name")]
            arch: Arch,
            text: Vec<&'a str>,
            withheld: Vec<usize>,
        }
        let mut text = String::new();
        for record in &self.records {
            record.write_pat(&mut text);
            text.push('\n');
        }
        text.push_str("---");
        if text.len() > MAX_PAT_BYTES {
            return Err(serde::ser::Error::custom("PAT serialized text exceeds limit"));
        }
        let mut chunks = Vec::new();
        let mut remaining = text.as_str();
        while !remaining.is_empty() {
            let mut end = remaining.len().min(MAX_PAT_FIELDS);
            while !remaining.is_char_boundary(end) {
                end -= 1;
            }
            chunks.push(&remaining[..end]);
            remaining = &remaining[end..];
        }
        Wire {
            version: 1,
            arch: self.arch,
            text: chunks,
            withheld: self.records.iter().enumerate().filter_map(|(i, r)| (!r.answer_allowed).then_some(i)).collect(),
        }
        .serialize(serializer)
    }
}

// Only the bounded database loaders can deserialize this private wire type. PatternDb deliberately
// has no public Deserialize implementation, which would bypass the raw JSON preflight admission.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatternWire {
    version: u8,
    #[serde(with = "crate::arch_name")]
    arch: Arch,
    #[serde(deserialize_with = "text_chunks")]
    text: String,
    #[serde(deserialize_with = "withheld_indices")]
    withheld: Vec<usize>,
}

pub(crate) fn deserialize_namespace<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<PatternDb>, D::Error> {
    let Some(wire) = Option::<PatternWire>::deserialize(deserializer)? else { return Ok(None) };
    if wire.version != 1 {
        return Err(serde::de::Error::custom("unsupported PAT namespace version"));
    }
    let mut db = PatternDb::parse(wire.arch, wire.text.as_bytes()).map_err(serde::de::Error::custom)?;
    let mut previous = None;
    for index in wire.withheld {
        if previous.is_some_and(|last| index <= last) {
            return Err(serde::de::Error::custom("PAT withheld indices must be sorted and unique"));
        }
        let record = db
            .records
            .get_mut(index)
            .ok_or_else(|| serde::de::Error::custom("PAT withheld index outside record set"))?;
        record.answer_allowed = false;
        previous = Some(index);
    }
    Ok(Some(db))
}

fn text_chunks<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    struct AppendChunk<'a>(&'a mut String);
    impl<'de> DeserializeSeed<'de> for AppendChunk<'_> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
            deserializer.deserialize_str(self)
        }
    }
    impl<'de> Visitor<'de> for AppendChunk<'_> {
        type Value = ();
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a PAT text chunk of at most 4096 UTF-8 bytes")
        }
        fn visit_str<E: serde::de::Error>(self, chunk: &str) -> Result<(), E> {
            if chunk.len() > MAX_PAT_FIELDS || chunk.len() > MAX_PAT_BYTES - self.0.len() {
                return Err(E::custom("PAT text limit exceeded"));
            }
            self.0.push_str(chunk);
            Ok(())
        }
    }
    struct Chunks;
    impl<'de> Visitor<'de> for Chunks {
        type Value = String;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bounded UTF-8 PAT text chunks")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<String, A::Error> {
            let mut text = String::new();
            let mut count = 0;
            while let Some(()) = access.next_element_seed(AppendChunk(&mut text))? {
                count += 1;
                if count > MAX_PAT_LINES {
                    return Err(serde::de::Error::custom("PAT text limit exceeded"));
                }
            }
            Ok(text)
        }
    }
    deserializer.deserialize_seq(Chunks)
}

fn withheld_indices<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<usize>, D::Error> {
    struct Indices;
    impl<'de> Visitor<'de> for Indices {
        type Value = Vec<usize>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bounded withheld PAT record indices")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Vec<usize>, A::Error> {
            let mut indices = Vec::new();
            while let Some(index) = access.next_element()? {
                if indices.len() == MAX_PAT_LINES {
                    return Err(serde::de::Error::custom("PAT withheld index limit exceeded"));
                }
                indices.push(index);
            }
            Ok(indices)
        }
    }
    deserializer.deserialize_seq(Indices)
}

fn parse_hex(text: &str, min: usize, max: usize, line: usize) -> Result<usize, PatError> {
    if !(min..=max).contains(&text.len()) || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(error(line, PatErrorKind::Hex));
    }
    usize::from_str_radix(text, 16).map_err(|_| error(line, PatErrorKind::Overflow))
}

fn parse_bytes(text: &str, line: usize) -> Result<Vec<PatternByte>, PatError> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return Err(error(line, PatErrorKind::Hex));
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| match pair {
            b".." => Ok(PatternByte::Wildcard),
            _ => {
                let hex = std::str::from_utf8(pair).map_err(|_| error(line, PatErrorKind::Hex))?;
                Ok(PatternByte::Fixed(parse_hex(hex, 2, 2, line)? as u8))
            }
        })
        .collect()
}

fn match_bytes(pattern: &[PatternByte], bytes: &[u8]) -> bool {
    pattern.len() == bytes.len()
        && pattern.iter().zip(bytes).all(|(pattern, byte)| match pattern {
            PatternByte::Fixed(expected) => expected == byte,
            PatternByte::Wildcard => true,
        })
}

/// Reflected 0x1021 polynomial, init/xorout FFFF; PAT stores the final CRC byte-swapped.
fn flirt_crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xffff_u16;
    for &byte in bytes {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0x8408 } else { crc >> 1 };
        }
    }
    (!crc).swap_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Owned hand-authored x86-64 body: push rbp; mov rbp,rsp; mov eax,42; add eax,7; pop rbp; ret.
    const LEAF: &[u8] = &[0x55, 0x48, 0x89, 0xe5, 0xb8, 42, 0, 0, 0, 0x83, 0xc0, 7, 0x5d, 0xc3];

    fn target() -> Target {
        Target {
            arch: Arch::X86_64,
            big_endian: false,
            data_big_endian: false,
            thumb: std::sync::Arc::new([]),
            global_pointer: None,
            got: None,
            m_profile: false,
        }
    }

    fn leaf_record(names: &str) -> String {
        format!("554889E5B82A00000083C0075DC3{} 00 0000 000E {names}", "..".repeat(18))
    }

    fn parse(records: &str) -> PatternDb {
        PatternDb::parse(Arch::X86_64, format!("{records}\n---\n").as_bytes()).unwrap()
    }

    fn identify<'a>(db: &'a PatternDb, body: &[u8]) -> Option<&'a str> {
        db.identify_in(&target(), &MaskContext::default(), body, 0x401000)
    }

    #[test]
    fn crc_has_independent_catalogue_and_wire_vectors() {
        // RevEng IBM-SDLC check = 906E, PAT textual order = 6E90, not 906E or CCITT-FALSE 29B1.
        assert_eq!(flirt_crc16(b"123456789"), 0x6e90);
        // ITU X.25 Appendix I's 03 3F 5B EC codeword: wire FCS bytes are 5B EC.
        assert_eq!(flirt_crc16(&[0x03, 0x3f]), 0x5bec);
        assert_eq!(flirt_crc16(&[]), 0);
    }

    #[test]
    fn short_function_uses_wildcard_padding_without_reading_past_body() {
        let db = parse(&leaf_record(":0000 owned_leaf"));
        assert_eq!(identify(&db, LEAF), Some("owned_leaf"));
        assert_eq!(db.records()[0].fixed_bytes(), LEAF.len());
        assert_eq!(identify(&db, &LEAF[..LEAF.len() - 1]), None);
        let mut longer = LEAF.to_vec();
        longer.push(0x90);
        assert_eq!(identify(&db, &longer), None);
        let mut wrong = LEAF.to_vec();
        wrong[5] ^= 1;
        assert_eq!(identify(&db, &wrong), None);
    }

    #[test]
    fn crc_window_and_tail_are_both_required() {
        // The first 32 bytes decode; bytes 32..41 are the independent CRC check vector.
        let prefix = format!("{}{}", crate::hex(LEAF), "90".repeat(32 - LEAF.len()));
        let db = parse(&format!("{prefix} 09 6E90 002D :0000 owned_crc_tail A1..B2C3"));
        let mut body = LEAF.to_vec();
        body.resize(32, 0x90);
        body.extend_from_slice(b"123456789");
        body.extend_from_slice(&[0xa1, 0x44, 0xb2, 0xc3]);
        assert_eq!(identify(&db, &body), Some("owned_crc_tail"));
        body[42] = 0x99;
        assert_eq!(identify(&db, &body), Some("owned_crc_tail"));
        body[43] ^= 1;
        assert_eq!(identify(&db, &body), None);
        body[43] ^= 1;
        body[32] ^= 1;
        assert_eq!(identify(&db, &body), None);
        body[32] ^= 1;
        body[31] ^= 1;
        assert_eq!(identify(&db, &body), None);
    }

    #[test]
    fn zero_crc_tail_starts_at_32_not_at_zero_or_module_end() {
        let prefix = format!("{}{}", crate::hex(LEAF), "90".repeat(32 - LEAF.len()));
        let db = parse(&format!("{prefix} 00 0000 0022 :0000 owned_tail ..C3"));
        let mut body = LEAF.to_vec();
        body.resize(33, 0x90);
        body.push(0xc3);
        assert_eq!(identify(&db, &body), Some("owned_tail"));
        body[33] = 0xc2;
        assert_eq!(identify(&db, &body), None);
    }

    #[test]
    fn aliases_collisions_unknowns_and_merge_never_choose_first_name() {
        for names in [":0000 alpha :0000 beta", ":0000 beta :0000 alpha", ":0000 alpha :0000 ?"] {
            let db = parse(&leaf_record(names));
            assert_eq!(identify(&db, LEAF), None);
        }
        let mut db = parse(&leaf_record(":0000 alpha"));
        let beta = parse(&leaf_record(":0000 beta"));
        db.merge(&beta).unwrap();
        db.merge(&parse(&leaf_record(":0000 alpha"))).unwrap();
        assert_eq!(identify(&db, LEAF), None);
        assert_eq!(
            db.match_in(&target(), &MaskContext::default(), LEAF, 0x401000),
            PatternMatch::Ambiguous { candidates: vec!["alpha", "beta"], matching_records: 2 }
        );
        let mut known = parse(&leaf_record(":0000 alpha"));
        known.merge(&parse(&leaf_record(":0000 ?"))).unwrap();
        assert_eq!(identify(&known, LEAF), None);
    }

    #[test]
    fn repeated_same_name_is_not_ambiguous_and_nonzero_public_is_not_a_boundary() {
        let record = leaf_record(":0000 owned_leaf :0000 owned_leaf :0004 interior :0009@ local_label");
        let db = parse(&format!("{record}\n{record}"));
        assert_eq!(identify(&db, LEAF), Some("owned_leaf"));
        assert_eq!(db.records()[0].names()[2].offset, 4);
        for names in [":0004 interior", ":0000@ local_label", ":0000 ?"] {
            assert_eq!(identify(&parse(&leaf_record(names)), LEAF), None);
        }
    }

    #[test]
    fn wildcard_heavy_patterns_and_thunks_cannot_autoname() {
        let sparse = format!("554889E5B82A{} 00 0000 000E :0000 weak", "..".repeat(26));
        let db = parse(&sparse);
        assert!(function_hash_in(&target(), &MaskContext::default(), LEAF, 0x401000).is_some());
        assert_eq!(identify(&db, LEAF), None);
        // A weaker colliding record remains negative evidence, even when a strong one matches.
        let db = parse(&format!("{}\n{sparse}", leaf_record(":0000 strong")));
        assert_eq!(identify(&db, LEAF), None);
        let thunk = parse(&format!("E900000000{} 00 0000 0005 :0000 thunk", "..".repeat(27)));
        assert_eq!(identify(&thunk, &[0xe9, 0, 0, 0, 0]), None);
        let padding = parse(&format!("{} 00 0000 0020 :0000 padding", "90".repeat(32)));
        assert_eq!(identify(&padding, &[0x90; 32]), None);
    }

    #[test]
    fn malformed_and_unsupported_suffixes_reject_the_entire_import() {
        let good = leaf_record(":0000 valid");
        let invalid = [
            (good.replace("00 0000 000E", "0G 0000 000E"), PatErrorKind::Hex),
            (good.replace("00 0000 000E", "00 Z000 000E"), PatErrorKind::Hex),
            (good.replace("00 0000 000E", "00 0001 000E"), PatErrorKind::EmptyCrc),
            (good.replace("00 0000 000E", "01 0000 000E"), PatErrorKind::Range),
            (good.replace("000E :0000", "0000 :0000"), PatErrorKind::Range),
            (good.replace(":0000", ":000E"), PatErrorKind::Range),
            (good.replace(":0000", ":-0001"), PatErrorKind::UnsupportedSymbol),
            (good.replace(":0000", ":0000?"), PatErrorKind::UnsupportedSymbol),
            (good.replace("000E :0000", "10000000000000000 :0000"), PatErrorKind::Hex),
            (format!("{good} ^0001 actual_callee"), PatErrorKind::UnsupportedReference),
            (format!("{good} ^FFFF out_of_bounds"), PatErrorKind::UnsupportedReference),
            (format!("{good} (0000: FF)"), PatErrorKind::UnsupportedTailTuple),
            (format!("{good} FF"), PatErrorKind::Range),
            (good.replace("5548", "55.8"), PatErrorKind::Hex),
            (good.replacen("..", "FF", 1), PatErrorKind::Range),
            (good.replace("valid", "^0001"), PatErrorKind::Name),
        ];
        for (bad, expected) in invalid {
            let input = format!("{good}\n{bad}\n---\n");
            let err = PatternDb::parse(Arch::X86_64, input.as_bytes()).unwrap_err();
            assert_eq!(err.line, 2, "{bad}");
            assert_eq!(err.reason, expected, "{bad}");
        }
    }

    #[test]
    fn strict_terminator_utf8_and_control_handling() {
        assert!(PatternDb::parse(Arch::X86_64, b"# owned license\r\n---\r\n").is_ok());
        let good = leaf_record(":0000 valid");
        for (input, reason) in [
            (good.into_bytes(), PatErrorKind::MissingTerminator),
            (b"---\nanything".to_vec(), PatErrorKind::TrailingContent),
            (b"---\n# trailing".to_vec(), PatErrorKind::TrailingContent),
            (b"\xff\n---".to_vec(), PatErrorKind::Utf8),
            (b"# a\0b\n---".to_vec(), PatErrorKind::Control),
            (b"# a\rb\n---".to_vec(), PatErrorKind::Control),
        ] {
            assert_eq!(PatternDb::parse(Arch::X86_64, &input).unwrap_err().reason, reason);
        }
    }

    #[test]
    fn bounded_inputs_and_failed_merge_do_not_mutate_the_database() {
        let too_large = vec![b' '; MAX_PAT_BYTES + 1];
        assert_eq!(PatternDb::parse(Arch::X86_64, &too_large).unwrap_err().reason, PatErrorKind::Limit);
        let too_many_lines = format!("{}---", "\n".repeat(MAX_PAT_LINES));
        assert_eq!(PatternDb::parse(Arch::X86_64, too_many_lines.as_bytes()).unwrap_err().reason, PatErrorKind::Limit);
        let long_name = leaf_record(&format!(":0000 {}", "x".repeat(MAX_PAT_FIELDS + 1)));
        assert_eq!(PatternDb::parse(Arch::X86_64, long_name.as_bytes()).unwrap_err().reason, PatErrorKind::Limit);
        let too_many_fields = format!("{} {}\n---", leaf_record(":0000 valid"), ":0000 valid ".repeat(MAX_PAT_FIELDS));
        assert_eq!(PatternDb::parse(Arch::X86_64, too_many_fields.as_bytes()).unwrap_err().reason, PatErrorKind::Limit);
        let mut db = parse(&leaf_record(":0000 valid"));
        let other = PatternDb::parse(Arch::X86, b"---").unwrap();
        assert_eq!(db.merge(&other).unwrap_err().reason, PatErrorKind::Architecture);
        assert_eq!(identify(&db, LEAF), Some("valid"));
        assert_eq!(db.records().len(), 1);
    }

    #[test]
    fn architecture_and_address_overflow_are_not_matches() {
        let db = parse(&leaf_record(":0000 owned_leaf"));
        let mut wrong_target = target();
        wrong_target.arch = Arch::X86;
        assert_eq!(db.identify_in(&wrong_target, &MaskContext::default(), LEAF, 0x401000), None);
        assert_eq!(db.identify_in(&target(), &MaskContext::default(), LEAF, u64::MAX - 1), None);
    }

    fn signature_db(name: &str) -> crate::SignatureDb {
        crate::SignatureDb::from_pat(Arch::X86_64, format!("{}\n---", leaf_record(name)).as_bytes()).unwrap()
    }

    fn native_db(name: &str) -> crate::SignatureDb {
        let mut db = crate::SignatureDb::empty(Arch::X86_64, crate::CURRENT_SCHEME);
        db.add(function_hash_in(&target(), &MaskContext::default(), LEAF, 0x401000).unwrap(), None, None, name);
        db
    }

    fn identify_signature<'a>(db: &'a crate::SignatureDb, body: &[u8]) -> Option<&'a str> {
        db.identify_in(&target(), &MaskContext::default(), body, 0x401000)
    }

    #[test]
    fn signature_database_import_reaches_direct_and_program_matching() {
        let db = signature_db(":0000 owned_leaf");
        assert_eq!(db.scheme(), crate::CURRENT_SCHEME);
        assert!(!db.is_empty());
        assert_eq!(db.len(), 1);
        assert_eq!(db.pat_records(), 1);
        assert!(db.entries.is_empty());
        assert!(db.exact.is_empty());
        assert!(db.calls.is_empty());
        assert_eq!(identify_signature(&db, LEAF), Some("owned_leaf"));
        let image = MaskContext::default();
        let bodies = [(0x401000, LEAF), (0x402000, &[0xc3][..])];
        assert_eq!(
            crate::identify_program_sources(&[&db], &target(), &image, &bodies),
            std::collections::BTreeMap::from([(0x401000, (0, "owned_leaf".into()))]),
        );
        let lower = native_db("other_database");
        assert_eq!(crate::identify_program(&[&db, &lower], &target(), &image, &bodies)[&0x401000], "owned_leaf");
        assert_eq!(crate::identify_program(&[&lower, &db], &target(), &image, &bodies)[&0x401000], "other_database");
    }

    #[test]
    fn signature_database_crc_tail_constraints_survive_json_and_gzip() {
        let prefix = format!("{}{}", crate::hex(LEAF), "90".repeat(32 - LEAF.len()));
        let text = format!("{prefix} 09 6E90 002D :0000 owned_crc_tail A1..B2C3\n---");
        let db = crate::SignatureDb::from_pat(Arch::X86_64, text.as_bytes()).unwrap();
        let mut body = LEAF.to_vec();
        body.resize(32, 0x90);
        body.extend_from_slice(b"123456789");
        body.extend_from_slice(&[0xa1, 0x44, 0xb2, 0xc3]);
        let json = db.to_json();
        let gzip = db.to_gzip().unwrap();
        assert!(json.contains("\"pat\":{\"version\":1"));
        for loaded in [crate::SignatureDb::from_json(&json).unwrap(), crate::SignatureDb::from_gzip(&gzip).unwrap()] {
            assert_eq!(loaded.to_json(), json);
            assert_eq!(loaded.to_gzip().unwrap(), gzip);
            assert_eq!(identify_signature(&loaded, &body), Some("owned_crc_tail"));
            let mut wrong_crc = body.clone();
            wrong_crc[32] ^= 1;
            assert_eq!(identify_signature(&loaded, &wrong_crc), None);
            let mut wrong_tail = body.clone();
            wrong_tail[44] ^= 1;
            assert_eq!(identify_signature(&loaded, &wrong_tail), None);
            assert_eq!(identify_signature(&loaded, &body[..44]), None);
        }
    }

    #[test]
    fn composed_pat_records_are_order_independent_and_never_first_wins() {
        let alpha = signature_db(":0000 alpha");
        let beta = signature_db(":0000 beta");
        let unknown = signature_db(":0000 ?");
        let mut expected = None;
        for sources in [[&alpha, &beta, &unknown], [&unknown, &beta, &alpha], [&beta, &alpha, &unknown]] {
            let mut combined = sources[0].clone();
            combined.combine(sources[1]).unwrap();
            combined.combine(sources[2]).unwrap();
            combined.combine(sources[0]).unwrap();
            assert_eq!(combined.pat_records(), 3);
            assert_eq!(identify_signature(&combined, LEAF), None);
            let json = combined.to_json();
            if let Some(expected) = &expected {
                assert_eq!(&json, expected);
            } else {
                expected = Some(json.clone());
            }
            let loaded = crate::SignatureDb::from_gzip(&combined.to_gzip().unwrap()).unwrap();
            assert_eq!(identify_signature(&loaded, LEAF), None);
        }
        let mut priority = alpha.clone();
        priority.merge(&beta);
        assert_eq!(identify_signature(&priority, LEAF), None);
        let mut same = alpha.clone();
        same.combine(&alpha).unwrap();
        assert_eq!(same.pat_records(), 1);
        assert_eq!(identify_signature(&same, LEAF), Some("alpha"));
    }

    #[test]
    fn native_and_pat_names_in_one_database_must_agree() {
        for use_overlay in [false, true] {
            let mut mixed = native_db("native_name");
            let pat = signature_db(":0000 different_name");
            if use_overlay {
                mixed.merge(&pat);
            } else {
                mixed.combine(&pat).unwrap();
            }
            assert_eq!(identify_signature(&mixed, LEAF), None);
            let loaded = crate::SignatureDb::from_gzip(&mixed.to_gzip().unwrap()).unwrap();
            assert_eq!(identify_signature(&loaded, LEAF), None);
        }
        let mut same = native_db("same_name");
        same.combine(&signature_db(":0000 same_name")).unwrap();
        assert_eq!(identify_signature(&same, LEAF), Some("same_name"));
        let mut unknown = native_db("native_name");
        unknown.combine(&signature_db(":0000 ?")).unwrap();
        assert_eq!(identify_signature(&unknown, LEAF), None);
    }

    #[test]
    fn pat_retain_names_preserves_negative_records_and_suppression_across_reload_and_composition() {
        let mut alpha = signature_db(":0000 alpha");
        alpha.retain_names(&BTreeSet::new());
        assert_eq!(alpha.pat_records(), 1);
        assert_eq!(identify_signature(&alpha, LEAF), None);
        let mut loaded = crate::SignatureDb::from_gzip(&alpha.to_gzip().unwrap()).unwrap();
        loaded.combine(&signature_db(":0000 alpha")).unwrap();
        assert_eq!(loaded.pat_records(), 1);
        assert_eq!(identify_signature(&loaded, LEAF), None);
        loaded.retain_names(&BTreeSet::from(["alpha".to_owned()]));
        assert_eq!(identify_signature(&loaded, LEAF), None);

        let mut conflict = signature_db(":0000 alpha");
        conflict.combine(&signature_db(":0000 beta")).unwrap();
        conflict.retain_names(&BTreeSet::from(["alpha".to_owned()]));
        assert_eq!(conflict.pat_records(), 2);
        assert_eq!(identify_signature(&conflict, LEAF), None);
        let loaded = crate::SignatureDb::from_json(&conflict.to_json()).unwrap();
        assert_eq!(identify_signature(&loaded, LEAF), None);
    }

    #[test]
    fn pat_corpus_curation_and_composition_mismatches_reject_before_mutation() {
        let mut pat = signature_db(":0000 owned_leaf");
        let before = pat.to_json();
        let native = native_db("native");
        assert_eq!(pat.reject_reference_conflicts_from([&native]), Err(crate::CombineError::UnsupportedPatCuration));
        assert_eq!(pat.try_withhold_exact_fallbacks(), Err(crate::CombineError::UnsupportedPatCuration));
        assert_eq!(pat.to_json(), before);
        let mut native = native;
        let native_before = native.to_json();
        assert_eq!(native.reject_reference_conflicts_from([&pat]), Err(crate::CombineError::UnsupportedPatCuration));
        assert_eq!(native.to_json(), native_before);
        for (other, expected) in [
            (crate::SignatureDb::empty(Arch::X86, crate::CURRENT_SCHEME), crate::CombineError::ArchitectureMismatch),
            (crate::SignatureDb::empty(Arch::X86_64, crate::LEGACY_SCHEME), crate::CombineError::SchemeMismatch),
        ] {
            assert_eq!(pat.combine(&other), Err(expected));
            pat.merge(&other);
            assert_eq!(pat.to_json(), before);
        }
        let mut too_large = signature_db(":0000 excessive");
        too_large.pat.as_mut().unwrap().input_bytes = MAX_PAT_BYTES;
        assert_eq!(pat.combine(&too_large), Err(crate::CombineError::PatLimitExceeded));
        assert!(!pat.can_merge(&too_large));
        pat.merge(&too_large);
        assert_eq!(pat.to_json(), before);
    }

    #[test]
    fn serialized_pat_is_revalidated_instead_of_trusting_a_constraint_ast() {
        let db = signature_db(":0000 owned_leaf");
        let original: serde_json::Value = serde_json::from_str(&db.to_json()).unwrap();
        let mut malformed = Vec::new();
        let mut changed = original.clone();
        changed["pat"]["version"] = 2.into();
        malformed.push(changed);
        let mut changed = original.clone();
        changed["pat"]["arch"] = "aarch64".into();
        malformed.push(changed);
        let mut changed = original.clone();
        changed["scheme"] = crate::LEGACY_SCHEME.into();
        malformed.push(changed);
        let mut changed = original.clone();
        changed["pat"]["withheld"] = serde_json::json!([1]);
        malformed.push(changed);
        let mut changed = original.clone();
        changed["pat"]["withheld"] = serde_json::json!([0, 0]);
        malformed.push(changed);
        let mut changed = original.clone();
        changed["pat"]["ignored_constraint"] = true.into();
        malformed.push(changed);
        let mut changed = original.clone();
        changed["pat"]["text"] = serde_json::json!([format!("{} ^0001 target\n---", leaf_record(":0000 leaf"))]);
        malformed.push(changed);
        let mut changed = original;
        changed["pat"]["text"] = serde_json::json!(["x".repeat(MAX_PAT_FIELDS + 1)]);
        malformed.push(changed);
        for value in malformed {
            let text = value.to_string();
            assert!(crate::SignatureDb::from_json(&text).is_err());
            let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            std::io::Write::write_all(&mut gzip, text.as_bytes()).unwrap();
            assert!(crate::SignatureDb::from_gzip(&gzip.finish().unwrap()).is_err());
        }
    }

    #[test]
    fn multi_chunk_pat_text_roundtrips_without_relaxing_gzip_string_limits() {
        let records = (0..90).map(|index| leaf_record(&format!(":0000 owned_{index}"))).collect::<Vec<_>>().join("\n");
        let db = crate::SignatureDb::from_pat(Arch::X86_64, format!("{records}\n---").as_bytes()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&db.to_json()).unwrap();
        let chunks = json["pat"]["text"].as_array().unwrap();
        assert!(chunks.len() > 1);
        assert!(chunks.iter().all(|chunk| chunk.as_str().unwrap().len() <= MAX_PAT_FIELDS));
        let loaded = crate::SignatureDb::from_gzip(&db.to_gzip().unwrap()).unwrap();
        assert_eq!(loaded.pat_records(), 90);
        assert_eq!(loaded.to_json(), db.to_json());
        assert_eq!(identify_signature(&loaded, LEAF), None);
    }

    #[test]
    fn native_only_frozen_musl_json_remains_byte_identical() {
        for original in [
            include_bytes!("../data/musl-x86_64.json").as_slice(),
            include_bytes!("../data/musl-aarch64.json").as_slice(),
        ] {
            let db = crate::SignatureDb::from_json(std::str::from_utf8(original).unwrap()).unwrap();
            assert_eq!(db.pat_records(), 0);
            assert_eq!(db.to_json().as_bytes(), original);
            assert_eq!(crate::compressed::decode_gzip(&db.to_gzip().unwrap()).unwrap(), original);
        }
    }

    #[test]
    fn native_collision_tombstones_cannot_be_filled_by_a_unique_pat() {
        let hash = function_hash_in(&target(), &MaskContext::default(), LEAF, 0x401000).unwrap();
        let exact = crate::function_hash(&target(), LEAF, 0x401000).unwrap();
        for masked_collision in [false, true] {
            let mut native = native_db("native_beta");
            if masked_collision {
                native.add(hash, None, None, "native_gamma");
            } else {
                native.entries.clear();
                native.ambiguous_exact.insert(crate::hex(&exact));
            }
            native.combine(&signature_db(":0000 pat_alpha")).unwrap();
            assert_eq!(identify_signature(&native, LEAF), None);
            let loaded = crate::SignatureDb::from_gzip(&native.to_gzip().unwrap()).unwrap();
            assert_eq!(identify_signature(&loaded, LEAF), None);
        }
        // Separate database priority remains independent of an ambiguity in another database.
        let user = signature_db(":0000 user_alpha");
        let mut ambiguous = native_db("native_beta");
        ambiguous.add(hash, None, None, "native_gamma");
        assert_eq!(
            crate::identify_program(&[&user, &ambiguous], &target(), &MaskContext::default(), &[(0x401000, LEAF)])
                [&0x401000],
            "user_alpha",
        );
    }

    fn call_body() -> Vec<u8> {
        // Owned frame-bearing caller; the rel32 call at +13 actually targets 0x402012.
        vec![0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x89, 0xf8, 0x83, 0xc0, 7, 0xe8, 0, 0x10, 0, 0, 0xc9, 0xc3]
    }

    fn body_pat(body: &[u8], name: &str) -> crate::SignatureDb {
        assert!(body.len() <= PREFIX_BYTES);
        let text = format!(
            "{}{} 00 0000 {:04X} :0000 {name}\n---",
            crate::hex(body),
            "..".repeat(PREFIX_BYTES - body.len()),
            body.len()
        );
        crate::SignatureDb::from_pat(Arch::X86_64, text.as_bytes()).unwrap()
    }

    fn call_key(body: &[u8], name: &str) -> crate::FunctionHash {
        crate::fingerprint_scheme(crate::CURRENT_SCHEME, &target(), &MaskContext::default(), body, 0x401000)
            .unwrap()
            .callee_key(0x401000..0x401000 + body.len() as u64, |at| (at == 0x402012).then_some(name))
            .unwrap()
    }

    #[test]
    fn pat_does_not_revive_native_ambiguity_but_actual_native_callee_fallback_still_works() {
        let body = call_body();
        let hash = function_hash_in(&target(), &MaskContext::default(), &body, 0x401000).unwrap();
        let exact = crate::function_hash(&target(), &body, 0x401000).unwrap();
        let key = call_key(&body, "actual_callee");
        let mut db = crate::SignatureDb::empty(Arch::X86_64, crate::CURRENT_SCHEME);
        db.add(hash, Some(exact), Some(key), "owned_caller");
        db.add(hash, Some(exact), Some(call_key(&body, "different_callee")), "other_caller");
        db.combine(&body_pat(&body, "owned_caller")).unwrap();
        let image = MaskContext::default();
        assert_eq!(db.identify_in(&target(), &image, &body, 0x401000), None);
        assert_eq!(
            db.identify_with_callees(&target(), &image, &body, 0x401000, |at| (at == 0x402012)
                .then_some("actual_callee")),
            Some("owned_caller")
        );
        assert_eq!(
            db.identify_with_callees(&target(), &image, &body, 0x401000, |at| (at == 0x402012)
                .then_some("unrecognized_callee")),
            None
        );

        let mut ambiguous = crate::SignatureDb::empty(Arch::X86_64, crate::CURRENT_SCHEME);
        ambiguous.ambiguous_calls.insert(crate::hex(&key));
        ambiguous.combine(&body_pat(&body, "owned_caller")).unwrap();
        assert_eq!(
            ambiguous.identify_with_callees(&target(), &image, &body, 0x401000, |at| (at == 0x402012)
                .then_some("actual_callee")),
            None
        );
        let loaded = crate::SignatureDb::from_gzip(&db.to_gzip().unwrap()).unwrap();
        assert_eq!(
            loaded.identify_with_callees(&target(), &image, &body, 0x401000, |at| (at == 0x402012)
                .then_some("actual_callee")),
            Some("owned_caller")
        );
        assert_eq!(
            loaded.identify_with_callees(&target(), &image, &body, 0x401000, |at| (at == 0x402012)
                .then_some("unrecognized_callee")),
            None
        );
    }

    #[test]
    fn native_exact_fallback_can_disambiguate_a_masked_collision_before_pat_agreement() {
        let image = MaskContext::new(std::iter::once(0x400000..0x500000));
        // Owned absolute load plus arithmetic; only the image address differs between two bodies.
        let first = [0x48, 0x8b, 4, 0x25, 0, 0x10, 0x40, 0, 5, 0x34, 0x12, 0, 0, 0x83, 0xf0, 0x22, 0xc3];
        let mut second = first;
        second[5] = 0x20;
        let hash = function_hash_in(&target(), &image, &first, 0x401000).unwrap();
        assert_eq!(function_hash_in(&target(), &image, &second, 0x401000), Some(hash));
        let first_exact = crate::function_hash(&target(), &first, 0x401000).unwrap();
        let second_exact = crate::function_hash(&target(), &second, 0x401000).unwrap();
        assert_ne!(first_exact, second_exact);
        let mut db = crate::SignatureDb::empty(Arch::X86_64, crate::CURRENT_SCHEME);
        db.add(hash, Some(first_exact), None, "owned_first");
        db.add(hash, Some(second_exact), None, "owned_second");
        db.combine(&body_pat(&first, "owned_first")).unwrap();
        assert_eq!(db.identify_in(&target(), &image, &first, 0x401000), Some("owned_first"));
        db.exact.remove(&crate::hex(&first_exact));
        assert_eq!(db.identify_in(&target(), &image, &first, 0x401000), None);
    }

    #[test]
    fn retaining_pat_alpha_cannot_erase_native_beta_negative_evidence() {
        let mut db = native_db("native_beta");
        db.combine(&signature_db(":0000 pat_alpha")).unwrap();
        assert_eq!(identify_signature(&db, LEAF), None);
        db.retain_names(&BTreeSet::from(["pat_alpha".to_owned()]));
        assert!(!db.ambiguous.is_empty());
        assert_eq!(identify_signature(&db, LEAF), None);
        for mut loaded in [
            crate::SignatureDb::from_json(&db.to_json()).unwrap(),
            crate::SignatureDb::from_gzip(&db.to_gzip().unwrap()).unwrap(),
        ] {
            assert_eq!(identify_signature(&loaded, LEAF), None);
            loaded.combine(&signature_db(":0000 pat_alpha")).unwrap();
            assert_eq!(identify_signature(&loaded, LEAF), None);
        }
        // An unrelated removed native key must not globally disable a valid PAT answer.
        let mut unrelated_body = LEAF.to_vec();
        unrelated_body[5] += 1;
        let mut unrelated = crate::SignatureDb::empty(Arch::X86_64, crate::CURRENT_SCHEME);
        unrelated.add(
            function_hash_in(&target(), &MaskContext::default(), &unrelated_body, 0x401000).unwrap(),
            None,
            None,
            "unrelated_native",
        );
        unrelated.combine(&signature_db(":0000 pat_alpha")).unwrap();
        unrelated.retain_names(&BTreeSet::from(["pat_alpha".to_owned()]));
        assert_eq!(identify_signature(&unrelated, LEAF), Some("pat_alpha"));
        let mut native_only = native_db("native_beta");
        native_only.retain_names(&BTreeSet::new());
        assert!(native_only.ambiguous.is_empty());
        assert!(native_only.ambiguous_exact.is_empty());
        assert!(native_only.ambiguous_calls.is_empty());
    }

    #[test]
    fn mixed_retention_persists_latent_exact_and_callee_negatives() {
        let body = call_body();
        let hash = function_hash_in(&target(), &MaskContext::default(), &body, 0x401000).unwrap();
        let exact = crate::function_hash(&target(), &body, 0x401000).unwrap();
        let key = call_key(&body, "actual_callee");
        let mut native = crate::SignatureDb::empty(Arch::X86_64, crate::CURRENT_SCHEME);
        native.add(hash, Some(exact), Some(key), "native_beta");
        let mut mixed = native.clone();
        mixed.combine(&body_pat(&body, "pat_alpha")).unwrap();
        mixed.retain_names(&BTreeSet::from(["pat_alpha".to_owned()]));
        assert!(mixed.ambiguous.contains(&crate::hex(&hash)));
        assert!(mixed.ambiguous_exact.contains(&crate::hex(&exact)));
        assert!(mixed.ambiguous_calls.contains(&crate::hex(&key)));
        assert!(mixed.entry_exact.is_empty());
        assert!(mixed.entry_calls.is_empty());
        let mut loaded = crate::SignatureDb::from_gzip(&mixed.to_gzip().unwrap()).unwrap();
        loaded.combine(&native).unwrap();
        assert_eq!(
            loaded.identify_with_callees(&target(), &MaskContext::default(), &body, 0x401000, |at| (at == 0x402012)
                .then_some("actual_callee")),
            None
        );
        assert!(!loaded.exact.contains_key(&crate::hex(&exact)));
        assert!(!loaded.calls.contains_key(&crate::hex(&key)));
    }

    #[test]
    fn direct_json_rejects_whole_input_and_literal_or_escaped_chunks_before_deserialization() {
        let oversized = " ".repeat(crate::MAX_SIGNATURE_DB_BYTES + 1);
        let err = crate::SignatureDb::from_json(&oversized).unwrap_err();
        assert!(err.to_string().contains("direct JSON bytes"));
        for chunk in [
            "x".repeat(MAX_PAT_FIELDS + 1),
            "\\u0061".repeat(MAX_PAT_FIELDS + 1),
            "\\u00E9".repeat(MAX_PAT_FIELDS / 2 + 1),
            "\\uD83D\\uDE00".repeat(MAX_PAT_FIELDS / 4 + 1),
        ] {
            let json = format!(
                concat!(
                    r#"{{"arch":"x86_64","scheme":2,"entries":{{}},"pat":{{"#,
                    r#""version":1,"arch":"x86_64","text":["{}"],"withheld":[]}}}}"#,
                ),
                chunk,
            );
            let err = crate::SignatureDb::from_json(&json).unwrap_err();
            assert!(err.to_string().contains("JSON string bytes"));
            let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            std::io::Write::write_all(&mut gzip, json.as_bytes()).unwrap();
            assert!(matches!(
                crate::SignatureDb::from_gzip(&gzip.finish().unwrap()),
                Err(crate::SignatureDbError::LimitExceeded("JSON string bytes"))
            ));
        }
    }

    #[test]
    fn direct_json_accepts_bounded_escaped_unicode_pat_names() {
        let name = "é".repeat(500);
        let db = signature_db(&format!(":0000 {name}"));
        let escaped = db.to_json().replace('é', "\\u00E9");
        let loaded = crate::SignatureDb::from_json(&escaped).unwrap();
        assert_eq!(identify_signature(&loaded, LEAF), Some(name.as_str()));
        assert_eq!(loaded.to_json(), db.to_json());
    }
}
