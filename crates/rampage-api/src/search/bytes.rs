use std::collections::BTreeMap;

use rampage_detect::BytePattern;
use rampage_loaders::{Binary, Format};
use regex::bytes::{Regex, RegexBuilder};

use super::*;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ByteSpan {
    pub address: u64,
    pub image_offset: u64,
    pub size: u64,
}

/// VA-sorted, nonoverlapping spans. Aliased mappings merge only when their backing agrees byte for byte.
pub(crate) fn mapped_spans(binary: &Binary, range: Option<SearchRange>) -> Result<Vec<ByteSpan>, ApiError> {
    if binary.segments.len() > MAX_SEARCH_MAPPINGS {
        return Err(invalid("search mapping metadata exceeds the public mapping limit"));
    }
    let mut spans = Vec::new();
    let mut claims = Vec::new();
    for segment in &binary.segments {
        if segment.file_size > segment.size {
            return Err(invalid("search mapping stores more bytes than its virtual size"));
        }
        segment.address.checked_add(segment.size).ok_or_else(|| invalid("search mapping address overflow"))?;
        let file_end = segment
            .file_offset
            .checked_add(segment.file_size)
            .ok_or_else(|| invalid("search mapping file offset overflow"))?;
        if file_end > binary.image_bytes().len() as u64 {
            return Err(invalid("search mapping extends beyond retained image bytes"));
        }
        let backed_end = segment.address + segment.file_size;
        let virtual_end = segment.address + segment.size;
        for (start, end, backing) in [
            (segment.address, backed_end, Some(i128::from(segment.file_offset) - i128::from(segment.address))),
            (backed_end, virtual_end, None),
        ] {
            let start = start.max(range.map_or(0, |range| range.start));
            let end = end.min(range.map_or(u64::MAX, |range| range.end));
            if start < end {
                claims.push((start, true, backing));
                claims.push((end, false, backing));
            }
        }
        if segment.file_size == 0 {
            continue;
        }
        let start = segment.address.max(range.map_or(0, |range| range.start));
        let end = (segment.address + segment.file_size).min(range.map_or(u64::MAX, |range| range.end));
        if start < end {
            spans.push(ByteSpan {
                address: start,
                image_offset: segment.file_offset + (start - segment.address),
                size: end - start,
            });
        }
    }
    claims.sort_unstable();
    let mut active: BTreeMap<Option<i128>, usize> = BTreeMap::new();
    for events in claims.chunk_by(|left, right| left.0 == right.0) {
        for &(_, entering, backing) in events {
            if entering {
                *active.entry(backing).or_default() += 1;
            } else if let Some(count) = active.get_mut(&backing) {
                *count -= 1;
                if *count == 0 {
                    active.remove(&backing);
                }
            }
        }
        if active.len() > 1 {
            return Err(invalid("search refuses overlapping virtual mappings with ambiguous backing"));
        }
    }
    spans.sort_unstable_by_key(|span| (span.address, span.image_offset, span.size));
    let mut unique: Vec<ByteSpan> = Vec::with_capacity(spans.len());
    for span in spans {
        if let Some(previous) = unique.last_mut() {
            let previous_end = previous.address + previous.size;
            if span.address < previous_end {
                if previous.image_offset + (span.address - previous.address) != span.image_offset {
                    return Err(invalid("search refuses overlapping virtual mappings with ambiguous backing"));
                }
                previous.size = previous.size.max(span.address + span.size - previous.address);
                continue;
            }
            if span.address == previous_end && previous.image_offset + previous.size == span.image_offset {
                previous.size += span.size;
                continue;
            }
        }
        unique.push(span);
    }
    Ok(unique)
}

pub(crate) fn source(binary: &Binary) -> Result<SearchSource, ApiError> {
    let mapped_source_checked = binary
        .validate_available_backing_source()
        .map_err(|error| ApiError::Unavailable(format!("search source validation: {error}")))?;
    let owned_image = binary.backing_path().is_none();
    let selected_image_file_offset = if binary.format == Format::Snapshot {
        None
    } else {
        let image = binary.image_bytes();
        let file = binary.file_bytes();
        let offset = (image.as_ptr() as usize).checked_sub(file.as_ptr() as usize);
        offset
            .filter(|&offset| offset.checked_add(image.len()).is_some_and(|end| end <= file.len()))
            .map(|offset| offset as u64)
    };
    Ok(SearchSource {
        backing_path: binary.backing_path().map(std::path::Path::to_owned),
        mapped_source_checked,
        owned_image,
        selected_image_file_offset,
    })
}

/// One proven contiguous virtual domain, backed by potentially discontiguous retained image pieces.
struct VirtualBytes<'a> {
    pieces: &'a [ByteSpan],
    image: &'a [u8],
}

impl VirtualBytes<'_> {
    fn address(&self) -> u64 {
        self.pieces[0].address
    }

    fn size(&self) -> u64 {
        let last = self.pieces.last().expect("virtual domain has a piece");
        last.address + last.size - self.address()
    }

    fn piece(&self, offset: usize) -> &ByteSpan {
        let address = self.address() + offset as u64;
        &self.pieces[self.pieces.partition_point(|piece| piece.address <= address) - 1]
    }

    fn image_offset(&self, offset: usize) -> u64 {
        let piece = self.piece(offset);
        piece.image_offset + (self.address() + offset as u64 - piece.address)
    }

    fn byte(&self, offset: usize) -> u8 {
        self.image[self.image_offset(offset) as usize]
    }

    fn window<'a>(&'a self, offset: usize, length: usize, scratch: &'a mut Vec<u8>) -> &'a [u8] {
        let piece = self.piece(offset);
        let address = self.address() + offset as u64;
        let start = (piece.image_offset + (address - piece.address)) as usize;
        if length as u64 <= piece.size - (address - piece.address) {
            return &self.image[start..start + length];
        }
        scratch.clear();
        let mut cursor = offset;
        while scratch.len() < length {
            let piece = self.piece(cursor);
            let within = self.address() + cursor as u64 - piece.address;
            let count = (piece.size - within).min((length - scratch.len()) as u64) as usize;
            let start = (piece.image_offset + within) as usize;
            scratch.extend_from_slice(&self.image[start..start + count]);
            cursor += count;
        }
        scratch
    }
}

enum Matcher {
    Bytes(BytePattern),
    Exact { needle: Vec<u8>, alignment: u64 },
    AsciiRegex(Regex),
    UnicodeRegex { regex: regex::Regex, big_endian: bool },
}

impl Matcher {
    fn compile(mode: &SearchMode) -> Result<Self, ApiError> {
        match mode {
            SearchMode::Bytes { pattern } => {
                if pattern.len() > MAX_SEARCH_PATTERN_BYTES * 8 {
                    return Err(invalid("byte-pattern query text exceeds the input size limit"));
                }
                BytePattern::parse(pattern)
                    .map(Self::Bytes)
                    .map_err(|error| ApiError::Invalid(format!("search byte pattern: {error}")))
            }
            SearchMode::Text { pattern, encoding, regex } => {
                if pattern.is_empty() || pattern.len() > MAX_SEARCH_PATTERN_BYTES {
                    return Err(invalid("search text pattern is empty or exceeds 4096 UTF-8 bytes"));
                }
                if *regex {
                    if *encoding != SearchTextEncoding::Ascii {
                        let regex = regex::RegexBuilder::new(pattern)
                            .size_limit(MAX_SEARCH_REGEX_SIZE)
                            .dfa_size_limit(MAX_SEARCH_REGEX_SIZE)
                            .nest_limit(64)
                            .build()
                            .map_err(|error| ApiError::Invalid(format!("search Unicode regex: {error}")))?;
                        if regex.is_match("") {
                            return Err(invalid("zero-length regex matches are unsupported"));
                        }
                        return Ok(Self::UnicodeRegex { regex, big_endian: *encoding == SearchTextEncoding::Utf16Be });
                    }
                    if !pattern.is_ascii() {
                        return Err(invalid("ASCII regex source must contain only ASCII characters"));
                    }
                    let regex = RegexBuilder::new(pattern)
                        .unicode(false)
                        .size_limit(MAX_SEARCH_REGEX_SIZE)
                        .dfa_size_limit(MAX_SEARCH_REGEX_SIZE)
                        .nest_limit(64)
                        .build()
                        .map_err(|error| ApiError::Invalid(format!("search regex: {error}")))?;
                    if regex.is_match(b"") {
                        return Err(invalid("zero-length regex matches are unsupported"));
                    }
                    return Ok(Self::AsciiRegex(regex));
                }
                let needle: Vec<u8> = match encoding {
                    SearchTextEncoding::Ascii => {
                        if !pattern.is_ascii() {
                            return Err(invalid("ASCII exact search requires ASCII query text"));
                        }
                        pattern.as_bytes().to_vec()
                    }
                    SearchTextEncoding::Utf16Le => pattern.encode_utf16().flat_map(u16::to_le_bytes).collect(),
                    SearchTextEncoding::Utf16Be => pattern.encode_utf16().flat_map(u16::to_be_bytes).collect(),
                };
                if needle.len() > MAX_SEARCH_PATTERN_BYTES {
                    return Err(invalid("encoded search pattern exceeds 4096 bytes"));
                }
                Ok(Self::Exact { needle, alignment: if *encoding == SearchTextEncoding::Ascii { 1 } else { 2 } })
            }
            _ => Err(invalid("byte search backend needs bytes or text mode")),
        }
    }

    fn literal_len(&self) -> Option<usize> {
        match self {
            Self::Bytes(pattern) => Some(pattern.len()),
            Self::Exact { needle, .. } => Some(needle.len()),
            Self::AsciiRegex(_) | Self::UnicodeRegex { .. } => None,
        }
    }

    fn matches(&self, data: &[u8]) -> bool {
        match self {
            Self::Bytes(pattern) => pattern.matches_at(data),
            Self::Exact { needle, .. } => data.starts_with(needle),
            Self::AsciiRegex(_) | Self::UnicodeRegex { .. } => false,
        }
    }
}

/// Candidate starts searched per exact-needle chunk, between cancellation checks.
const EXACT_CHUNK: usize = 1 << 20;

struct Scan<'a> {
    query: &'a SearchQuery,
    control: &'a SearchControl<'a>,
    report: SearchReport,
    retained: Vec<SearchHit>,
    /// The first address whose matches were not searched when a budget or cancellation stopped the scan.
    resume_at: Option<u64>,
}

impl Scan<'_> {
    fn charge(&mut self, work: u64) -> bool {
        if self.control.cancelled() {
            self.report.stop_reason = SearchStopReason::Cancelled;
            return false;
        }
        if work > self.query.budget.match_work - self.report.budget.match_work {
            self.report.stop_reason = SearchStopReason::MatchWorkBudget;
            return false;
        }
        self.report.budget.match_work += work;
        true
    }

    fn hit(&mut self, view: &VirtualBytes<'_>, offset: usize, size: usize) -> bool {
        self.report.total += 1;
        if self.report.total > self.query.budget.results {
            self.report.stop_reason = SearchStopReason::ResultCap;
            return false;
        }
        let image_offset = view.image_offset(offset);
        self.retained.push(SearchHit {
            address: view.address() + offset as u64,
            size: size as u64,
            image_offset: Some(image_offset),
            file_offset: self.report.source.selected_image_file_offset.and_then(|base| base.checked_add(image_offset)),
            function: None,
            evidence: match self.query.mode {
                SearchMode::Bytes { .. } => SearchHitEvidence::BytePattern,
                _ => SearchHitEvidence::Text,
            },
            target: None,
            code: None,
            reference_kinds: vec![],
        });
        true
    }

    /// Exact needles: a linear substring search charging one unit of match work per candidate start, so the
    /// default budget covers a whole large image instead of a few MiB of `length`-byte comparisons.
    fn exact(&mut self, view: &VirtualBytes<'_>, size: usize, needle: &[u8], alignment: usize) {
        let length = needle.len();
        if size < length {
            self.report.scanned_bytes += size as u64;
            return;
        }
        let finder = memchr::memmem::Finder::new(needle);
        let starts = size - length + 1;
        let mut scratch = Vec::new();
        let mut next = 0;
        while next < starts {
            if self.control.cancelled() {
                self.report.stop_reason = SearchStopReason::Cancelled;
                break;
            }
            let available = self.query.budget.match_work - self.report.budget.match_work;
            let chunk = (starts - next).min(EXACT_CHUNK).min(usize::try_from(available).unwrap_or(usize::MAX));
            if chunk == 0 {
                self.report.stop_reason = SearchStopReason::MatchWorkBudget;
                break;
            }
            self.report.budget.match_work += chunk as u64;
            let window = view.window(next, chunk + length - 1, &mut scratch);
            let mut from = 0;
            let mut stopped_at = None;
            while let Some(found) = finder.find(&window[from..]) {
                let offset = next + from + found;
                from += found + 1;
                if alignment == 2 && !(view.address() + offset as u64).is_multiple_of(2) {
                    continue;
                }
                if !self.hit(view, offset, length) {
                    stopped_at = Some(offset);
                    break;
                }
            }
            if let Some(offset) = stopped_at {
                // A result-cap stop examined the bytes through the capped match, not the whole chunk.
                self.report.scanned_bytes += (offset + length) as u64;
                return;
            }
            next += chunk;
        }
        self.report.scanned_bytes += if next == starts { size } else { next + length - 1 } as u64;
        if matches!(self.report.stop_reason, SearchStopReason::MatchWorkBudget | SearchStopReason::Cancelled)
            && next < starts
        {
            self.resume_at = Some(view.address() + next as u64);
        }
    }

    fn literals(&mut self, view: &VirtualBytes<'_>, size: usize, matcher: &Matcher, length: usize) {
        if let Matcher::Exact { needle, alignment } = matcher {
            return self.exact(view, size, needle, *alignment as usize);
        }
        if size < length {
            self.report.scanned_bytes += size as u64;
            return;
        }
        let alignment = match matcher {
            Matcher::Exact { alignment, .. } => *alignment as usize,
            _ => 1,
        };
        let first = if alignment == 2 && !view.address().is_multiple_of(2) { 1 } else { 0 };
        let mut consumed = 0;
        let mut scratch = Vec::with_capacity(length);
        for offset in (first..=size - length).step_by(alignment) {
            if !self.charge(length as u64) {
                self.resume_at = Some(view.address() + offset as u64);
                break;
            }
            consumed = offset + length;
            if matcher.matches(view.window(offset, length, &mut scratch)) && !self.hit(view, offset, length) {
                break;
            }
        }
        if self.report.stop_reason == SearchStopReason::Complete {
            consumed = size;
        }
        self.report.scanned_bytes += consumed as u64;
    }

    fn regex(&mut self, view: &VirtualBytes<'_>, size: usize, regex: &Regex) -> Result<(), ApiError> {
        let mut consumed = 0;
        let mut run_start = 0;
        let mut run = Vec::new();
        while run_start < size {
            if !self.charge(1) {
                break;
            }
            if !view.byte(run_start).is_ascii() {
                run_start += 1;
                consumed = run_start;
                continue;
            }
            let mut run_end = run_start;
            run.clear();
            while run_end < size && view.byte(run_end).is_ascii() {
                if !self.charge(1) {
                    self.report.scanned_bytes += consumed as u64;
                    return Ok(());
                }
                if run.len() == MAX_SEARCH_TEXT_RUN_BYTES {
                    self.report.stop_reason = SearchStopReason::TextRunBudget;
                    self.report.scanned_bytes += consumed as u64;
                    return Ok(());
                }
                run.push(view.byte(run_end));
                run_end += 1;
            }
            let mut cursor = 0;
            while cursor <= run.len() {
                if !self.charge((run.len() - cursor) as u64) {
                    self.report.scanned_bytes += consumed as u64;
                    return Ok(());
                }
                let Some(found) = regex.find_at(&run, cursor) else { break };
                if found.is_empty() {
                    return Err(invalid("zero-length regex matches are unsupported"));
                }
                consumed = run_start + found.end();
                if !self.hit(view, run_start + found.start(), found.len()) {
                    self.report.scanned_bytes += consumed as u64;
                    return Ok(());
                }
                cursor = found.end();
            }
            consumed = run_end;
            run_start = run_end;
        }
        if self.report.stop_reason == SearchStopReason::Complete {
            consumed = size;
        }
        self.report.scanned_bytes += consumed as u64;
        Ok(())
    }

    fn unicode_run(
        &mut self,
        view: &VirtualBytes<'_>,
        text: &str,
        offsets: &[(usize, usize)],
        regex: &regex::Regex,
    ) -> Result<bool, ApiError> {
        if text.is_empty() {
            return Ok(true);
        }
        let mut cursor = 0;
        while cursor <= text.len() {
            if !self.charge((text.len() - cursor) as u64) {
                return Ok(false);
            }
            let Some(found) = regex.find_at(text, cursor) else { break };
            if found.is_empty() {
                return Err(invalid("zero-length regex matches are unsupported"));
            }
            let start = offsets
                .binary_search_by_key(&found.start(), |&(decoded, _)| decoded)
                .map_err(|_| invalid("Unicode regex match did not begin at a scalar boundary"))?;
            let end = offsets
                .binary_search_by_key(&found.end(), |&(decoded, _)| decoded)
                .map_err(|_| invalid("Unicode regex match did not end at a scalar boundary"))?;
            let (start, end) = (offsets[start].1, offsets[end].1);
            if !self.hit(view, start, end - start) {
                return Ok(false);
            }
            cursor = found.end();
        }
        Ok(true)
    }

    fn unicode_regex(
        &mut self,
        view: &VirtualBytes<'_>,
        length: usize,
        regex: &regex::Regex,
        big_endian: bool,
    ) -> Result<(), ApiError> {
        let word = |at: usize| {
            let bytes = [view.byte(at), view.byte(at + 1)];
            if big_endian { u16::from_be_bytes(bytes) } else { u16::from_le_bytes(bytes) }
        };
        let mut cursor = usize::from(!view.address().is_multiple_of(2)).min(length);
        self.report.scanned_bytes += cursor as u64;
        let mut run = String::new();
        let mut offsets = vec![(0, cursor)];
        while cursor + 1 < length {
            if !self.charge(2) {
                return Ok(());
            }
            let first = word(cursor);
            let (scalar, size) = if (0xd800..=0xdbff).contains(&first) {
                if cursor + 3 < length && (0xdc00..=0xdfff).contains(&word(cursor + 2)) {
                    if !self.charge(2) {
                        return Ok(());
                    }
                    let scalar = 0x10000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(word(cursor + 2)) - 0xdc00);
                    (char::from_u32(scalar), 4)
                } else {
                    (None, 2)
                }
            } else if (0xdc00..=0xdfff).contains(&first) {
                (None, 2)
            } else {
                (char::from_u32(u32::from(first)), 2)
            };
            let Some(scalar) = scalar else {
                if !self.unicode_run(view, &run, &offsets, regex)? {
                    return Ok(());
                }
                self.report.invalid_utf16_units += 1;
                cursor += size;
                self.report.scanned_bytes += size as u64;
                run.clear();
                offsets.clear();
                offsets.push((0, cursor));
                continue;
            };
            if run.len() + scalar.len_utf8() > MAX_SEARCH_TEXT_RUN_BYTES {
                self.report.stop_reason = SearchStopReason::TextRunBudget;
                return Ok(());
            }
            run.push(scalar);
            cursor += size;
            self.report.scanned_bytes += size as u64;
            offsets.push((run.len(), cursor));
        }
        if !self.unicode_run(view, &run, &offsets, regex)? {
            return Ok(());
        }
        if cursor < length && self.charge(1) {
            self.report.utf16_trailing_bytes += 1;
            self.report.scanned_bytes += 1;
        }
        Ok(())
    }
}

pub(super) fn search(
    project: &Project,
    query: &SearchQuery,
    control: &SearchControl<'_>,
) -> Result<SearchReport, ApiError> {
    let matcher = Matcher::compile(&query.mode)?;
    let source = source(&project.binary)?;
    let spans = mapped_spans(&project.binary, query.range)?;
    let eligible_bytes = spans
        .iter()
        .try_fold(0u64, |total, span| total.checked_add(span.size))
        .ok_or_else(|| invalid("search scope byte count overflow"))?;
    let mut scan = Scan {
        query,
        control,
        report: SearchReport {
            source,
            scope: SearchScope {
                kind: "mapped_file_backed_virtual_addresses",
                requested_range: query.range,
                eligible_bytes,
                mapped_spans: spans.len(),
                excludes_unmapped_overlay_and_zero_fill: true,
                joins_virtual_gaps: false,
            },
            hits: Vec::new(),
            offset: query.offset,
            limit: query.limit,
            total: 0,
            total_is_exact: true,
            scanned_bytes: 0,
            scanned_instructions: 0,
            scanned_references: 0,
            truncated: false,
            cancelled: false,
            stop_reason: SearchStopReason::Complete,
            budget: SearchBudgetEvidence { limits: query.budget, match_work: 0 },
            invalid_utf16_units: 0,
            utf16_trailing_bytes: 0,
            resume_at: None,
            unscanned_ranges: Vec::new(),
            unscanned_range_count: 0,
            unscanned_bytes: 0,
            limitations: [
                "Byte/text results are content matches, not evidence of execution or references.",
                "Only stored mapped bytes are searched; overlay, virtual gaps and zero-fill are excluded.",
                "Context is optional native function discovery; absent context is not a function boundary claim.",
                "Opt-in context discovery is outside byte matching budgets and can initialize native analysis.",
                "UTF-16 exact matches begin at even virtual addresses; no surrogate replacement is performed.",
                "ASCII regex uses maximal ASCII runs, nonoverlapping matches and run-relative anchors.",
                "Regex compilation and DFA cache are bounded; match-work charges are conservative, not CPU timings.",
                "UTF-16 regex uses Unicode scalar runs separated by invalid surrogate units, counted explicitly.",
                "Regex runs are limited to 1 MiB of ASCII bytes or decoded UTF-8; oversized runs stop \
                 without partial-run hits.",
                "Adjacent backed virtual pieces share a search domain even when their file offsets are discontiguous.",
                "Requested range endpoints and actual virtual gaps bound domains; regex anchors may match those ends.",
                "Hit offsets identify the backing of the first matched byte, not a contiguous file extent \
                 for its size.",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        },
        retained: Vec::new(),
        resume_at: None,
    };
    if control.cancelled() {
        scan.report.stop_reason = SearchStopReason::Cancelled;
    }
    let domains: Vec<&[ByteSpan]> = spans.chunk_by(|left, right| left.address + left.size == right.address).collect();
    let mut unscanned_from = None;
    for (index, pieces) in domains.iter().copied().enumerate() {
        let view = VirtualBytes { pieces, image: project.binary.image_bytes() };
        let remaining = query.budget.scan_bytes - scan.report.scanned_bytes;
        if scan.report.stop_reason == SearchStopReason::Complete && control.cancelled() {
            scan.report.stop_reason = SearchStopReason::Cancelled;
        } else if scan.report.stop_reason == SearchStopReason::Complete
            && (remaining == 0
                // Cutting a regex haystack would manufacture an end-of-run anchor at the budget boundary.
                || (matches!(matcher, Matcher::AsciiRegex(_) | Matcher::UnicodeRegex { .. })
                    && remaining < view.size()))
        {
            scan.report.stop_reason = SearchStopReason::ScanByteBudget;
        }
        if scan.report.stop_reason != SearchStopReason::Complete {
            scan.resume_at = Some(view.address());
            unscanned_from = Some(index);
            break;
        }
        let size = view.size().min(remaining) as usize;
        if let Some(length) = matcher.literal_len() {
            scan.literals(&view, size, &matcher, length);
        } else if let Matcher::AsciiRegex(regex) = &matcher {
            scan.regex(&view, size, regex)?;
        } else if let Matcher::UnicodeRegex { regex, big_endian } = &matcher {
            scan.unicode_regex(&view, size, regex, *big_endian)?;
        }
        if scan.report.stop_reason == SearchStopReason::Complete && size as u64 != view.size() {
            scan.report.stop_reason = SearchStopReason::ScanByteBudget;
            if let Some(length) = matcher.literal_len() {
                scan.resume_at = Some(view.address() + size.saturating_sub(length - 1) as u64);
            }
        }
        if scan.report.stop_reason != SearchStopReason::Complete {
            // A domain stopped before it started (regex or no byte budget left) resumes at its start.
            let end = view.address() + view.size();
            let started = scan.resume_at.is_some_and(|at| at >= view.address() && at < end);
            // A result cap is not resumable by range, and a text-run stop would meet the same run again.
            let resumable =
                !matches!(scan.report.stop_reason, SearchStopReason::ResultCap | SearchStopReason::TextRunBudget);
            if !started && resumable {
                scan.resume_at.get_or_insert(view.address());
            }
            unscanned_from = Some(index);
            break;
        }
    }
    if let (Some(index), Some(resume)) = (unscanned_from, scan.resume_at) {
        for pieces in &domains[index..] {
            let last = pieces.last().expect("domain has a piece");
            let (start, end) = (pieces[0].address.max(resume), last.address + last.size);
            if start < end {
                scan.report.unscanned_range_count += 1;
                scan.report.unscanned_bytes += end - start;
                if scan.report.unscanned_ranges.len() < MAX_UNSCANNED_RANGES {
                    scan.report.unscanned_ranges.push(UnscannedRange { start, end });
                }
            }
        }
        scan.report.resume_at = Some(resume);
    }
    scan.report.total_is_exact = scan.report.stop_reason == SearchStopReason::Complete;
    scan.report.truncated = !scan.report.total_is_exact;
    scan.report.cancelled = scan.report.stop_reason == SearchStopReason::Cancelled;
    scan.report.hits = scan.retained.into_iter().skip(query.offset).take(query.limit).collect();
    if query.include_context {
        for hit in &mut scan.report.hits {
            if control.cancelled() {
                scan.report.cancelled = true;
                scan.report.stop_reason = SearchStopReason::Cancelled;
                scan.report.truncated = true;
                scan.report.total_is_exact = false;
                break;
            }
            hit.function = function_context(project, hit.address)?;
        }
    }
    project
        .binary
        .validate_available_backing_source()
        .map_err(|error| ApiError::Unavailable(format!("search source changed: {error}")))?;
    Ok(scan.report)
}
