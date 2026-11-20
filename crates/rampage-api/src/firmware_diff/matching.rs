//! Function matching for a version diff: `transfer_annotations`' matching (`build_match`), completed and checked so
//! that only real changes are reported.
//!
//! 1. `build_match` pairs functions by unique evidence (symbols, bytes, masked hashes, strings, the call graph).
//! 2. Leftover functions are paired as multisets by identical bytes, then by identical masked hash: identical stubs
//!    and twins carry no change however they pair, and a count difference is a real addition or removal.
//! 3. Then by identical normalised listings (below), repeated while callees pairing lets callers pair.
//! 4. Then by a string (of at least six characters, found anywhere in the image) that exactly one leftover
//!    function references in each version.
//! 5. A pair `build_match` calls changed (neither bytes nor masked hash equal) is unchanged when its normalised
//!    listings are equal: each instruction with call and branch targets read as the older version's function names,
//!    other addresses as `<addr>`, and PC-relative loads as what they load. A literal pool whose pointer moved, or a
//!    branch to a function that moved, is then no change.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::LazyLock;

use rampage_analysis::discover::XrefKind;
use rampage_signatures::{MaskContext, function_hash_in};
use regex::Regex;

use crate::workflows::is_default_name;
use crate::{DisassemblyLine, Project};

/// Instructions listed per function for normalised comparison.
const MAX_LISTING: usize = 1500;
/// Functions per side compared by normalised listing; past this, pairs stay as `build_match` judged them.
const MAX_NORMALISED: usize = 4000;
/// Rounds of normalised pairing of leftovers.
const NORMALISED_ROUNDS: usize = 4;
/// Strings shorter than this do not anchor a pair.
const MIN_ANCHOR: usize = 6;
/// A listing stops at a string of at least this many characters.
const MIN_STOP: usize = 8;

pub(crate) static HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"0x[0-9a-fA-F]+").expect("hex pattern"));

/// One matched pair.
#[derive(Debug, Clone)]
pub(crate) struct Pair {
    pub(crate) old: u64,
    pub(crate) new: u64,
    pub(crate) method: &'static str,
    pub(crate) confidence: f64,
    pub(crate) changed: bool,
    /// `build_match` saw a change that normalisation explained away.
    pub(crate) normalised: bool,
}

pub(crate) struct Matched {
    pub(crate) pairs: Vec<Pair>,
    pub(crate) removed: Vec<u64>,
    pub(crate) added: Vec<u64>,
    pub(crate) sizes_old: HashMap<u64, u64>,
    pub(crate) sizes_new: HashMap<u64, u64>,
    pub(crate) notes: Vec<String>,
}

impl Matched {
    pub(crate) fn old_to_new(&self) -> HashMap<u64, u64> {
        self.pairs.iter().map(|pair| (pair.old, pair.new)).collect()
    }

    pub(crate) fn changed_old(&self) -> BTreeSet<u64> {
        self.pairs.iter().filter(|pair| pair.changed).map(|pair| pair.old).collect()
    }
}

fn sizes(project: &Project) -> Result<HashMap<u64, u64>, String> {
    let analysis = project.analysis().map_err(|error| error.to_string())?;
    Ok(analysis
        .program
        .functions
        .iter()
        .map(|function| (function.address, function.end().saturating_sub(function.address)))
        .collect())
}

/// Every string of at least `minimum` characters by address: in data anywhere, and in code when NUL-terminated
/// (firmware keeps constants beside its code, and discovery may have run over them).
pub(crate) fn strings(project: &Project, minimum: usize) -> BTreeMap<u64, String> {
    let binary = &project.binary;
    let mut found = BTreeMap::new();
    for segment in &binary.segments {
        let Some(bytes) = binary.read_to_segment_end(segment.address) else { continue };
        for string in rampage_analysis::strings::scan_bytes(bytes, segment.address, minimum) {
            if string.encoding != rampage_analysis::strings::Encoding::Ascii && binary.is_code(string.address) {
                continue;
            }
            let end = (string.address - segment.address) as usize + string.text.len();
            let terminated = bytes[end.min(bytes.len())..]
                .iter()
                .take(3)
                .position(|&byte| byte == 0)
                .is_some_and(|at| bytes[end..end + at].iter().all(|&byte| byte == b'\r' || byte == b'\n'));
            if binary.is_code(string.address) && !terminated {
                continue;
            }
            found.insert(string.address, string.text);
        }
    }
    found
}

/// One version's code as the comparison reads it: its function sizes and blocks, and the strings that end a listing.
pub(crate) struct Code<'a> {
    pub(crate) project: &'a Project,
    pub(crate) sizes: &'a HashMap<u64, u64>,
    /// Each function's basic blocks in address order.
    blocks: HashMap<u64, Vec<(u64, u64)>>,
    /// Strings of at least [`MIN_STOP`] characters: a listing stops at one (discovery may run into constants).
    pub(crate) strings: BTreeMap<u64, String>,
}

impl<'a> Code<'a> {
    pub(crate) fn new(project: &'a Project, sizes: &'a HashMap<u64, u64>) -> Self {
        let blocks = project
            .analysis()
            .map(|analysis| {
                analysis
                    .program
                    .functions
                    .iter()
                    .map(|function| {
                        let mut blocks: Vec<(u64, u64)> =
                            function.blocks.iter().map(|block| (block.start, block.end)).collect();
                        blocks.sort_unstable();
                        (function.address, blocks)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { project, sizes, blocks, strings: strings(project, MIN_STOP) }
    }

    /// The instructions of the function at `address`, block by block in address order (so padding and literals
    /// between blocks are skipped), stopping at a string and at [`MAX_LISTING`] instructions.
    pub(crate) fn listing(&self, address: u64) -> Result<Vec<DisassemblyLine>, String> {
        let end = address + self.sizes.get(&address).copied().unwrap_or(0);
        let ranges = match self.blocks.get(&address) {
            Some(blocks) if !blocks.is_empty() => blocks.clone(),
            _ => vec![(address, end)],
        };
        let mut lines = Vec::new();
        for (start, stop) in ranges {
            if lines.len() >= MAX_LISTING {
                break;
            }
            let count = usize::try_from((stop - start) / 2 + 1).unwrap_or(MAX_LISTING).min(MAX_LISTING - lines.len());
            let block =
                self.project.disassemble(Some(&format!("{start:#x}")), count).map_err(|error| error.to_string())?;
            let before = lines.len();
            lines.extend(block.into_iter().take_while(|line| {
                line.address < stop && (line.address == address || !self.strings.contains_key(&line.address))
            }));
            if lines.len() == before && start != address {
                continue;
            }
        }
        Ok(lines)
    }

    /// `lines` normalised (see [`normalise`]), with `movw`/`movt` pairs that form an address read as that address.
    pub(crate) fn normalised(&self, lines: &[DisassemblyLine], label: &dyn Fn(u64) -> Option<String>) -> Vec<String> {
        let mut texts: Vec<String> = lines.iter().map(|line| normalise(line, label, &self.project.binary)).collect();
        for (index, line) in lines.iter().enumerate() {
            let Some((register, low)) = wide_move(&line.text, "movw") else { continue };
            // The movt that completes it, before anything else writes the register.
            let mut pair = None;
            for (other, line) in lines.iter().enumerate().skip(index + 1).take(6) {
                if let Some((name, high)) = wide_move(&line.text, "movt")
                    && name == register
                {
                    pair = Some((other, high));
                    break;
                }
                let first = line.text.split_once(' ').and_then(|(_, operands)| operands.split(',').next());
                if first.is_some_and(|operand| operand.trim() == register) {
                    break;
                }
            }
            let Some((other, high)) = pair else { continue };
            let value = (high << 16) | low;
            if label(value).is_none() && self.project.binary.read(value, 1).is_none() {
                continue;
            }
            let mut what = label(value).unwrap_or_else(|| "<addr>".to_owned());
            if let Some(text) = self.strings.get(&value).or_else(|| strings_at(self.project, value)) {
                what = format!("{what} {text:?}");
            }
            texts[index] = format!("movw {register}, #lo({what})");
            texts[other] = format!("movt {register}, #hi({what})");
        }
        texts
    }
}

/// The string of at least four characters at `address`, from the project's own scan.
fn strings_at(project: &Project, address: u64) -> Option<&String> {
    project.scanned_strings().iter().find(|found| found.address == address).map(|found| &found.text)
}

/// The register and 16-bit immediate of a `movw` or `movt` (`mnemonic`) instruction's text.
fn wide_move(text: &str, mnemonic: &str) -> Option<(String, u64)> {
    let (head, operands) = text.split_once(' ')?;
    if !head.starts_with(mnemonic) {
        return None;
    }
    let (register, immediate) = operands.split_once(',')?;
    let immediate = immediate.trim().strip_prefix('#')?;
    let value = match immediate.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None => immediate.parse().ok()?,
    };
    Some((register.trim().to_owned(), value & 0xffff))
}

/// Listings of functions, read once, and their normalised text under the current pairing.
struct Listings<'a> {
    old: Code<'a>,
    new: Code<'a>,
    lines_old: HashMap<u64, Vec<DisassemblyLine>>,
    lines_new: HashMap<u64, Vec<DisassemblyLine>>,
    budget: usize,
}

impl Listings<'_> {
    fn text(&mut self, old: bool, address: u64, labels: &Labels) -> Option<Vec<String>> {
        let (code, cache) = if old { (&self.old, &mut self.lines_old) } else { (&self.new, &mut self.lines_new) };
        if !cache.contains_key(&address) {
            if self.budget == 0 {
                return None;
            }
            self.budget -= 1;
            cache.insert(address, code.listing(address).unwrap_or_default());
        }
        let lines = cache.get(&address)?;
        if lines.is_empty() {
            return None;
        }
        Some(code.normalised(lines, &|target| labels.label(old, target)))
    }
}

/// Function labels under a pairing: the older version's name for every paired function, so a call to a moved
/// function reads the same in both; `new:` and the newer name for a function only there.
pub(crate) struct Labels {
    names_old: HashMap<u64, String>,
    names_new: HashMap<u64, String>,
    new_to_old: HashMap<u64, u64>,
}

impl Labels {
    pub(crate) fn new(
        old: &Project,
        new: &Project,
        sizes_old: &HashMap<u64, u64>,
        sizes_new: &HashMap<u64, u64>,
    ) -> Self {
        Self {
            names_old: sizes_old.keys().map(|&address| (address, old.function_name(address))).collect(),
            names_new: sizes_new.keys().map(|&address| (address, new.function_name(address))).collect(),
            new_to_old: HashMap::new(),
        }
    }

    pub(crate) fn pair(&mut self, old: u64, new: u64) {
        self.new_to_old.insert(new, old);
    }

    pub(crate) fn label(&self, old: bool, address: u64) -> Option<String> {
        if old {
            return self.names_old.get(&address).cloned();
        }
        if let Some(old_address) = self.new_to_old.get(&address) {
            return self.names_old.get(old_address).cloned();
        }
        self.names_new.get(&address).map(|name| format!("new:{name}"))
    }
}

/// An instruction's text with addresses replaced: function starts by their label, other mapped addresses (and the
/// memory operand of a PC-relative reference) by `<addr>`; what a reference loads (a string, a name) is appended.
pub(crate) fn normalise(
    line: &DisassemblyLine,
    label: &dyn Fn(u64) -> Option<String>,
    binary: &rampage_loaders::Binary,
) -> String {
    // Narrow and wide encodings of one instruction (Thumb `.n`/`.w`, Xtensa `.n`) differ only by alignment.
    let mut text = match line.text.split_once(' ') {
        Some((mnemonic, operands)) => {
            let mnemonic = mnemonic.strip_suffix(".n").or_else(|| mnemonic.strip_suffix(".w")).unwrap_or(mnemonic);
            format!("{mnemonic} {operands}")
        }
        None => line.text.strip_suffix(".n").or_else(|| line.text.strip_suffix(".w")).unwrap_or(&line.text).to_owned(),
    };
    if line.data_ref.is_some() {
        if let (Some(open), Some(close)) = (text.find('['), text.rfind(']'))
            && open < close
        {
            text.replace_range(open..=close, "[<ref>]");
        } else {
            // An address formed from a PC or page base plus an offset (adr, add after adrp).
            text = IMMEDIATE.replace_all(&text, "#<ref>").into_owned();
        }
    }
    let replaced = HEX.replace_all(&text, |found: &regex::Captures| {
        let token = &found[0];
        let Ok(value) = u64::from_str_radix(&token[2..], 16) else { return token.to_owned() };
        if let Some(name) = label(value) {
            return name;
        }
        if value >= 0x100 && (binary.read(value, 1).is_some() || Some(value) == line.data_ref) {
            return "<addr>".to_owned();
        }
        token.to_owned()
    });
    let mut text = replaced.into_owned();
    if let Some(comment) = &line.comment
        && line.data_ref.is_some()
    {
        let comment = HEX.replace_all(comment, |found: &regex::Captures| {
            let token = &found[0];
            u64::from_str_radix(&token[2..], 16).ok().and_then(label).unwrap_or_else(|| "<addr>".to_owned())
        });
        // Default names carry the address; the older version's label stands for both.
        let comment = DEFAULT_NAME.replace_all(&comment, "<fn>");
        text.push_str(" ; ");
        text.push_str(&comment);
    }
    text
}

static IMMEDIATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"#-?(?:0x[0-9a-fA-F]+|\d+)").expect("immediate"));

static DEFAULT_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:sub|loc|data|str|off|unk)_[0-9a-fA-F]+\b").expect("default name pattern"));

/// Matches two versions: see the module documentation.
pub(crate) fn match_pair(old: &Project, new: &Project) -> Result<Matched, String> {
    let matching = crate::build_match::match_builds(old, new).map_err(|error| error.to_string())?;
    let (sizes_old, sizes_new) = (sizes(old)?, sizes(new)?);
    let mut notes = Vec::new();
    if matching.round_limited {
        notes.push("matching stopped at its round limit; some functions may be unmatched".to_owned());
    }
    let mut pairs: Vec<Pair> = matching
        .matches
        .iter()
        .map(|m| Pair {
            old: m.old,
            new: m.new,
            method: m.method.name(),
            confidence: m.method.confidence(),
            changed: m.changed,
            normalised: false,
        })
        .collect();
    let mut removed: BTreeSet<u64> = matching.removed.iter().copied().collect();
    let mut added: BTreeSet<u64> = matching.added.iter().copied().collect();
    let mut labels = Labels::new(old, new, &sizes_old, &sizes_new);
    for pair in &pairs {
        labels.pair(pair.old, pair.new);
    }

    // Leftovers with identical bytes, then identical masked hashes, as multisets.
    let body = |project: &Project, sizes: &HashMap<u64, u64>, address: u64| -> Option<Vec<u8>> {
        project.binary.read(address, *sizes.get(&address)?).filter(|bytes| !bytes.is_empty()).map(<[u8]>::to_vec)
    };
    let exact = |project: &Project, sizes: &HashMap<u64, u64>, address: u64| {
        body(project, sizes, address).map(|bytes| rampage_arch::hex::bytes(&bytes))
    };
    let masked = |project: &Project, sizes: &HashMap<u64, u64>, address: u64| {
        let image = MaskContext::from_binary(&project.binary);
        let bytes = body(project, sizes, address)?;
        function_hash_in(&project.binary.target(), &image, &bytes, address).map(|hash| format!("{hash:?}"))
    };
    type Key<'k> = &'k dyn Fn(&Project, &HashMap<u64, u64>, u64) -> Option<String>;
    for (method, key) in [("identical_body", &exact as Key), ("identical_masked_body", &masked as Key)] {
        let group = |project: &Project, sizes: &HashMap<u64, u64>, addresses: &BTreeSet<u64>| {
            let mut groups: BTreeMap<String, Vec<u64>> = BTreeMap::new();
            for &address in addresses {
                if let Some(key) = key(project, sizes, address) {
                    groups.entry(key).or_default().push(address);
                }
            }
            groups
        };
        let (old_groups, new_groups) = (group(old, &sizes_old, &removed), group(new, &sizes_new, &added));
        for (key, olds) in &old_groups {
            let Some(news) = new_groups.get(key) else { continue };
            for (&a, &b) in olds.iter().zip(news) {
                removed.remove(&a);
                added.remove(&b);
                labels.pair(a, b);
                pairs.push(Pair { old: a, new: b, method, confidence: 1.0, changed: false, normalised: false });
            }
        }
    }

    let mut listings = Listings {
        old: Code::new(old, &sizes_old),
        new: Code::new(new, &sizes_new),
        lines_old: HashMap::new(),
        lines_new: HashMap::new(),
        budget: MAX_NORMALISED * 2,
    };
    // Leftovers with identical normalised listings, until a round pairs nothing more.
    for _ in 0..NORMALISED_ROUNDS {
        let mut groups_old: BTreeMap<Vec<String>, Vec<u64>> = BTreeMap::new();
        for &address in &removed {
            if let Some(text) = listings.text(true, address, &labels) {
                groups_old.entry(text).or_default().push(address);
            }
        }
        let mut groups_new: BTreeMap<Vec<String>, Vec<u64>> = BTreeMap::new();
        for &address in &added {
            if let Some(text) = listings.text(false, address, &labels) {
                groups_new.entry(text).or_default().push(address);
            }
        }
        let mut paired = 0;
        for (text, olds) in &groups_old {
            let Some(news) = groups_new.get(text) else { continue };
            for (&a, &b) in olds.iter().zip(news) {
                removed.remove(&a);
                added.remove(&b);
                labels.pair(a, b);
                pairs.push(Pair {
                    old: a,
                    new: b,
                    method: "identical_normalised_body",
                    confidence: 0.9,
                    changed: false,
                    normalised: false,
                });
                paired += 1;
            }
        }
        if paired == 0 {
            break;
        }
    }

    // Leftovers that alone reference a string in each version.
    let anchors = |project: &Project, leftovers: &BTreeSet<u64>| -> BTreeMap<String, BTreeSet<u64>> {
        let Ok(analysis) = project.analysis() else { return BTreeMap::new() };
        let texts = strings(project, MIN_ANCHOR);
        let mut by_text: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
        for xref in analysis.program.xrefs.iter().filter(|xref| xref.kind == XrefKind::Data) {
            let (Some(text), Some(function)) = (texts.get(&xref.to), analysis.function_containing(xref.from)) else {
                continue;
            };
            by_text.entry(text.clone()).or_default().insert(function);
        }
        by_text.retain(|_, functions| functions.len() == 1 && functions.iter().all(|f| leftovers.contains(f)));
        by_text
    };
    let (old_anchors, new_anchors) = (anchors(old, &removed), anchors(new, &added));
    let mut proposals: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    let mut reverse: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for (text, olds) in &old_anchors {
        let Some(news) = new_anchors.get(text) else { continue };
        let (a, b) = (*olds.first().expect("one"), *news.first().expect("one"));
        proposals.entry(a).or_default().insert(b);
        reverse.entry(b).or_default().insert(a);
    }
    for (a, news) in proposals {
        let b = *news.first().expect("one");
        if news.len() != 1 || reverse.get(&b).is_none_or(|olds| olds.len() != 1) {
            continue;
        }
        removed.remove(&a);
        added.remove(&b);
        labels.pair(a, b);
        pairs.push(Pair { old: a, new: b, method: "unique_string", confidence: 0.8, changed: true, normalised: false });
    }

    // Changes `build_match` saw that normalisation explains away.
    let mut unchecked = 0;
    for pair in pairs.iter_mut().filter(|pair| pair.changed) {
        match (listings.text(true, pair.old, &labels), listings.text(false, pair.new, &labels)) {
            (Some(a), Some(b)) if a == b => {
                pair.changed = false;
                pair.normalised = true;
            }
            (Some(_), Some(_)) => {}
            _ => unchecked += 1,
        }
    }
    if unchecked > 0 {
        notes.push(format!(
            "{unchecked} changed pairs were not checked against address normalisation (listing budget); they may \
             differ only in addresses"
        ));
    }
    let ambiguous_left = matching.ambiguities.iter().any(|ambiguity| {
        ambiguity.old.iter().any(|address| removed.contains(address))
            || ambiguity.new.iter().any(|address| added.contains(address))
    });
    if ambiguous_left || matching.ambiguity_count > matching.ambiguities.len() {
        notes.push(
            "some functions had ambiguous evidence and no identical counterpart; they are listed as added and removed"
                .to_owned(),
        );
    }
    pairs.sort_by_key(|pair| pair.old);
    Ok(Matched {
        pairs,
        removed: removed.into_iter().collect(),
        added: added.into_iter().collect(),
        sizes_old,
        sizes_new,
        notes,
    })
}

/// A function's name for a report: the newer version's symbol when it has one, else the older one's.
pub(crate) fn pair_name(old: &Project, new: &Project, a: u64, b: u64) -> String {
    let name = new.function_name(b);
    if !is_default_name(&name, b) {
        return name;
    }
    old.function_name(a)
}
