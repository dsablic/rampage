//! VS_VERSIONINFO: the fixed file information and the StringFileInfo/VarFileInfo blocks, read as a tree of
//! length-prefixed nodes with every length clamped to its parent and node, string and byte budgets.

use serde::Serialize;

use super::utf16_until_nul;
use crate::warnings::CappedWarnings;

/// Bytes of a version resource that are parsed; the rest is ignored and reported as truncation.
pub const MAX_VERSION_BYTES: usize = 64 * 1024;
/// Nodes visited.
pub const MAX_VERSION_NODES: usize = 1024;
/// Key/value strings retained across all string tables.
pub const MAX_VERSION_STRINGS: usize = 256;
const MAX_KEY_UNITS: usize = 64;
const MAX_VALUE_UNITS: usize = 1024;
const MAX_TRANSLATIONS: usize = 64;
const FIXED_SIGNATURE: u32 = 0xfeef_04bd;
const WARNINGS: CappedWarnings = CappedWarnings::new(32, "version resource");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionInfo {
    pub fixed: Option<FixedFileInfo>,
    pub string_tables: Vec<VersionStringTable>,
    /// VarFileInfo `Translation` pairs: the languages and code pages the file supports.
    pub translations: Vec<Translation>,
    /// Whether a byte, node or string budget cut the decoding short.
    pub truncated: bool,
    pub warnings: Vec<String>,
}

/// VS_FIXEDFILEINFO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixedFileInfo {
    /// `major.minor.build.revision`.
    pub file_version: String,
    pub product_version: String,
    pub flags_mask: u32,
    pub flags: u32,
    /// VS_FF_* names of the flags that the mask declares valid.
    pub flag_names: Vec<&'static str>,
    pub os: u32,
    pub os_name: Option<&'static str>,
    pub file_type: u32,
    pub file_type_name: Option<&'static str>,
    pub file_subtype: u32,
    pub file_date: u64,
}

/// One StringFileInfo table: the strings for one language and code page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionStringTable {
    /// The table key as written, e.g. `040904B0`.
    pub key: String,
    /// The LANGID and code page the key encodes, when it is eight hex digits.
    pub language: Option<u16>,
    pub code_page: Option<u16>,
    pub strings: Vec<VersionString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionString {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Translation {
    pub language: u16,
    pub code_page: u16,
}

struct Node<'a> {
    key: String,
    /// 1 for text, 0 for binary.
    value_type: u16,
    /// The value: its declared length (characters for text, bytes for binary) clamped to the node.
    value: &'a [u8],
    /// Everything from the value to the node's end, for text values whose declared length is unreliable.
    text: &'a [u8],
    children: &'a [u8],
}

struct Reader {
    nodes: usize,
    strings: usize,
    report: VersionInfo,
}

fn align4(value: usize) -> usize {
    value.saturating_add(3) & !3
}

pub(super) fn parse(bytes: &[u8]) -> VersionInfo {
    let mut reader = Reader {
        nodes: 0,
        strings: 0,
        report: VersionInfo {
            fixed: None,
            string_tables: Vec::new(),
            translations: Vec::new(),
            truncated: bytes.len() > MAX_VERSION_BYTES,
            warnings: Vec::new(),
        },
    };
    let bytes = &bytes[..bytes.len().min(MAX_VERSION_BYTES)];
    let Some(root) = reader.nodes(bytes).next() else {
        reader.warn("the version resource has no readable root node".to_owned());
        return reader.report;
    };
    if root.key != "VS_VERSION_INFO" {
        reader.warn(format!("the root node is keyed `{}`, not VS_VERSION_INFO", root.key));
    }
    if !root.value.is_empty() {
        reader.report.fixed = fixed(root.value);
        if reader.report.fixed.is_none() {
            reader.warn("VS_FIXEDFILEINFO is short or lacks its signature".to_owned());
        }
    }
    let blocks: Vec<Node> = reader.nodes(root.children).collect();
    for block in blocks {
        match block.key.as_str() {
            "StringFileInfo" => reader.string_file_info(block.children),
            "VarFileInfo" => reader.var_file_info(block.children),
            other => reader.warn(format!("unknown version block `{other}`")),
        }
    }
    reader.report
}

impl Reader {
    fn warn(&mut self, warning: String) {
        WARNINGS.push(&mut self.report.warnings, warning);
    }

    /// The sibling nodes packed in `bytes`, within the node budget.
    fn nodes<'r, 'a>(&'r mut self, mut bytes: &'a [u8]) -> impl Iterator<Item = Node<'a>> + 'r
    where
        'a: 'r,
    {
        std::iter::from_fn(move || {
            if bytes.len() < 6 {
                return None;
            }
            if self.nodes >= MAX_VERSION_NODES {
                self.report.truncated = true;
                return None;
            }
            self.nodes += 1;
            let declared = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            if declared < 6 {
                self.warn(format!("a version node declares {declared} bytes, fewer than its header"));
                return None;
            }
            if declared > bytes.len() {
                self.warn(format!("a version node declares {declared} bytes but {} remain", bytes.len()));
            }
            let node = &bytes[..declared.min(bytes.len())];
            bytes = bytes.get(align4(declared)..).unwrap_or_default();
            let value_length = usize::from(u16::from_le_bytes([node[2], node[3]]));
            let value_type = u16::from_le_bytes([node[4], node[5]]);
            let (key, consumed, _) = utf16_until_nul(&node[6..], MAX_KEY_UNITS);
            let value_start = align4(6 + consumed).min(node.len());
            let value_bytes = if value_type == 1 { value_length.saturating_mul(2) } else { value_length };
            let value_end = value_start.saturating_add(value_bytes).min(node.len());
            let children = &node[align4(value_end).min(node.len())..];
            Some(Node { key, value_type, value: &node[value_start..value_end], text: &node[value_start..], children })
        })
    }

    fn string_file_info(&mut self, bytes: &[u8]) {
        let tables: Vec<Node> = self.nodes(bytes).collect();
        for table in tables {
            let (language, code_page) = match (table.key.len(), u32::from_str_radix(&table.key, 16)) {
                (8, Ok(value)) => (Some((value >> 16) as u16), Some(value as u16)),
                _ => (None, None),
            };
            let mut strings = Vec::new();
            let children: Vec<Node> = self.nodes(table.children).collect();
            for child in children {
                if self.strings >= MAX_VERSION_STRINGS {
                    self.report.truncated = true;
                    break;
                }
                self.strings += 1;
                // Some resource compilers count text value lengths in bytes, so read up to the terminator instead.
                let (value, _, _) = utf16_until_nul(child.text, MAX_VALUE_UNITS);
                if child.value_type != 1 && !child.value.is_empty() {
                    self.warn(format!("version string `{}` is marked binary", child.key));
                }
                strings.push(VersionString { key: child.key, value });
            }
            self.report.string_tables.push(VersionStringTable { key: table.key, language, code_page, strings });
        }
    }

    fn var_file_info(&mut self, bytes: &[u8]) {
        let vars: Vec<Node> = self.nodes(bytes).collect();
        for var in vars.into_iter().filter(|var| var.key == "Translation") {
            for pair in var.value.as_chunks::<4>().0 {
                if self.report.translations.len() >= MAX_TRANSLATIONS {
                    self.report.truncated = true;
                    return;
                }
                self.report.translations.push(Translation {
                    language: u16::from_le_bytes([pair[0], pair[1]]),
                    code_page: u16::from_le_bytes([pair[2], pair[3]]),
                });
            }
        }
    }
}

fn fixed(value: &[u8]) -> Option<FixedFileInfo> {
    let word = |index: usize| value.get(index * 4..index * 4 + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    if word(0)? != FIXED_SIGNATURE || value.len() < 52 {
        return None;
    }
    let version = |high: u32, low: u32| format!("{}.{}.{}.{}", high >> 16, high & 0xffff, low >> 16, low & 0xffff);
    let flags_mask = word(6)?;
    let flags = word(7)?;
    const FLAGS: [(u32, &str); 6] = [
        (0x01, "debug"),
        (0x02, "prerelease"),
        (0x04, "patched"),
        (0x08, "private_build"),
        (0x10, "info_inferred"),
        (0x20, "special_build"),
    ];
    let os = word(8)?;
    let file_type = word(9)?;
    Some(FixedFileInfo {
        file_version: version(word(2)?, word(3)?),
        product_version: version(word(4)?, word(5)?),
        flags_mask,
        flags,
        flag_names: FLAGS.iter().filter(|(bit, _)| flags & flags_mask & bit != 0).map(|&(_, name)| name).collect(),
        os,
        os_name: match os {
            0x0000_0000 => Some("unknown"),
            0x0000_0004 => Some("windows32"),
            0x0001_0000 => Some("dos"),
            0x0001_0001 => Some("dos_windows16"),
            0x0001_0004 => Some("dos_windows32"),
            0x0004_0000 => Some("nt"),
            0x0004_0004 => Some("nt_windows32"),
            _ => None,
        },
        file_type,
        file_type_name: match file_type {
            0 => Some("unknown"),
            1 => Some("app"),
            2 => Some("dll"),
            3 => Some("driver"),
            4 => Some("font"),
            5 => Some("vxd"),
            7 => Some("static_lib"),
            _ => None,
        },
        file_subtype: word(10)?,
        file_date: (u64::from(word(11)?) << 32) | u64::from(word(12)?),
    })
}
