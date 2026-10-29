//! The PE resource directory: a bounded walk of its type/name/language tree that lists each data leaf, and
//! bounded structural decoding of version information (RT_VERSION) and manifests (RT_MANIFEST). Other resource
//! payloads are located but never interpreted.

use std::collections::HashSet;

use object::LittleEndian as LE;
use object::read::pe::{ImageNtHeaders, PeFile, ResourceDirectory, ResourceDirectoryEntryData, ResourceNameOrId};
use serde::Serialize;

use crate::warnings::CappedWarnings;
use crate::{Binary, Format, LoadError};

mod manifest;
mod version;

pub use manifest::{
    MAX_MANIFEST_DEPENDENCIES, MAX_MANIFEST_SCAN, MAX_MANIFEST_TEXT, Manifest, RequestedExecutionLevel,
};
pub use version::{
    FixedFileInfo, MAX_VERSION_BYTES, MAX_VERSION_NODES, MAX_VERSION_STRINGS, Translation, VersionInfo, VersionString,
    VersionStringTable,
};

/// Directory levels below the root: type, name, language. A table nested deeper is not followed.
pub const MAX_RESOURCE_DEPTH: usize = 3;
/// Directory tables visited, the root included.
pub const MAX_RESOURCE_TABLES: usize = 4096;
/// Directory entries examined across all tables.
pub const MAX_RESOURCE_ENTRIES: usize = 65_536;
/// Data leaves retained.
pub const MAX_RESOURCE_LEAVES: usize = 16_384;
/// UTF-16 code units kept of a string resource name.
pub const MAX_RESOURCE_NAME_UNITS: usize = 256;
const WARNINGS: CappedWarnings = CappedWarnings::new(64, "PE resource");

/// A directory entry's identity: a numeric id or a string name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(untagged)]
pub enum ResourceKey {
    Id(u16),
    Name(String),
}

/// One resource data entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceLeaf {
    /// The type entry: numeric (`RT_*`) or a string name.
    #[serde(rename = "type")]
    pub type_key: ResourceKey,
    /// `RT_VERSION`-style name for a predefined numeric type, `#<id>` for another number, or the string name.
    pub type_name: String,
    /// The name entry; `None` when the data entry sits directly under the type (an irregular tree).
    pub name: Option<ResourceKey>,
    /// The language entry (a LANGID when numeric); `None` when the data entry sits above the language level.
    pub language: Option<ResourceKey>,
    pub data_rva: u32,
    pub size: u32,
    pub code_page: u32,
    /// Offset of the first byte within the PE image, when the RVA lies in a section's file data.
    pub file_offset: Option<u64>,
    /// Whether all `size` bytes are in the image's file data.
    pub in_file: bool,
}

impl ResourceLeaf {
    /// Whether `filter` names this leaf's type: `RT_ICON`, `ICON`, `3` or `#3` for a numeric type (predefined or
    /// not), or a string type's name, ignoring case.
    pub fn matches_type(&self, filter: &str) -> bool {
        let filter = filter.trim();
        match &self.type_key {
            ResourceKey::Id(id) => {
                let number = filter.strip_prefix('#').unwrap_or(filter);
                number.parse::<u16>().ok() == Some(*id)
                    || type_name(*id).is_some_and(|name| {
                        name.eq_ignore_ascii_case(filter) || name["RT_".len()..].eq_ignore_ascii_case(filter)
                    })
            }
            ResourceKey::Name(name) => name.eq_ignore_ascii_case(filter),
        }
    }

    /// Whether [`decode`] interprets this leaf's type (RT_VERSION or RT_MANIFEST).
    pub fn is_decodable(&self) -> bool {
        matches!(self.type_key, ResourceKey::Id(RT_VERSION | RT_MANIFEST))
    }

    /// The leaf's bytes, when they are all in `image`.
    pub fn bytes<'a>(&self, image: &'a [u8]) -> Option<&'a [u8]> {
        let start = usize::try_from(self.file_offset?).ok()?;
        image.get(start..start.checked_add(usize::try_from(self.size).ok()?)?)
    }
}

/// The resource directory's location and every leaf the bounded walk reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeResources {
    /// RVA and size from the data directory; `None` when the image declares no resources.
    pub directory_rva: Option<u32>,
    pub directory_size: Option<u32>,
    pub leaves: Vec<ResourceLeaf>,
    pub tables_visited: usize,
    pub entries_visited: usize,
    /// Whether a table, entry or leaf limit stopped the walk early.
    pub truncated: bool,
    pub warnings: Vec<String>,
}

/// A decoded resource payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourcePayload {
    Version(VersionInfo),
    Manifest(Manifest),
}

/// The resources of a loaded image, or `None` when it is not a PE.
pub fn resources(binary: &Binary) -> Result<Option<PeResources>, LoadError> {
    if binary.format != Format::Pe {
        return Ok(None);
    }
    parse_resources(binary.image_bytes())
}

/// [`resources`] for raw PE file bytes.
pub fn parse_resources(image: &[u8]) -> Result<Option<PeResources>, LoadError> {
    match object::FileKind::parse(image) {
        Ok(object::FileKind::Pe32) => walk::<object::pe::ImageNtHeaders32>(image).map(Some),
        Ok(object::FileKind::Pe64) => walk::<object::pe::ImageNtHeaders64>(image).map(Some),
        _ => Ok(None),
    }
}

/// Decodes RT_VERSION and RT_MANIFEST leaves whose bytes are in the image; `None` for any other leaf.
pub fn decode(image: &[u8], leaf: &ResourceLeaf) -> Option<ResourcePayload> {
    match leaf.type_key {
        ResourceKey::Id(RT_VERSION) => Some(ResourcePayload::Version(version::parse(leaf.bytes(image)?))),
        ResourceKey::Id(RT_MANIFEST) => Some(ResourcePayload::Manifest(manifest::parse(leaf.bytes(image)?))),
        _ => None,
    }
}

const RT_VERSION: u16 = 16;
const RT_MANIFEST: u16 = 24;

/// The predefined numeric resource types.
pub fn type_name(id: u16) -> Option<&'static str> {
    Some(match id {
        1 => "RT_CURSOR",
        2 => "RT_BITMAP",
        3 => "RT_ICON",
        4 => "RT_MENU",
        5 => "RT_DIALOG",
        6 => "RT_STRING",
        7 => "RT_FONTDIR",
        8 => "RT_FONT",
        9 => "RT_ACCELERATOR",
        10 => "RT_RCDATA",
        11 => "RT_MESSAGETABLE",
        12 => "RT_GROUP_CURSOR",
        14 => "RT_GROUP_ICON",
        16 => "RT_VERSION",
        17 => "RT_DLGINCLUDE",
        19 => "RT_PLUGPLAY",
        20 => "RT_VXD",
        21 => "RT_ANICURSOR",
        22 => "RT_ANIICON",
        23 => "RT_HTML",
        24 => "RT_MANIFEST",
        _ => return None,
    })
}

struct Walk<'data> {
    image: &'data [u8],
    directory: ResourceDirectory<'data>,
    sections: object::read::pe::SectionTable<'data>,
    visited: HashSet<u32>,
    report: PeResources,
}

fn walk<Pe: ImageNtHeaders>(image: &[u8]) -> Result<PeResources, LoadError> {
    let file = PeFile::<Pe>::parse(image)?;
    let mut report = PeResources {
        directory_rva: None,
        directory_size: None,
        leaves: Vec::new(),
        tables_visited: 0,
        entries_visited: 0,
        truncated: false,
        warnings: Vec::new(),
    };
    let Some(entry) = file.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE) else { return Ok(report) };
    let (rva, size) = entry.address_range();
    if rva == 0 || size == 0 {
        return Ok(report);
    }
    report.directory_rva = Some(rva);
    report.directory_size = Some(size);
    let sections = file.section_table();
    // Windows reads the tree from the RVA and ignores the declared size, which packers leave too large; so when
    // the size overruns the section's file data, the directory runs to the end of that data instead.
    let data = entry.data(image, &sections).or_else(|error| {
        let data = sections.pe_data_at(image, rva).ok_or(error)?;
        let warning = format!(
            "resource directory size {size:#x} overruns its section's file data; read the {:#x} bytes from RVA \
             {rva:#x} to the section's end",
            data.len()
        );
        WARNINGS.push(&mut report.warnings, warning);
        Ok::<_, object::read::Error>(data)
    });
    let directory = match data {
        Ok(data) => ResourceDirectory::new(data),
        Err(error) => {
            WARNINGS.push(&mut report.warnings, format!("resource directory at RVA {rva:#x} is unreadable: {error}"));
            return Ok(report);
        }
    };
    let root = match directory.root() {
        Ok(root) => root,
        Err(error) => {
            WARNINGS.push(&mut report.warnings, format!("resource root table is unreadable: {error}"));
            return Ok(report);
        }
    };
    let mut walk = Walk { image, directory, sections, visited: HashSet::from([0]), report };
    walk.report.tables_visited = 1;
    walk.table(root, &mut Vec::new());
    Ok(walk.report)
}

impl<'data> Walk<'data> {
    fn warn(&mut self, warning: String) {
        WARNINGS.push(&mut self.report.warnings, warning);
    }

    /// Visits `table`'s entries; `path` holds the keys of the tables above it (type, then name).
    fn table(&mut self, table: object::read::pe::ResourceDirectoryTable<'data>, path: &mut Vec<ResourceKey>) {
        for entry in table.entries {
            if self.report.entries_visited >= MAX_RESOURCE_ENTRIES {
                self.report.truncated = true;
                return;
            }
            self.report.entries_visited += 1;
            let key = self.key(entry.name_or_id());
            let offset = entry.data_offset();
            if entry.is_table() {
                if path.len() + 1 >= MAX_RESOURCE_DEPTH {
                    self.warn(format!("resource table at offset {offset:#x} nests deeper than type/name/language"));
                    continue;
                }
                if !self.visited.insert(offset) {
                    self.warn(format!("resource table at offset {offset:#x} is referenced again (a loop or alias)"));
                    continue;
                }
                if self.report.tables_visited >= MAX_RESOURCE_TABLES {
                    self.report.truncated = true;
                    return;
                }
                self.report.tables_visited += 1;
                match entry.data(self.directory) {
                    Ok(ResourceDirectoryEntryData::Table(child)) => {
                        path.push(key);
                        self.table(child, path);
                        path.pop();
                    }
                    Ok(ResourceDirectoryEntryData::Data(_)) => {}
                    Err(error) => self.warn(format!("resource table at offset {offset:#x} is unreadable: {error}")),
                }
                if self.report.truncated {
                    return;
                }
            } else {
                let data = match entry.data(self.directory) {
                    Ok(ResourceDirectoryEntryData::Data(data)) => data,
                    Ok(ResourceDirectoryEntryData::Table(_)) => continue,
                    Err(error) => {
                        self.warn(format!("resource data entry at offset {offset:#x} is unreadable: {error}"));
                        continue;
                    }
                };
                if self.report.leaves.len() >= MAX_RESOURCE_LEAVES {
                    self.report.truncated = true;
                    return;
                }
                let mut keys = path.iter().cloned().chain([key]);
                let type_key = keys.next().expect("the path ends with this entry's key");
                let (name, language) = (keys.next(), keys.next());
                if language.is_none() {
                    self.warn(format!("resource data entry at offset {offset:#x} sits above the language level"));
                }
                let data_rva = data.offset_to_data.get(LE);
                let size = data.size.get(LE);
                let range = self.sections.pe_file_range_at(data_rva);
                let in_file = range.is_some_and(|(start, remaining)| {
                    size <= remaining && u64::from(start) + u64::from(size) <= self.image.len() as u64
                });
                if !in_file {
                    self.warn(format!("resource data at RVA {data_rva:#x} ({size} bytes) is not all in the file"));
                }
                self.report.leaves.push(ResourceLeaf {
                    type_name: match &type_key {
                        ResourceKey::Id(id) => type_name(*id).map_or_else(|| format!("#{id}"), str::to_owned),
                        ResourceKey::Name(name) => name.clone(),
                    },
                    type_key,
                    name,
                    language,
                    data_rva,
                    size,
                    code_page: data.code_page.get(LE),
                    file_offset: range
                        .map(|(start, _)| u64::from(start))
                        .filter(|&start| start < self.image.len() as u64),
                    in_file,
                });
            }
        }
    }

    fn key(&mut self, name_or_id: ResourceNameOrId) -> ResourceKey {
        match name_or_id {
            ResourceNameOrId::Id(id) => ResourceKey::Id(id),
            ResourceNameOrId::Name(name) => match name.data(self.directory) {
                Ok(units) => {
                    let kept = &units[..units.len().min(MAX_RESOURCE_NAME_UNITS)];
                    let mut text: String = char::decode_utf16(kept.iter().map(|unit| unit.get(LE)))
                        .map(|decoded| decoded.unwrap_or(char::REPLACEMENT_CHARACTER))
                        .collect();
                    if units.len() > kept.len() {
                        text.push('…');
                    }
                    ResourceKey::Name(text)
                }
                Err(error) => {
                    self.warn(format!("resource name is unreadable: {error}"));
                    ResourceKey::Name(String::from("<unreadable>"))
                }
            },
        }
    }
}

/// Reads a NUL-terminated or length-bounded UTF-16LE string from `bytes`, keeping at most `max_units` units.
/// Returns the text, the number of bytes consumed (terminator included) and whether a terminator was found.
pub(crate) fn utf16_until_nul(bytes: &[u8], max_units: usize) -> (String, usize, bool) {
    let mut units = Vec::new();
    let mut consumed = 0;
    let mut terminated = false;
    for pair in bytes.as_chunks::<2>().0 {
        consumed += 2;
        let unit = u16::from_le_bytes(*pair);
        if unit == 0 {
            terminated = true;
            break;
        }
        if units.len() < max_units {
            units.push(unit);
        }
    }
    let text = char::decode_utf16(units).map(|decoded| decoded.unwrap_or(char::REPLACEMENT_CHARACTER)).collect();
    (text, consumed, terminated)
}

#[cfg(test)]
mod tests;
