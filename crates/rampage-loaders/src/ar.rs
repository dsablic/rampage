//! Static archives (`ar`: GNU and BSD formats, with their symbol indexes and long-name tables): listing members and
//! choosing one to open. A member is named in a path the way linkers spell it, `libfoo.a(member.o)`; `#N` picks the
//! member at index N (in archive order, from 0), which tells apart members that share a name: `libfoo.a(#3)`, or
//! `libfoo.a(member.o#3)` to also check the name.

use std::path::{Path, PathBuf};

use object::Object;
use object::read::archive::ArchiveFile;
use serde::Serialize;

use crate::{ImageAt, LoadError};

/// The most members listed in an error that names them.
const MEMBERS_IN_ERRORS: usize = 12;

/// One member of an archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Member {
    /// The member's place in archive order, from 0 (the symbol index and long-name tables are not members).
    pub index: usize,
    /// The member's name, from its header or the long-name table.
    pub name: String,
    /// Where its bytes start in the archive file.
    pub offset: u64,
    pub size: u64,
    /// How many other members have the same name.
    #[serde(skip_serializing_if = "is_zero")]
    pub duplicates: usize,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

impl Member {
    /// What a path names this member with: its name, or `#index` when another member shares the name.
    pub fn selector(&self) -> String {
        if self.duplicates > 0 { format!("{}#{}", self.name, self.index) } else { self.name.clone() }
    }
}

/// A static archive's members and symbol index.
#[derive(Debug, Clone, Serialize)]
pub struct Archive {
    /// `gnu`, `gnu64`, `bsd`, `bsd64`, `coff` or `unknown` (no symbol index or long names to tell).
    pub kind: &'static str,
    pub members: Vec<Member>,
    /// The symbol index: each defined symbol and the index of the member defining it.
    pub symbols: Vec<(String, usize)>,
}

/// Whether `data` starts like an `ar` archive.
pub fn is_archive(data: &[u8]) -> bool {
    data.starts_with(b"!<arch>\n") || data.starts_with(b"!<thin>\n")
}

/// Reads the members and symbol index of the archive in `data`. Thin archives, whose members are other files, are
/// refused.
pub fn read(data: &[u8]) -> Result<Archive, LoadError> {
    let archive = ArchiveFile::parse(data).map_err(|error| LoadError::Malformed(format!("ar archive: {error}")))?;
    if archive.is_thin() {
        return Err(LoadError::Unsupported("thin archives (members stored as separate files)".to_owned()));
    }
    let kind = match archive.kind() {
        object::read::archive::ArchiveKind::Gnu => "gnu",
        object::read::archive::ArchiveKind::Gnu64 => "gnu64",
        object::read::archive::ArchiveKind::Bsd => "bsd",
        object::read::archive::ArchiveKind::Bsd64 => "bsd64",
        object::read::archive::ArchiveKind::Coff => "coff",
        _ => "unknown",
    };
    let mut members = Vec::new();
    for member in archive.members() {
        let member = member.map_err(|error| LoadError::Malformed(format!("ar archive member: {error}")))?;
        let (offset, size) = member.file_range();
        members.push(Member {
            index: members.len(),
            name: String::from_utf8_lossy(member.name()).into_owned(),
            offset,
            size,
            duplicates: 0,
        });
    }
    let mut counts = std::collections::HashMap::new();
    for member in &members {
        *counts.entry(member.name.clone()).or_insert(0usize) += 1;
    }
    for member in &mut members {
        member.duplicates = counts[&member.name] - 1;
    }
    let mut symbols = Vec::new();
    if let Ok(Some(index)) = archive.symbols() {
        for symbol in index {
            let Ok(symbol) = symbol else { break };
            let Ok(member) = archive.member(symbol.offset()) else { continue };
            let offset = member.file_range().0;
            if let Ok(position) = members.binary_search_by_key(&offset, |member| member.offset) {
                symbols.push((String::from_utf8_lossy(symbol.name()).into_owned(), position));
            }
        }
    }
    Ok(Archive { kind, members, symbols })
}

impl Archive {
    /// The member `selector` names: `name`, `#index` or `name#index`.
    pub fn select(&self, selector: &str) -> Result<&Member, LoadError> {
        let (name, index) = match selector.rsplit_once('#') {
            Some((name, index)) if index.parse::<usize>().is_ok() => (name, Some(index.parse::<usize>().unwrap())),
            _ => (selector, None),
        };
        if let Some(index) = index {
            let member = self.members.get(index).ok_or_else(|| {
                LoadError::Location(format!(
                    "archive member #{index} does not exist; the archive has {} members (#0 to #{})",
                    self.members.len(),
                    self.members.len().saturating_sub(1)
                ))
            })?;
            if !name.is_empty() && member.name != name {
                return Err(LoadError::Location(format!("archive member #{index} is `{}`, not `{name}`", member.name)));
            }
            return Ok(member);
        }
        let matching: Vec<&Member> = self.members.iter().filter(|member| member.name == name).collect();
        match matching.as_slice() {
            [member] => Ok(member),
            [] => Err(LoadError::Location(format!("no archive member is named `{name}`; {}", self.listing()))),
            several => {
                let choices: Vec<String> = several.iter().map(|member| format!("`{name}#{}`", member.index)).collect();
                Err(LoadError::Location(format!(
                    "{} archive members are named `{name}`; name one by index: {}",
                    several.len(),
                    choices.join(", ")
                )))
            }
        }
    }

    /// The first members, for an error that has to name some.
    pub fn listing(&self) -> String {
        let names: Vec<String> =
            self.members.iter().take(MEMBERS_IN_ERRORS).map(|member| format!("`{}`", member.selector())).collect();
        let more = self.members.len().saturating_sub(MEMBERS_IN_ERRORS);
        let tail = if more > 0 {
            format!(" and {more} more (archive_inventory, in group carve, lists them all)")
        } else {
            String::new()
        };
        format!("its {} members include {}{tail}", self.members.len(), names.join(", "))
    }

    /// The member whose bytes start at `offset`.
    pub fn member_at(&self, offset: u64) -> Option<&Member> {
        let index = self.members.binary_search_by_key(&offset, |member| member.offset).ok()?;
        self.members.get(index)
    }
}

/// The error for opening a whole archive as one binary: which members there are and how to open one.
pub fn whole_archive_error(path: Option<&Path>, archive: &Archive) -> LoadError {
    let spelled =
        path.and_then(Path::file_name).map_or_else(|| "lib.a".to_owned(), |name| name.to_string_lossy().into_owned());
    let example = archive.members.first().map_or_else(|| "member.o".to_owned(), Member::selector);
    LoadError::Unsupported(format!(
        "static archive ({} ar format, {} members) as one binary: open one member by naming it in the path, \
         `{spelled}({example})`; {}",
        archive.kind,
        archive.members.len(),
        archive.listing()
    ))
}

/// Splits a path naming an archive member, `dir/libfoo.a(member.o)`, into the archive's path and the selector,
/// when no file has that whole name.
pub fn split_member_path(path: &Path) -> Option<(PathBuf, String)> {
    let text = path.to_str()?;
    if !text.ends_with(')') || path.exists() {
        return None;
    }
    let open = text.rfind('(')?;
    let (archive, selector) = (&text[..open], &text[open + 1..text.len() - 1]);
    if archive.is_empty() || selector.is_empty() || archive.ends_with(['/', '\\']) {
        return None;
    }
    Some((PathBuf::from(archive), selector.to_owned()))
}

/// The member a member path names, as the archive's path and the member's location in it. `Ok(None)` when `path`
/// names no member.
pub fn resolve(path: &Path) -> Result<Option<(PathBuf, ImageAt, Member)>, LoadError> {
    let Some((archive_path, selector)) = split_member_path(path) else { return Ok(None) };
    let data = map(&archive_path)?;
    if !is_archive(&data) {
        return Err(LoadError::Unsupported(format!(
            "`{}` is not an ar archive, so `({selector})` names no member",
            archive_path.display()
        )));
    }
    let archive = read(&data)?;
    let member = archive.select(&selector)?.clone();
    if member.size == 0 {
        return Err(LoadError::Malformed(format!("archive member `{}` is empty", member.name)));
    }
    Ok(Some((archive_path, ImageAt::new(member.offset, Some(member.size)), member)))
}

/// The file at `path`, mapped read-only.
pub fn map(path: &Path) -> Result<impl std::ops::Deref<Target = [u8]> + use<>, LoadError> {
    let io_error = |source| LoadError::Io { path: path.to_owned(), source };
    let file = std::fs::File::open(path).map_err(io_error)?;
    // SAFETY: the mapping is read-only; a concurrent external truncation of the input is out of scope, the same
    // assumption every mmap-based binary tool makes.
    unsafe { memmap2::Mmap::map(&file) }.map_err(io_error)
}

/// What the bytes of a member are: `elf relocatable x86_64`, or `not an object file`.
pub fn member_format(bytes: &[u8]) -> String {
    match object::File::parse(bytes) {
        Ok(parsed) => {
            format!("{:?} {:?} {:?}", parsed.format(), parsed.kind(), parsed.architecture()).to_ascii_lowercase()
        }
        Err(_) => "not an object file".to_owned(),
    }
}
