//! Static archives (`ar`: GNU and BSD formats, with their symbol indexes and long-name tables): listing members and
//! choosing one to open. A member is named in a path the way linkers spell it, `libfoo.a(member.o)`; `#N` picks the
//! member at index N (in archive order, from 0), which tells apart members that share a name: `libfoo.a(#3)`, or
//! `libfoo.a(member.o#3)` to also check the name. MSVC `.lib` libraries are `ar` archives too (their members COFF
//! objects, or short import objects in an import library), and a Mach-O universal library holds one archive per
//! architecture, of which a member path opens the slice the architecture selects.

use std::path::{Path, PathBuf};

use object::Object;
use object::read::archive::ArchiveFile;
use serde::Serialize;

use rampage_arch::Arch;

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
    /// The universal library's slice the member is in, by architecture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

impl Member {
    /// What a path names this member with: its name, or `#index` when another member shares the name.
    pub fn selector(&self) -> String {
        if self.name.contains(['(', ')', '#']) || self.name.is_empty() {
            format!("#{}", self.index)
        } else if self.duplicates > 0 {
            format!("{}#{}", self.name, self.index)
        } else {
            self.name.clone()
        }
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
            arch: None,
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
    let slice = archive.members.first().and_then(|member| member.arch.as_deref()).map_or_else(String::new, |arch| {
        format!(" in the {arch} slice of a universal library (`arch` picks another slice)")
    });
    LoadError::Unsupported(format!(
        "static archive ({} ar format, {} members{slice}) as one binary: open one member by naming it in the path, \
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

/// A static library as a member path reads it: the archive (of the selected slice, for a universal library), where
/// its bytes start in the file, and the slice's architecture.
pub struct Library {
    pub archive: Archive,
    /// Where the archive starts in the file: 0, or the selected slice's offset.
    pub base: u64,
    /// The selected slice's architecture, for a universal library.
    pub arch: Option<Arch>,
    /// Every slice's architecture, for a universal library.
    pub slices: Vec<Arch>,
}

/// The slices of a Mach-O universal file whose every slice is an `ar` archive: each one's architecture and byte
/// range. `None` for any other file.
pub fn universal_archives(data: &[u8]) -> Option<Vec<(Option<Arch>, std::ops::Range<usize>)>> {
    use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
    fn slices<Fat: FatArch>(arches: &[Fat], data: &[u8]) -> Option<Vec<(Option<Arch>, std::ops::Range<usize>)>> {
        let mut found = Vec::new();
        for slice in arches {
            let start = usize::try_from(slice.offset().into()).ok()?;
            let end = start.checked_add(usize::try_from(slice.size().into()).ok()?)?;
            let bytes = data.get(start..end)?;
            if !is_archive(bytes) {
                return None;
            }
            found.push((crate::load::arch_of(slice.architecture()), start..end));
        }
        (!found.is_empty()).then_some(found)
    }
    match object::FileKind::parse(data).ok()? {
        object::FileKind::MachOFat32 => slices(MachOFatFile32::parse(data).ok()?.arches(), data),
        object::FileKind::MachOFat64 => slices(MachOFatFile64::parse(data).ok()?.arches(), data),
        _ => None,
    }
}

/// Whether `data` is a static library: an `ar` archive, or a universal file of them.
pub fn is_static_library(data: &[u8]) -> bool {
    is_archive(data) || universal_archives(data).is_some()
}

/// Reads the static library in `data`: an `ar` archive, or the slice of a universal one that `wanted` selects
/// (else x86-64, arm64 or x86, in that order, as a universal binary's slice is chosen). Members' offsets are the
/// file's.
pub fn read_library(data: &[u8], wanted: Option<Arch>) -> Result<Library, LoadError> {
    if is_archive(data) {
        return Ok(Library { archive: read(data)?, base: 0, arch: None, slices: Vec::new() });
    }
    let Some(slices) = universal_archives(data) else {
        return Err(LoadError::Unsupported("not an ar archive or a universal library of them".to_owned()));
    };
    let present: Vec<Arch> = slices.iter().filter_map(|(arch, _)| *arch).collect();
    let chosen = match wanted {
        Some(wanted) => slices.iter().find(|(arch, _)| *arch == Some(wanted)),
        None => [Arch::X86_64, Arch::Aarch64, Arch::X86]
            .iter()
            .find_map(|&preferred| slices.iter().find(|(arch, _)| *arch == Some(preferred)))
            .or_else(|| slices.iter().find(|(arch, _)| arch.is_some())),
    };
    let Some((arch, range)) = chosen else {
        let present = present.iter().map(Arch::to_string).collect::<Vec<_>>().join(", ");
        let wanted = wanted.map_or_else(|| "a supported".to_owned(), |wanted| wanted.to_string());
        return Err(LoadError::Unsupported(format!("no {wanted} slice; the universal library holds {present}")));
    };
    let mut archive = read(&data[range.clone()])?;
    let name = arch.map(|arch| arch.to_string());
    for member in &mut archive.members {
        member.offset += range.start as u64;
        member.arch.clone_from(&name);
    }
    Ok(Library { archive, base: range.start as u64, arch: *arch, slices: present })
}

/// The member of the static library in `data` whose bytes start at `offset`, in any slice of a universal one.
pub fn member_at(data: &[u8], offset: u64) -> Option<Member> {
    if is_archive(data) {
        return read(data).ok()?.member_at(offset).cloned();
    }
    let slices = universal_archives(data)?;
    let at = usize::try_from(offset).ok()?;
    let (arch, range) = slices.iter().find(|(_, range)| range.contains(&at))?;
    let archive = read(&data[range.clone()]).ok()?;
    let mut member = archive.member_at(offset - range.start as u64)?.clone();
    member.offset += range.start as u64;
    member.arch = arch.map(|arch| arch.to_string());
    Some(member)
}

/// The member a member path names, as the archive's path and the member's location in it; `wanted` picks a
/// universal library's slice. `Ok(None)` when `path` names no member.
pub fn resolve(path: &Path, wanted: Option<Arch>) -> Result<Option<(PathBuf, ImageAt, Member)>, LoadError> {
    let Some((archive_path, selector)) = split_member_path(path) else { return Ok(None) };
    if !archive_path.exists() {
        return Err(LoadError::Io {
            path: path.to_owned(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "no such file, nor an archive `{}` with a member `{selector}` (a member path is `lib.a(member.o)`)",
                    archive_path.display()
                ),
            ),
        });
    }
    let data = map(&archive_path)?;
    if !is_static_library(&data) {
        return Err(LoadError::Unsupported(format!(
            "`{}` is not an ar archive, so `({selector})` names no member",
            archive_path.display()
        )));
    }
    let library = read_library(&data, wanted)?;
    let member = library.archive.select(&selector)?.clone();
    if member.size == 0 {
        return Err(LoadError::Malformed(format!("archive member `{}` is empty", member.name)));
    }
    Ok(Some((archive_path, ImageAt::new(member.offset, Some(member.size)), member)))
}

/// `path` and `image`, or for a path naming a static archive's member (`libfoo.a(member.o)`), the archive, the
/// member's location in it and the member; `wanted` picks a universal library's slice. A member path given with an
/// image location other than the whole file as well is refused.
pub fn member_image(
    path: &Path,
    image: Option<ImageAt>,
    wanted: Option<Arch>,
) -> Result<(PathBuf, Option<ImageAt>, Option<Member>), LoadError> {
    match resolve(path, wanted)? {
        None => Ok((path.to_owned(), image, None)),
        Some(_) if image.is_some_and(|image| !image.is_whole_file()) => Err(LoadError::Location(
            "a path naming an archive member selects the image itself; give no image offset with it".to_owned(),
        )),
        Some((archive, location, member)) => Ok((archive, Some(location), Some(member))),
    }
}

/// A short import object (`IMPORT_OBJECT_HEADER`, an import library's member): the symbol a DLL exports and how
/// the import names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportMember {
    pub dll: String,
    pub symbol: String,
    /// `code`, `data` or `const`.
    pub kind: &'static str,
    /// How the DLL's export is found: `ordinal`, or by `name` (the symbol as it is, without its prefix, undecorated,
    /// or a separate export name).
    pub by: &'static str,
    /// The export name looked up in the DLL, when imported by name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import: Option<String>,
    /// The ordinal, when imported by ordinal; else the hint.
    pub ordinal_or_hint: u16,
}

/// The short import object in `bytes`, or `None` for anything else.
pub fn import_member(bytes: &[u8]) -> Option<ImportMember> {
    use object::read::coff::{ImportFile, ImportName, ImportType};
    if object::FileKind::parse(bytes).ok()? != object::FileKind::CoffImport {
        return None;
    }
    let file = ImportFile::parse(bytes).ok()?;
    let header = object::pe::ImportObjectHeader::parse(bytes, &mut 0).ok()?;
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    let ordinal_or_hint = header.ordinal_or_hint.get(object::LittleEndian);
    let (by, import) = match file.import() {
        ImportName::Ordinal(_) => ("ordinal", None),
        ImportName::Name(name) => ("name", Some(text(name))),
    };
    let by = match (by, header.name_type()) {
        ("ordinal", _) => "ordinal",
        (_, object::pe::IMPORT_OBJECT_NAME_NO_PREFIX) => "name without prefix",
        (_, object::pe::IMPORT_OBJECT_NAME_UNDECORATE) => "undecorated name",
        (_, object::pe::IMPORT_OBJECT_NAME_EXPORTAS) => "export name",
        _ => "name",
    };
    Some(ImportMember {
        dll: text(file.dll()),
        symbol: text(file.symbol()),
        kind: match file.import_type() {
            ImportType::Code => "code",
            ImportType::Data => "data",
            ImportType::Const => "const",
        },
        by,
        import,
        ordinal_or_hint,
    })
}

/// The error for opening a short import object: it names an import and holds no code.
pub fn import_member_error(import: &ImportMember) -> LoadError {
    let how = match import.by {
        "ordinal" => format!("by ordinal {}", import.ordinal_or_hint),
        by => format!("by {by} `{}`", import.import.as_deref().unwrap_or(&import.symbol)),
    };
    LoadError::Unsupported(format!(
        "short import object (an import library member): `{}` imports {}!{} ({}, {how}) and holds no code or \
         data to analyze; archive_inventory lists a library's imports",
        import.symbol,
        import.dll,
        import.import.as_deref().unwrap_or(&import.symbol),
        import.kind
    ))
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
    if let Ok(object::FileKind::CoffImport) = object::FileKind::parse(bytes) {
        let machine = object::read::coff::ImportFile::parse(bytes).map(|file| file.architecture());
        return format!("coff import {:?}", machine.unwrap_or(object::Architecture::Unknown)).to_ascii_lowercase();
    }
    match object::File::parse(bytes) {
        Ok(parsed) => {
            format!("{:?} {:?} {:?}", parsed.format(), parsed.kind(), parsed.architecture()).to_ascii_lowercase()
        }
        // MSVC libraries hold machine-independent COFF objects (`IMAGE_FILE_MACHINE_UNKNOWN`) that only alias
        // symbols, through weak externals.
        Err(_) if bytes.starts_with(&[0, 0]) && object::read::coff::CoffFile::<&[u8]>::parse(bytes).is_ok() => {
            "coff relocatable unknown (symbol aliases, no code)".to_owned()
        }
        Err(_) => "not an object file".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::Member;

    #[test]
    fn names_a_path_cannot_spell_are_selected_by_index() {
        let member = |name: &str, duplicates| Member {
            index: 4,
            name: name.to_owned(),
            offset: 0,
            size: 1,
            duplicates,
            arch: None,
        };
        assert_eq!(member("plain.o", 0).selector(), "plain.o");
        assert_eq!(member("plain.o", 1).selector(), "plain.o#4");
        for name in ["a(b).o", "x#1.o", ""] {
            assert_eq!(member(name, 0).selector(), "#4", "{name}");
        }
    }
}
