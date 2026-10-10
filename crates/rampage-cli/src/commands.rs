use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use rampage_analysis::discover::XrefKind;
use rampage_analysis::functions;
use rampage_analysis::strings::Encoding;
use rampage_api::{FunctionsQuery, ListQuery, Project, Session, StringsQuery, XrefQuery};
use rampage_arch::Arch;
use rampage_loaders::Details;
use serde::Serialize;

pub struct Options {
    pub json: bool,
    pub arch: Option<Arch>,
}

fn open(path: &Path, options: &Options) -> Result<Arc<Project>> {
    Ok(Session::default().open(path, options.arch)?)
}

/// Serializes before writing so that I/O errors such as a closed pipe surface as `io::Error`.
fn write_json(out: &mut impl Write, value: &impl Serialize) -> Result<()> {
    let mut json = serde_json::to_vec_pretty(value)?;
    json.push(b'\n');
    out.write_all(&json)?;
    Ok(())
}

pub fn info(out: &mut impl Write, path: &Path, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let summary = project.summary();
    if options.json {
        return write_json(out, &summary);
    }
    writeln!(out, "format    {:?}", summary.format)?;
    writeln!(out, "arch      {}", summary.arch)?;
    if summary.slices.len() > 1 {
        let slices: Vec<_> = summary.slices.iter().map(Arch::to_string).collect();
        writeln!(out, "slices    {}", slices.join(", "))?;
    }
    match summary.entry {
        Some(entry) => writeln!(out, "entry     {entry:#x}")?,
        None => writeln!(out, "entry     none")?,
    }
    writeln!(out, "symbols   {}", summary.symbols)?;
    writeln!(out, "imports   {}", summary.imports)?;
    writeln!(out, "exports   {}", summary.exports)?;
    for warning in summary.warnings {
        writeln!(out, "warning   {warning}")?;
    }
    writeln!(out, "\nsegments")?;
    for segment in summary.segments {
        let end = segment.address.saturating_add(segment.size);
        let perms = segment.perms;
        writeln!(out, "  {:#018x}-{:#018x} {perms} {}", segment.address, end, segment.name)?;
    }
    writeln!(out, "\nsections")?;
    for section in summary.sections {
        let end = section.address.saturating_add(section.size);
        writeln!(out, "  {:#018x}-{:#018x} {:<20} {:?}", section.address, end, section.name, section.kind)?;
    }
    Ok(())
}

pub fn disasm(out: &mut impl Write, path: &Path, at: Option<&str>, count: usize, options: &Options) -> Result<()> {
    let lines = open(path, options)?.disassemble(at, count)?;
    if options.json {
        return write_json(out, &lines);
    }
    for line in &lines {
        if let Some(label) = &line.label {
            writeln!(out, "{label}:")?;
        }
        // The user's comment first, then what the instruction refers to.
        let comments: Vec<&str> = [line.note.as_deref(), line.comment.as_deref()].into_iter().flatten().collect();
        if comments.is_empty() {
            writeln!(out, "  {:#018x}  {:<24} {}", line.address, line.bytes, line.text)?;
        } else {
            let comments = comments.join(" | ");
            writeln!(out, "  {:#018x}  {:<24} {:<40} ; {comments}", line.address, line.bytes, line.text)?;
        }
    }
    Ok(())
}

pub fn strings(out: &mut impl Write, path: &Path, query: &StringsQuery, options: &Options) -> Result<()> {
    let found = open(path, options)?.strings(query).items;
    if options.json {
        return write_json(out, &found);
    }
    for string in &found {
        let encoding = match string.encoding {
            Encoding::Ascii => "a",
            Encoding::Utf16Le => "u",
        };
        writeln!(out, "{:#018x} {encoding} {}", string.address, string.text)?;
    }
    Ok(())
}

pub fn funcs(
    out: &mut impl Write,
    path: &Path,
    symbols_only: bool,
    query: &FunctionsQuery,
    options: &Options,
) -> Result<()> {
    let project = open(path, options)?;
    if symbols_only {
        let found = functions::from_symbols(&project.binary);
        if options.json {
            return write_json(out, &found);
        }
        for function in &found {
            writeln!(out, "{:#018x} {:>8} {}", function.address, function.size, function.name)?;
        }
        return Ok(());
    }

    let rows = project.functions(query)?.items;
    if options.json {
        return write_json(out, &rows);
    }
    writeln!(out, "{:<18} {:>8} {:>6} {:>6}  name", "address", "size", "blocks", "insns")?;
    for row in &rows {
        writeln!(out, "{:#018x} {:>8} {:>6} {:>6}  {}", row.address, row.size, row.blocks, row.instructions, row.name)?;
    }
    Ok(())
}

pub enum XrefTarget<'a> {
    To(&'a str),
    From(&'a str),
}

pub fn xrefs(out: &mut impl Write, path: &Path, target: XrefTarget, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let query = match target {
        XrefTarget::To(text) => XrefQuery::To(project.resolve(text)?),
        XrefTarget::From(text) => XrefQuery::From(project.resolve(text)?),
    };
    let rows = project.xrefs(&query)?;
    if options.json {
        return write_json(out, &rows);
    }
    for row in &rows {
        let kind = match row.kind {
            XrefKind::Call => "call",
            XrefKind::Jump => "jump",
            XrefKind::Data => "data",
        };
        let from_function = row.from_function.as_deref().unwrap_or("?");
        let to_name = row.to_name.as_deref().map(|name| format!(" {name}")).unwrap_or_default();
        writeln!(out, "{:#018x} {kind} {:#018x}{to_name}  (in {from_function})", row.from, row.to)?;
    }
    Ok(())
}

/// One character per entropy point, from blank (0 bits per byte) to `@` (8).
fn profile_text(profile: &[f64]) -> String {
    const SHADES: &[u8] = b" .:-=+*#%@";
    profile.iter().map(|&bits| SHADES[((bits / 8.0) * (SHADES.len() - 1) as f64).round() as usize] as char).collect()
}

pub fn triage(out: &mut impl Write, path: &Path, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let triage = project.triage();
    if options.json {
        return write_json(out, triage);
    }
    writeln!(out, "size      {} bytes", triage.image_size)?;
    writeln!(out, "md5       {}", triage.image_hashes.md5)?;
    writeln!(out, "sha1      {}", triage.image_hashes.sha1)?;
    writeln!(out, "sha256    {}", triage.image_hashes.sha256)?;
    if let (Some(size), Some(hashes)) = (triage.file_size, &triage.file_hashes) {
        writeln!(out, "file      {size} bytes (universal binary), sha256 {}", hashes.sha256)?;
    }
    if let Some(imphash) = &triage.imphash {
        writeln!(out, "imphash   {imphash}")?;
    }
    writeln!(out, "entropy   {:.2}  [{}]", triage.entropy, profile_text(&triage.entropy_profile))?;
    match &triage.details {
        Details::Pe(pe) => {
            writeln!(out, "built     {} UTC (timestamp {:#x})", pe.timestamp_utc, pe.timestamp)?;
            writeln!(out, "subsystem {}, linker {}", pe.subsystem, pe.linker_version)?;
            writeln!(out, "flags     {}", pe.characteristics.join(", "))?;
            writeln!(out, "signed    {}", if pe.signed { "yes" } else { "no" })?;
            if !pe.rich.is_empty() {
                writeln!(out, "rich      {} tool entries", pe.rich.len())?;
            }
        }
        Details::Elf(elf) => {
            writeln!(out, "kind      {}{}", elf.kind, if elf.pie { " (PIE)" } else { "" })?;
            if let Some(interpreter) = &elf.interpreter {
                writeln!(out, "interp    {interpreter}")?;
            }
            if !elf.needed.is_empty() {
                writeln!(out, "needed    {}", elf.needed.join(", "))?;
            }
            writeln!(out, "hardening nx {}, relro {}", if elf.nx { "yes" } else { "no" }, elf.relro)?;
            if let Some(build_id) = &elf.build_id {
                writeln!(out, "build id  {build_id}")?;
            }
        }
        Details::MachO(macho) => {
            writeln!(out, "type      {}  flags {}", macho.file_type, macho.flags.join(", "))?;
            if let (Some(platform), Some(min_os)) = (&macho.platform, &macho.min_os) {
                writeln!(out, "platform  {platform} {min_os} (sdk {})", macho.sdk.as_deref().unwrap_or("?"))?;
            }
            for dylib in &macho.dylibs {
                writeln!(out, "dylib     {dylib}")?;
            }
            writeln!(out, "signed    {}", if macho.code_signature { "yes" } else { "no" })?;
            if let Some(uuid) = &macho.uuid {
                writeln!(out, "uuid      {uuid}")?;
            }
        }
        Details::None => {}
    }
    writeln!(out, "\nsections")?;
    for section in &triage.sections {
        writeln!(
            out,
            "  {:#018x} {:>10} {} {:5.2}  {}",
            section.address, section.size, section.perms, section.entropy, section.name
        )?;
    }
    if let Some(overlay) = &triage.overlay {
        writeln!(out, "\noverlay   {} bytes at {:#x}, entropy {:.2}", overlay.size, overlay.offset, overlay.entropy)?;
    }
    if !triage.hints.is_empty() {
        writeln!(out, "\nhints")?;
        for hint in &triage.hints {
            writeln!(out, "  - {hint}")?;
        }
    }
    Ok(())
}

pub fn imports(out: &mut impl Write, path: &Path, query: &ListQuery, options: &Options) -> Result<()> {
    let rows = open(path, options)?.imports(query).items;
    if options.json {
        return write_json(out, &rows);
    }
    for row in &rows {
        let slot = row.slot.map(|slot| format!("{slot:#018x}")).unwrap_or_else(|| " ".repeat(18));
        writeln!(out, "{slot}  {:<40} {}", row.library.as_deref().unwrap_or("-"), row.name)?;
    }
    Ok(())
}

pub fn exports(out: &mut impl Write, path: &Path, query: &ListQuery, options: &Options) -> Result<()> {
    let rows = open(path, options)?.exports(query).items;
    if options.json {
        return write_json(out, &rows);
    }
    for row in &rows {
        writeln!(out, "{:#018x}  {}", row.address, row.name)?;
    }
    Ok(())
}

/// The value to set: `value`, or nothing with `clear`. Exactly one must be given.
fn edit_value<'a>(value: Option<&'a str>, clear: bool, what: &str) -> Result<Option<&'a str>> {
    match (value, clear) {
        (Some(value), false) => Ok(Some(value)),
        (None, true) => Ok(None),
        _ => anyhow::bail!("pass a {what} or --clear, not both"),
    }
}

pub fn rename(path: &Path, at: &str, name: Option<&str>, clear: bool, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let address = project.resolve(at)?;
    project.rename(address, edit_value(name, clear, "name")?)?;
    Ok(())
}

pub fn comment(path: &Path, at: &str, text: Option<&str>, clear: bool, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let address = project.resolve(at)?;
    project.comment(address, edit_value(text, clear, "comment")?)?;
    Ok(())
}

pub fn annotations(out: &mut impl Write, path: &Path, options: &Options) -> Result<()> {
    let list = open(path, options)?.annotation_list();
    if options.json {
        return write_json(out, &list);
    }
    for name in &list.names {
        writeln!(out, "{:#018x} name    {}", name.address, name.text)?;
    }
    for comment in &list.comments {
        writeln!(out, "{:#018x} comment {}", comment.address, comment.text)?;
    }
    Ok(())
}
