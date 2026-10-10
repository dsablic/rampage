use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use rampage_analysis::discover::XrefKind;
use rampage_analysis::functions;
use rampage_analysis::strings::Encoding;
use rampage_api::{FunctionsQuery, Project, Session, StringsQuery, XrefQuery};
use rampage_arch::Arch;
use rampage_loaders::Perms;
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

fn perms_text(perms: Perms) -> String {
    let flag = |set, letter| if set { letter } else { '-' };
    [flag(perms.read, 'r'), flag(perms.write, 'w'), flag(perms.execute, 'x')].iter().collect()
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
        let perms = perms_text(segment.perms);
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
        writeln!(out, "  {:#018x}  {:<24} {}", line.address, line.bytes, line.text)?;
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
