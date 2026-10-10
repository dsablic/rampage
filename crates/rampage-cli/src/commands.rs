use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rampage_analysis::{functions, strings};
use rampage_arch::{Arch, Flow, decoder_for};
use rampage_loaders::{Binary, Perms};
use serde::Serialize;

pub struct Options {
    pub json: bool,
    pub arch: Option<Arch>,
}

fn open(path: &Path, options: &Options) -> Result<Binary> {
    Binary::open_with(path, options.arch).with_context(|| format!("{}", path.display()))
}

fn write_json(out: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer_pretty(&mut *out, value)?;
    writeln!(out)?;
    Ok(())
}

fn perms_text(perms: Perms) -> String {
    let flag = |set, letter| if set { letter } else { '-' };
    [flag(perms.read, 'r'), flag(perms.write, 'w'), flag(perms.execute, 'x')].iter().collect()
}

pub fn info(out: &mut impl Write, path: &Path, options: &Options) -> Result<()> {
    let binary = open(path, options)?;
    if options.json {
        return write_json(out, &binary);
    }
    writeln!(out, "format    {:?}", binary.format)?;
    writeln!(out, "arch      {}", binary.arch)?;
    if binary.slices.len() > 1 {
        let slices: Vec<_> = binary.slices.iter().map(Arch::to_string).collect();
        writeln!(out, "slices    {}", slices.join(", "))?;
    }
    match binary.entry {
        Some(entry) => writeln!(out, "entry     {entry:#x}")?,
        None => writeln!(out, "entry     none")?,
    }
    writeln!(out, "symbols   {}", binary.symbols.len())?;
    writeln!(out, "imports   {}", binary.imports.len())?;
    writeln!(out, "exports   {}", binary.exports.len())?;
    writeln!(out, "\nsegments")?;
    for segment in &binary.segments {
        let end = segment.address.saturating_add(segment.size);
        let perms = perms_text(segment.perms);
        writeln!(out, "  {:#018x}-{:#018x} {perms} {}", segment.address, end, segment.name)?;
    }
    writeln!(out, "\nsections")?;
    for section in &binary.sections {
        let end = section.address.saturating_add(section.size);
        writeln!(out, "  {:#018x}-{:#018x} {:<20} {:?}", section.address, end, section.name, section.kind)?;
    }
    Ok(())
}

fn resolve_address(binary: &Binary, text: &str) -> Result<u64> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).with_context(|| format!("invalid hex address {text:?}"));
    }
    if let Ok(address) = text.parse() {
        return Ok(address);
    }
    let symbol = binary.symbol_by_name(text).map(|symbol| symbol.address);
    let export = || binary.exports.iter().find(|export| export.name == text).map(|export| export.address);
    symbol.or_else(export).with_context(|| format!("no symbol or export named {text:?}"))
}

pub fn disasm(out: &mut impl Write, path: &Path, at: Option<&str>, count: usize, options: &Options) -> Result<()> {
    let binary = open(path, options)?;
    let mut decoder = decoder_for(binary.arch)?;
    let start = match at {
        Some(text) => resolve_address(&binary, text)?,
        None => binary.entry.context("no entry point; pass --at <address or symbol>")?,
    };
    let Some(code) = binary.read_to_segment_end(start) else {
        bail!("address {start:#x} is not backed by file data");
    };

    #[derive(Serialize)]
    struct Line {
        address: u64,
        bytes: String,
        text: String,
        flow: Flow,
    }

    let mut lines = Vec::with_capacity(count.min(4096));
    let mut offset = 0;
    while lines.len() < count && offset < code.len() {
        let address = start + offset as u64;
        let insn = decoder.decode_one(&code[offset..], address);
        let bytes = &code[offset..offset + insn.len as usize];
        offset += insn.len as usize;
        lines.push(Line { address, bytes: hex(bytes), text: insn.text, flow: insn.flow });
    }

    if options.json {
        return write_json(out, &lines);
    }
    for line in &lines {
        if let Some(symbol) = binary.symbols.iter().find(|symbol| symbol.address == line.address) {
            writeln!(out, "{}:", symbol.name)?;
        }
        writeln!(out, "  {:#018x}  {:<24} {}", line.address, line.bytes, line.text)?;
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn strings(out: &mut impl Write, path: &Path, min_len: usize, options: &Options) -> Result<()> {
    let binary = open(path, options)?;
    let found = strings::scan(&binary, min_len);
    if options.json {
        return write_json(out, &found);
    }
    for string in &found {
        let encoding = match string.encoding {
            strings::Encoding::Ascii => "a",
            strings::Encoding::Utf16Le => "u",
        };
        writeln!(out, "{:#018x} {encoding} {}", string.address, string.text)?;
    }
    Ok(())
}

pub fn funcs(out: &mut impl Write, path: &Path, options: &Options) -> Result<()> {
    let binary = open(path, options)?;
    let found = functions::from_symbols(&binary);
    if options.json {
        return write_json(out, &found);
    }
    for function in &found {
        writeln!(out, "{:#018x} {:>8} {}", function.address, function.size, function.name)?;
    }
    Ok(())
}
