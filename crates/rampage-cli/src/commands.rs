use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rampage_analysis::discover::{Xref, XrefKind};
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
    if let Some(address) = functions::Names::new(binary).address_of(text) {
        return Ok(address);
    }
    if let Some(address) = text.strip_prefix("sub_").and_then(|hex| u64::from_str_radix(hex, 16).ok()) {
        return Ok(address);
    }
    bail!("no symbol or export named {text:?}")
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
        #[serde(skip_serializing_if = "Option::is_none")]
        data_ref: Option<u64>,
    }

    let mut lines = Vec::with_capacity(count.min(4096));
    let mut offset = 0;
    while lines.len() < count && offset < code.len() {
        let address = start + offset as u64;
        let insn = decoder.decode(&code[offset..], address);
        let bytes = &code[offset..offset + insn.len as usize];
        let text = decoder.format(bytes, address);
        offset += insn.len as usize;
        lines.push(Line { address, bytes: hex(bytes), text, flow: insn.flow, data_ref: insn.data_ref });
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

pub fn funcs(out: &mut impl Write, path: &Path, symbols_only: bool, options: &Options) -> Result<()> {
    let binary = open(path, options)?;
    if symbols_only {
        let found = functions::from_symbols(&binary);
        if options.json {
            return write_json(out, &found);
        }
        for function in &found {
            writeln!(out, "{:#018x} {:>8} {}", function.address, function.size, function.name)?;
        }
        return Ok(());
    }

    #[derive(Serialize)]
    struct Row {
        address: u64,
        name: String,
        size: u64,
        blocks: usize,
        instructions: usize,
    }

    let program = functions::analyze(&binary)?;
    let names = functions::Names::new(&binary);
    let rows: Vec<Row> = program
        .functions
        .iter()
        .map(|function| {
            let end = function.blocks.iter().map(|block| block.end).max().unwrap_or(function.address);
            Row {
                address: function.address,
                name: names.function_name(function.address),
                size: end.saturating_sub(function.address),
                blocks: function.blocks.len(),
                instructions: function.instruction_count,
            }
        })
        .collect();
    if options.json {
        return write_json(out, &rows);
    }
    writeln!(out, "{:<18} {:>8} {:>6} {:>6}  name", "address", "size", "blocks", "insns")?;
    for row in &rows {
        writeln!(out, "{:#018x} {:>8} {:>6} {:>6}  {}", row.address, row.size, row.blocks, row.instructions, row.name)?;
    }
    Ok(())
}

pub enum XrefQuery<'a> {
    To(&'a str),
    From(&'a str),
}

pub fn xrefs(out: &mut impl Write, path: &Path, query: XrefQuery, options: &Options) -> Result<()> {
    let binary = open(path, options)?;
    let program = functions::analyze(&binary)?;
    let names = functions::Names::new(&binary);

    let selected: Vec<Xref> = match query {
        XrefQuery::To(text) => program.xrefs_to(resolve_address(&binary, text)?).to_vec(),
        XrefQuery::From(text) => {
            let address = resolve_address(&binary, text)?;
            match program.function_at(address) {
                Some(function) => program.xrefs.iter().filter(|xref| function.contains(xref.from)).copied().collect(),
                None => program.xrefs.iter().filter(|xref| xref.from == address).copied().collect(),
            }
        }
    };

    #[derive(Serialize)]
    struct Row {
        from: u64,
        to: u64,
        kind: XrefKind,
        from_function: Option<String>,
        to_name: Option<String>,
    }

    let mut rows: Vec<Row> = selected
        .iter()
        .map(|xref| Row {
            from: xref.from,
            to: xref.to,
            kind: xref.kind,
            from_function: program
                .functions_containing(xref.from)
                .next()
                .map(|function| names.function_name(function.address)),
            to_name: names.get(xref.to).map(str::to_owned),
        })
        .collect();
    rows.sort_by_key(|row| (row.from, row.to));
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
