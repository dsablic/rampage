use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use rampage_analysis::functions;
use rampage_analysis::strings::Encoding;
use rampage_api::annotations::Field;
use rampage_api::{EditResult, FunctionsQuery, ListQuery, Project, Session, StringsQuery, XrefQuery};
use rampage_arch::Arch;
use rampage_loaders::Details;
use serde::Serialize;

pub struct Options {
    pub json: bool,
    pub arch: Option<Arch>,
}

pub fn audit(out: &mut impl Write, path: &Path, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let audit = rampage_analysis::diagnostics::diagnostics(&project.binary);
    if options.json {
        return write_json(out, &audit);
    }
    for region in audit.regions {
        writeln!(
            out,
            "{:#x} {}: {} invalid of {} sampled instructions; entropy {:.2}",
            region.address, region.name, region.invalid, region.instructions, region.entropy
        )?;
        writeln!(out, "  {}", region.assessment)?;
    }
    for limitation in audit.limitations {
        writeln!(out, "note: {limitation}")?;
    }
    Ok(())
}

pub fn metadata(out: &mut impl Write, path: &Path, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let metadata = rampage_analysis::language::metadata(&project.binary);
    if options.json {
        return write_json(out, &metadata);
    }
    for symbol in metadata.symbols {
        writeln!(out, "{:#x} {} {}", symbol.address, symbol.category, symbol.display)?;
    }
    for selector in metadata.selectors {
        writeln!(out, "{:#x} selector {}", selector.address, selector.name)?;
    }
    Ok(())
}

pub fn inventory(out: &mut impl Write, path: &Path, options: &Options) -> Result<()> {
    let inventory = rampage_loaders::container::inventory(path)?;
    if options.json {
        return write_json(out, &inventory);
    }
    for binary in inventory.binaries {
        writeln!(out, "{} [{}]", binary.path.display(), binary.slices.join(", "))?;
    }
    for warning in inventory.warnings {
        writeln!(out, "warning: {warning}")?;
    }
    Ok(())
}

pub fn summarize(out: &mut impl Write, path: &Path, at: &str, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let summary = project.function_summary(project.resolve(at)?)?;
    if options.json {
        return write_json(out, &summary);
    }
    writeln!(
        out,
        "{}: {} blocks, {} edges, {} references",
        summary.graph.name,
        summary.graph.blocks.len(),
        summary.graph.edges.len(),
        summary.references.total
    )?;
    for limitation in summary.limitations {
        writeln!(out, "note: {limitation}")?;
    }
    Ok(())
}

pub fn decompile(out: &mut impl Write, path: &Path, at: &str, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let decompilation = project.decompile(project.resolve(at)?)?;
    if options.json {
        return write_json(out, &decompilation);
    }
    write!(out, "{}", decompilation.code)?;
    Ok(())
}

pub fn pseudocode(out: &mut impl Write, path: &Path, at: &str, structured: bool, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let summary = project.function_summary(project.resolve(at)?)?;
    let pseudocode = if structured { summary.structured_pseudocode } else { summary.pseudocode }
        .ok_or_else(|| anyhow::anyhow!("pseudocode unavailable: {}", summary.limitations.join("; ")))?;
    if options.json {
        return write_json(out, &pseudocode);
    }
    write!(out, "{}", pseudocode.text)?;
    for limitation in pseudocode.limitations {
        writeln!(out, "// {limitation}")?;
    }
    Ok(())
}

pub fn compare(out: &mut impl Write, path: &Path, reference: &Path, options: &Options) -> Result<()> {
    if !std::fs::symlink_metadata(reference)?.is_file() {
        anyhow::bail!("reference must be a regular JSON file");
    }
    let file = std::fs::File::open(reference)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(file, 32 * 1024 * 1024 + 1), &mut bytes)?;
    if bytes.len() > 32 * 1024 * 1024 {
        anyhow::bail!("comparison reference exceeds 32 MiB");
    }
    let reference: rampage_api::ReferenceAnalysis = serde_json::from_slice(&bytes)?;
    let result = open(path, options)?.compare_functions(&reference)?;
    if options.json {
        return write_json(out, &result);
    }
    writeln!(
        out,
        "{} {}: {} matches, {} missing, {} extra",
        result.reference_tool,
        result.reference_version,
        result.matched,
        result.missing.len(),
        result.extra.len()
    )?;
    for limitation in result.limitations {
        writeln!(out, "note: {limitation}")?;
    }
    Ok(())
}

pub fn jump_table(
    out: &mut impl Write,
    path: &Path,
    at: &str,
    count: usize,
    relative_base: Option<&str>,
    options: &Options,
) -> Result<()> {
    let project = open(path, options)?;
    let table = project.inspect_jump_table(
        project.resolve(at)?,
        count,
        relative_base.map(|base| project.resolve(base)).transpose()?,
    )?;
    if options.json {
        return write_json(out, &table);
    }
    for entry in table.entries {
        writeln!(out, "{:#x} -> {:#x}", entry.slot, entry.target)?;
    }
    for limitation in table.limitations {
        writeln!(out, "note: {limitation}")?;
    }
    Ok(())
}

pub fn correlate(
    out: &mut impl Write,
    path: &Path,
    original: &Path,
    module: &str,
    at: &str,
    options: &Options,
) -> Result<()> {
    let project = open(path, options)?;
    let original = rampage_loaders::Binary::open_with(original, Some(project.binary.arch))?;
    let result = project.correlate_runtime(module, &original, project.resolve(at)?)?;
    if options.json {
        return write_json(out, &result);
    }
    writeln!(out, "{:#x} -> {:#x} (module {})", result.runtime_address, result.image_address, result.module_uuid)?;
    for limitation in result.limitations {
        writeln!(out, "note: {limitation}")?;
    }
    Ok(())
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
        let needle = query.name_contains.as_deref().map(str::to_lowercase);
        let found: Vec<_> = functions::from_symbols(&project.binary)
            .into_iter()
            .filter(|function| needle.as_deref().is_none_or(|needle| function.name.to_lowercase().contains(needle)))
            .collect();
        if options.json {
            return write_json(out, &found);
        }
        writeln!(out, "{:<18} {:>8}  name", "address", "size")?;
        for function in &found {
            writeln!(out, "{:#018x} {:>8}  {}", function.address, function.size, function.name)?;
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
    let rows = project.xrefs(query, None, None)?.items;
    if options.json {
        return write_json(out, &rows);
    }
    for row in &rows {
        let kind = row.kind.as_str();
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

pub fn rename(out: &mut impl Write, path: &Path, at: &str, name: Option<&str>, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let result = project.rename(project.resolve(at)?, name)?;
    write_edit(out, &result, options)
}

pub fn comment(out: &mut impl Write, path: &Path, at: &str, text: Option<&str>, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let result = project.comment(project.resolve(at)?, text)?;
    write_edit(out, &result, options)
}

fn write_edit(out: &mut impl Write, result: &EditResult, options: &Options) -> Result<()> {
    if options.json {
        return write_json(out, result);
    }
    let field = match result.field {
        Field::Name => "name",
        Field::Comment => "comment",
    };
    let state = if result.changed { "" } else { " (unchanged)" };
    match &result.value {
        Some(value) => writeln!(out, "{:#018x} {field} {value}{state}", result.address)?,
        None => writeln!(out, "{:#018x} {field} removed{state}", result.address)?,
    }
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
