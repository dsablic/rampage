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

pub fn audit(out: &mut impl Write, path: &Path, include_discovery: bool, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let audit = project.analysis_diagnostics(include_discovery)?;
    if options.json {
        return write_json(out, &audit);
    }
    if let Some(discovery) = &audit.discovery {
        writeln!(
            out,
            "{} discovery candidates (not verified functions); {} tiny (at most {} instructions)",
            discovery.total_candidates, discovery.tiny_candidates, discovery.tiny_instruction_limit
        )?;
        writeln!(
            out,
            "{} candidate entries in flagged samples; {} outside sampled ranges",
            discovery.candidates_in_flagged_sampled_ranges, discovery.candidates_outside_sampled_ranges
        )?;
    }
    for region in audit.regions {
        writeln!(
            out,
            "{:#x} {}: {} invalid of {} sampled instructions; entropy {:.2}",
            region.address, region.name, region.invalid, region.instructions, region.entropy
        )?;
        writeln!(out, "  {}", region.assessment)?;
        if let Some(discovery) = region.discovery {
            writeln!(
                out,
                "  {} candidate entries in this sample; {} tiny",
                discovery.candidates, discovery.tiny_candidates
            )?;
        }
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

pub fn decompile(
    out: &mut impl Write,
    path: &Path,
    at: &str,
    compiler: Option<&str>,
    isolated: bool,
    options: &Options,
) -> Result<()> {
    let project = open(path, options)?;
    if isolated {
        project.set_decompiler_worker(Some(rampage_api::DecompilerWorkerConfig::default()));
    }
    if let Some(compiler) = compiler {
        project.set_decompiler_options(Some(rampage_api::DecompilerOptions {
            compiler: Some(compiler.to_owned()),
            ..Default::default()
        }));
    }
    let decompilation = project.decompile(project.resolve(at)?)?;
    if options.json {
        return write_json(out, &decompilation);
    }
    write!(out, "{}", decompilation.code)?;
    if decompilation.recovery_status != rampage_api::RecoveryStatus::NoReportedIssues {
        writeln!(out, "\n/* Recovery: {} */", decompilation.recovery_status.label())?;
    }
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

pub fn compare_runtime(
    out: &mut impl Write,
    path: &Path,
    original: &Path,
    module: &str,
    ranges: &[String],
    options: &Options,
) -> Result<()> {
    let project = Project::new(rampage_loaders::Binary::open_with(path, options.arch)?);
    let original = rampage_loaders::Binary::open_with(original, Some(project.binary.arch))?;
    let ranges = ranges
        .iter()
        .map(|range| {
            let (address, size) =
                range.split_once(':').ok_or_else(|| anyhow::anyhow!("range requires ADDRESS:SIZE"))?;
            let size =
                size.strip_prefix("0x").map_or_else(|| size.parse::<u64>(), |hex| u64::from_str_radix(hex, 16))?;
            Ok(rampage_api::RuntimeRange { address: project.resolve(address)?, size })
        })
        .collect::<Result<Vec<_>>>()?;
    let result = project.compare_runtime_bytes(module, &original, &ranges)?;
    if options.json {
        return write_json(out, &result);
    }
    writeln!(
        out,
        "{} equal, {} changed, {} unavailable bytes ({} requested)",
        result.equal_bytes, result.changed_bytes, result.unavailable_bytes, result.requested_bytes
    )?;
    for span in result.spans {
        writeln!(
            out,
            "{:#x} -> {:#x}: {} bytes {:?}",
            span.runtime_address, span.image_address, span.size, span.status
        )?;
    }
    for limitation in result.limitations {
        writeln!(out, "note: {limitation}")?;
    }
    Ok(())
}

pub fn observe_pointer(out: &mut impl Write, path: &Path, at: &str, options: &Options) -> Result<()> {
    let project = Project::new(rampage_loaders::Binary::open_with(path, options.arch)?);
    let observation = project.observe_pointer(project.resolve(at)?)?;
    if options.json {
        return write_json(out, &observation);
    }
    writeln!(out, "slot {:#x}, {} bytes: {:?}", observation.slot, observation.pointer_size, observation.assessment)?;
    if let Some(value) = observation.raw_value {
        writeln!(out, "captured raw value: {value:#x}")?;
    }
    if let Some(target) = observation.candidate_target {
        writeln!(out, "code candidate: {target:#x} (not a proven edge)")?;
    }
    for limitation in observation.limitations {
        writeln!(out, "note: {limitation}")?;
    }
    Ok(())
}

pub fn compare_pointers(
    out: &mut impl Write,
    path: &Path,
    other: &Path,
    at: &str,
    other_at: &str,
    options: &Options,
) -> Result<()> {
    let before = Project::new(rampage_loaders::Binary::open_with(path, options.arch)?);
    let after = Project::new(rampage_loaders::Binary::open_with(other, Some(before.binary.arch))?);
    let result = before.compare_pointer_observations(
        rampage_loaders::snapshot::address(at)?,
        &after,
        rampage_loaders::snapshot::address(other_at)?,
    )?;
    if options.json {
        return write_json(out, &result);
    }
    writeln!(
        out,
        "slots {:#x} -> {:#x}: {:?} raw values",
        result.before.slot, result.after.slot, result.raw_value_change
    )?;
    writeln!(
        out,
        "slot permissions changed: {}; target assessment changed: {}",
        result.slot_permissions_changed, result.target_assessment_changed
    )?;
    for limitation in result.limitations {
        writeln!(out, "note: {limitation}")?;
    }
    Ok(())
}

pub fn observe_indirect_branch(
    out: &mut impl Write,
    path: &Path,
    start: &str,
    at: &str,
    options: &Options,
) -> Result<()> {
    let project = Project::new(rampage_loaders::Binary::open_with(path, options.arch)?);
    let observation = project
        .observe_indirect_branch(rampage_loaders::snapshot::address(start)?, rampage_loaders::snapshot::address(at)?)?;
    if options.json {
        return write_json(out, &observation);
    }
    writeln!(out, "{:#x}: {} ({:?})", observation.branch_address, observation.branch_text, observation.slot_status)?;
    if let Some(pointer) = observation.pointer {
        writeln!(
            out,
            "linked slot: {:#x}; captured value: {:?} (not a proven edge)",
            pointer.slot,
            pointer.raw_value.map(|value| format!("{value:#x}"))
        )?;
    }
    for limitation in observation.limitations {
        writeln!(out, "note: {limitation}")?;
    }
    Ok(())
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
    if let Some(identity) = &triage.capture_identity {
        writeln!(out, "capture   {} ({})", identity.sha256, identity.schema)?;
    }
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
        Field::Signature => "signature",
        Field::Types => "types",
        Field::Global => "global",
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
    for annotation in &list.signatures {
        writeln!(out, "{:#018x} signature {}", annotation.address, annotation.text)?;
    }
    for annotation in &list.types {
        writeln!(out, "{:#018x} types {}", annotation.address, annotation.text)?;
    }
    for annotation in &list.globals {
        writeln!(out, "{:#018x} global {}", annotation.address, annotation.text)?;
    }
    Ok(())
}

pub fn debug_types(out: &mut impl Write, path: &Path, apply: bool, options: &Options) -> Result<()> {
    let result = open(path, options)?.import_debug_signatures(apply)?;
    if options.json {
        return write_json(out, &result);
    }
    for signature in result.preview.signatures {
        writeln!(out, "{:#x} {}", signature.address, signature.declaration)?;
    }
    for warning in result.preview.warnings {
        writeln!(out, "warning: {warning}")?;
    }
    writeln!(out, "applied {}, preserved {}", result.applied.len(), result.preserved.len())?;
    Ok(())
}

pub fn signatures(out: &mut impl Write, path: &Path, output: Option<&Path>, options: &Options) -> Result<()> {
    let database = open(path, options)?.build_signatures();
    let json = database.to_json();
    if let Some(output) = output {
        std::fs::write(output, &json)?;
        writeln!(out, "wrote {} signatures to {}", database.len(), output.display())?;
    } else {
        writeln!(out, "{json}")?;
    }
    Ok(())
}

fn load_signature_database(db: &Path) -> Result<rampage_api::SignatureDb> {
    if !std::fs::symlink_metadata(db)?.is_file() {
        anyhow::bail!("signature database must be a regular JSON file");
    }
    let file = std::fs::File::open(db)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(file, 256 * 1024 * 1024 + 1), &mut bytes)?;
    if bytes.len() > 256 * 1024 * 1024 {
        anyhow::bail!("signature database exceeds 256 MiB");
    }
    Ok(rampage_api::SignatureDb::from_json(std::str::from_utf8(&bytes)?)?)
}

pub fn identify(
    out: &mut impl Write,
    path: &Path,
    db: Option<&Path>,
    no_bundled: bool,
    apply: bool,
    options: &Options,
) -> Result<()> {
    if no_bundled && db.is_none() {
        anyhow::bail!("--no-bundled needs a --db to apply");
    }
    let user = match db {
        Some(db) => Some(load_signature_database(db)?),
        None => None,
    };
    let project = open(path, options)?;
    let result = if no_bundled {
        project.apply_signatures(user.as_ref().expect("checked above"), apply)?
    } else {
        project.apply_signatures_default(user.as_ref(), apply)?
    };
    if options.json {
        return write_json(out, &result);
    }
    writeln!(out, "{} matched, {} applied", result.matched, result.applied)?;
    for item in result.matches {
        let mark = if item.unnamed { "" } else { " (already named)" };
        writeln!(out, "{:#x}  {}{}", item.address, item.name, mark)?;
    }
    Ok(())
}

pub fn capabilities(out: &mut impl Write, path: &Path, options: &Options) -> Result<()> {
    let capabilities = open(path, options)?.capabilities();
    if options.json {
        return write_json(out, &capabilities);
    }
    if capabilities.is_empty() {
        writeln!(out, "no capabilities detected")?;
    }
    for capability in capabilities {
        writeln!(out, "[{}] {} ({})", capability.category, capability.name, capability.evidence.join(", "))?;
    }
    Ok(())
}
