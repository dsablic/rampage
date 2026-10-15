use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use rampage_analysis::functions;
use rampage_analysis::strings::Encoding;
use rampage_api::{
    Capability, ContentStatus, EditResult, FunctionsQuery, ListQuery, PackInfo, Packs, Project, Session, StringsQuery,
    XrefQuery, label,
};
use rampage_arch::Arch;
use rampage_loaders::Details;
use rampage_loaders::dotnet::EntryPoint;
use serde::Serialize;

pub struct Options {
    pub json: bool,
    pub arch: Option<Arch>,
    /// Where the executable to open lies inside the file, for one embedded in a larger file.
    pub image: Option<rampage_loaders::ImageAt>,
    pub packs: Arc<Packs>,
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
    for class in &metadata.objc.classes {
        let superclass = class.superclass.as_deref().map(|name| format!(" : {name}")).unwrap_or_default();
        writeln!(out, "{:#x} objc_class {}{superclass}", class.address, class.name)?;
    }
    for category in &metadata.objc.categories {
        let class = category.class.as_deref().unwrap_or("?");
        writeln!(out, "{:#x} objc_category {class}({})", category.address, category.name)?;
    }
    let classes = metadata.objc.classes.iter().map(|class| &class.methods);
    for method in classes.chain(metadata.objc.categories.iter().map(|category| &category.methods)).flatten() {
        if let Some(address) = method.implementation {
            writeln!(out, "{address:#x} objc_method {}", method.name)?;
        }
    }
    for warning in &metadata.objc.warnings {
        writeln!(out, "warning: {warning}")?;
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

pub fn archive_inventory(
    out: &mut impl Write,
    path: &Path,
    query: &rampage_api::ArchiveQuery,
    options: &Options,
) -> Result<()> {
    let page = rampage_api::archive_inventory(path, query)?;
    if options.json {
        serde_json::to_writer(&mut *out, &page)?;
        return Ok(());
    }
    writeln!(out, "ZIP32 central-directory metadata evidence: {}", path.display())?;
    writeln!(out, "metadata SHA-256: {} (not whole-payload identity)", page.archive_ref.metadata_sha256)?;
    writeln!(
        out,
        "{} declared, {} examined, {} validated directory records; {} matched, {} returned",
        page.declared, page.examined, page.validated, page.matched, page.returned
    )?;
    for member in &page.members {
        writeln!(
            out,
            "#{} name={} raw_hex={}{} method={} flags={:#x} compressed={} uncompressed={} local_offset={:#x}",
            member.member_ref.ordinal,
            serde_json::to_string(&member.name_display)?,
            member.raw_name_hex,
            if member.name_truncated { " [name truncated]" } else { "" },
            member.compression_method,
            member.flags,
            member.compressed_size,
            member.uncompressed_size,
            member.local_header_offset
        )?;
    }
    if let Some(next) = page.next_offset {
        writeln!(out, "more matching metadata; continue with --offset {next}")?;
    }
    for warning in page.warnings {
        writeln!(out, "warning: {warning}")?;
    }
    for limitation in page.limitations {
        writeln!(out, "note: {limitation}")?;
    }
    Ok(())
}

pub fn carve(out: &mut impl Write, path: &Path, max_candidates: usize, options: &Options) -> Result<()> {
    let carving = rampage_api::carve(path, Some(max_candidates))?;
    if options.json {
        return write_json(out, &carving);
    }
    for candidate in &carving.candidates {
        let mut facts = vec![candidate.kind.to_string(), candidate.confidence.to_string()];
        facts.extend(candidate.arch.clone());
        facts.extend(candidate.bits.map(|bits| format!("{bits}-bit")));
        facts.extend(candidate.endianness.map(|endianness| endianness.to_string()));
        facts.extend(candidate.declared_size.map(|size| format!("size {size:#x}")));
        facts.extend(candidate.uncompressed_size.map(|size| format!("uncompressed {size:#x}")));
        facts.extend(candidate.extent.map(|extent| format!("extent {extent:#x}")));
        writeln!(out, "{:#010x} {}", candidate.offset, facts.join(" "))?;
        for slice in &candidate.slices {
            writeln!(out, "  slice {} at {:#x} size {:#x}", slice.arch, slice.offset, slice.size)?;
        }
        for note in &candidate.notes {
            writeln!(out, "  {note}")?;
        }
    }
    writeln!(
        out,
        "{} candidates in {:#x} of {:#x} bytes",
        carving.candidates.len(),
        carving.scanned_bytes,
        carving.file_size
    )?;
    for limitation in &carving.limitations {
        writeln!(out, "note: {limitation}")?;
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

/// The largest comparison reference (JSON) `compare` reads.
const MAX_REFERENCE_BYTES: u64 = 32 * 1024 * 1024;

pub fn compare(out: &mut impl Write, path: &Path, reference: &Path, options: &Options) -> Result<()> {
    let text = rampage_api::read_bounded(reference, MAX_REFERENCE_BYTES, "comparison reference")?;
    let reference: rampage_api::ReferenceAnalysis = serde_json::from_str(&text)?;
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

pub(crate) fn open(path: &Path, options: &Options) -> Result<Arc<Project>> {
    let session = Session::default().with_packs(Arc::clone(&options.packs));
    Ok(session.open_at(path, options.arch, options.image)?)
}

/// The binary at `path`, without its annotations.
fn open_binary(path: &Path, options: &Options) -> Result<rampage_loaders::Binary> {
    Ok(rampage_loaders::Binary::open_image(path, options.image, options.arch)?)
}

pub fn compare_runtime(
    out: &mut impl Write,
    path: &Path,
    original: &Path,
    original_image: Option<rampage_loaders::ImageAt>,
    module: &str,
    ranges: &[String],
    options: &Options,
) -> Result<()> {
    let project = Project::new(open_binary(path, options)?);
    let original = rampage_loaders::Binary::open_image(original, original_image, Some(project.binary.arch))?;
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
    let project = Project::new(open_binary(path, options)?);
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
    let before = Project::new(open_binary(path, options)?);
    let after = before.open_peer(other)?;
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
    let project = Project::new(open_binary(path, options)?);
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
pub(crate) fn write_json(out: &mut impl Write, value: &impl Serialize) -> Result<()> {
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
    if let Some(embedded) = summary.embedded {
        writeln!(out, "embedded  {} bytes at offset {:#x} of the outer file", embedded.size, embedded.offset)?;
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

/// Every function's block starts, intra-function edges, outgoing call and jump references, and the calls that end
/// their block because they never return (with why: `listed` or `inferred`), as JSON.
pub fn export_cfg(out: &mut impl Write, path: &Path, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let hex = |address: u64| format!("{address:#x}");
    let mut functions = Vec::new();
    for row in project.functions(&FunctionsQuery::default())?.items {
        let graph = project.function_graph(row.address)?;
        let blocks: Vec<_> = graph.blocks.iter().map(|block| hex(block.start)).collect();
        let edges: Vec<_> =
            graph.edges.iter().map(|edge| serde_json::json!([blocks[edge.from], blocks[edge.to], edge.kind])).collect();
        let references: Vec<_> = project
            .xrefs(XrefQuery::From(row.address), None, None)?
            .items
            .into_iter()
            .filter(|xref| xref.kind != rampage_analysis::discover::XrefKind::Data)
            .map(|xref| serde_json::json!([hex(xref.from), hex(xref.to), xref.kind]))
            .collect();
        let noreturn_calls: Vec<_> = graph
            .blocks
            .iter()
            .flat_map(|block| &block.lines)
            .filter_map(|line| Some(serde_json::json!([hex(line.address), line.noreturn?])))
            .collect();
        functions.push(serde_json::json!({
            "address": hex(row.address), "blocks": blocks, "edges": edges, "references": references,
            "noreturn_calls": noreturn_calls,
        }));
    }
    write_json(out, &functions)
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
        let whole = if triage.embedded.is_some() { "outer file" } else { "universal binary" };
        writeln!(out, "file      {size} bytes ({whole}), sha256 {}", hashes.sha256)?;
    }
    if let Some(embedded) = triage.embedded {
        writeln!(out, "embedded  at offset {:#x} of the outer file", embedded.offset)?;
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

/// The largest batch file (JSON) `annotate-batch` reads: room for the most entries with long comments.
const MAX_BATCH_BYTES: u64 = 8 * 1024 * 1024;

pub fn annotate_batch(out: &mut impl Write, path: &Path, entries: &Path, options: &Options) -> Result<()> {
    let text = rampage_api::read_bounded(entries, MAX_BATCH_BYTES, "batch file")?;
    let entries: Vec<rampage_api::BatchEntry> = serde_json::from_str(&text).map_err(|error| {
        anyhow::anyhow!("{}: expected a JSON array of {{at, name?, comment?}}: {error}", entries.display())
    })?;
    let result = open(path, options)?.annotate_batch(&entries)?;
    if options.json {
        return write_json(out, &result);
    }
    for entry in &result.entries {
        let state = if entry.changed { "" } else { " (unchanged)" };
        let name = entry.name.as_deref().map(|name| format!(" name {name}")).unwrap_or_default();
        let comment = entry.comment.as_deref().map(|comment| format!(" comment {comment}")).unwrap_or_default();
        writeln!(out, "{:#018x}{name}{comment}{state}", entry.address)?;
    }
    writeln!(out, "{} of {} entries changed", result.changed, result.entries.len())?;
    Ok(())
}

pub fn check_names(out: &mut impl Write, path: &Path, names: &[String], options: &Options) -> Result<()> {
    let checks = open(path, options)?.check_names(names)?;
    if options.json {
        return write_json(out, &checks);
    }
    for check in &checks {
        let verdict = match (&check.problem, check.used_at) {
            (Some(problem), _) => format!("invalid: {problem}"),
            (None, Some(at)) => format!("used by {} at {at:#x}", check.used_by.unwrap_or("symbol")),
            (None, None) => "free".to_owned(),
        };
        writeln!(out, "{}  {verdict}", check.name)?;
    }
    Ok(())
}

fn write_edit(out: &mut impl Write, result: &EditResult, options: &Options) -> Result<()> {
    if options.json {
        return write_json(out, result);
    }
    let field = label(&result.field);
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

pub fn import_debug_layouts(
    out: &mut impl Write,
    args: &crate::args::ImportDebugLayoutsArgs,
    options: &Options,
) -> Result<()> {
    let input = serde_json::json!({
        "apply": args.apply, "review_sha256": args.review_sha256, "offset": args.offset, "limit": args.limit,
    });
    let result = (|| -> Result<(String, bool)> {
        rampage_api::tools::validate_debug_layout_arguments(&input).map_err(anyhow::Error::msg)?;
        let project = open(&args.file, options)?;
        Ok(rampage_api::tools::call(&rampage_api::tools::tools(), &project, "import_debug_layouts", input))
    })();
    let (text, failed) = match result {
        Ok(result) => result,
        Err(error) => (rampage_api::tools::debug_layout_import_error(&format!("{error:#}"), Some(args.apply)), true),
    };
    let receipt: serde_json::Value = serde_json::from_str(&text).map_err(|error| {
        anyhow::anyhow!("debug layout result decoding failed after the operation; do not assume no action: {error}")
    })?;
    write_debug_layout_receipt(out, &text, &receipt, options.json)?;
    if failed {
        anyhow::bail!("{}", receipt["error"].as_str().unwrap_or("debug layout import rejected; nothing imported"));
    }
    Ok(())
}

fn write_debug_layout_receipt(out: &mut impl Write, text: &str, receipt: &serde_json::Value, json: bool) -> Result<()> {
    let result = (|| -> Result<()> {
        if json {
            out.write_all(text.as_bytes())?;
        } else {
            render_debug_layout_receipt(out, receipt)?;
        }
        out.flush()?;
        Ok(())
    })();
    result.map_err(|error| {
        anyhow::anyhow!(
            "debug layout output failed (status={}, whole_apply_succeeded={}, \
             applied_total={}, imported_types_total={}): {error}",
            receipt["status"].as_str().unwrap_or("unknown"),
            receipt["whole_apply_succeeded"],
            receipt["applied_total"],
            receipt["imported_types_total"]
        )
    })
}

fn render_debug_layout_receipt(out: &mut impl Write, receipt: &serde_json::Value) -> Result<()> {
    match receipt["status"].as_str() {
        Some("preview") => writeln!(out, "preview only; annotations unchanged")?,
        Some("applied") => {
            writeln!(out, "whole apply succeeded; complete checked dependency batch applied atomically")?
        }
        _ => writeln!(out, "import rejected; whole apply did not succeed; nothing imported")?,
    }
    for key in ["review_sha256", "image_sha256", "compiler_spec_sha256"] {
        if let Some(hash) = receipt[key].as_str() {
            writeln!(out, "{key}: {hash}")?;
        }
    }
    if receipt["ok"] == true {
        writeln!(
            out,
            "{} review types, {} fields, {} functions; {} approved, {} applied, {} preserved; {} imported types",
            receipt["types_total"],
            receipt["fields_total"],
            receipt["functions_total"],
            receipt["approved_total"],
            receipt["applied_total"],
            receipt["preserved_total"],
            receipt["imported_types_total"]
        )?;
        writeln!(
            out,
            "{} checked warnings; producer-only evidence: {} types, {} fields, {} functions, {} warnings",
            receipt["warnings_total"],
            receipt["producer_types_total"],
            receipt["producer_fields_total"],
            receipt["producer_functions_total"],
            receipt["producer_warnings_total"]
        )?;
    }
    if let Some(details) = receipt["details"].as_array() {
        for row in details {
            let source = row["source"].as_str().unwrap_or("unknown source");
            let status = row["status"].as_str().unwrap_or("evidence");
            let data = &row["data"];
            match row["kind"].as_str() {
                Some("warning") => {
                    writeln!(out, "warning ({source}): {}", row["text"].as_str().unwrap_or("<unreadable warning>"))?;
                }
                Some("type") => {
                    let name = data["layout"]["name"].as_str().or_else(|| data["emitted_name"].as_str());
                    writeln!(out, "type {} [{source}/{status}] {data}", name.unwrap_or("<unreadable type>"))?;
                }
                Some("field") => {
                    let name = data["name"].as_str().or_else(|| data["emitted_name"].as_str());
                    writeln!(
                        out,
                        "  field {}.{} +{} [{source}/{status}] {data}",
                        row["type_name"].as_str().unwrap_or("?"),
                        name.unwrap_or("?"),
                        data["offset"]
                    )?;
                }
                Some("function") => {
                    writeln!(
                        out,
                        "{} {} [{source}/{status}]",
                        data["address"].as_str().unwrap_or("?"),
                        data["declaration"].as_str().unwrap_or("?")
                    )?;
                    writeln!(out, "  evidence: {data}")?;
                }
                Some("parameter") => writeln!(out, "  parameter [{source}/{status}] {data}")?,
                Some("projection") => {
                    writeln!(
                        out,
                        "opaque consumer storage projection for {} [{source}/{status}]: {data}",
                        row["type_name"].as_str().unwrap_or("?")
                    )?;
                    writeln!(
                        out,
                        "  void pointer is storage only; producer pointer -> pointer -> subroutine roles \
                         do not claim an exact void pointer or callback type; null facts remain unknown"
                    )?;
                }
                Some("vtable") => {
                    writeln!(
                        out,
                        "raw named table {} [{source}/{status}], header {}, confidence {}: {data}",
                        row["table_address"].as_str().unwrap_or("?"),
                        data["header"],
                        data["confidence"]
                    )?;
                    writeln!(
                        out,
                        "  unverified prefixes imply candidate slot positions only; \
                         unknown offset-to-top is not inferred; no object-vptr or table-owner proof"
                    )?;
                }
                Some("vtable_slot") => writeln!(
                    out,
                    "  candidate slot {} of table {} [{source}/{status}], raw target {}: {data}",
                    data["index"],
                    row["table_address"].as_str().unwrap_or("?"),
                    data["target"]
                )?,
                Some("virtual_method") => {
                    writeln!(
                        out,
                        "  exact method entry {} at table {} / candidate slot {}, declared virtual slot {} \
                         [{source}/{status}]: {data}",
                        data["method_address"].as_str().unwrap_or("?"),
                        row["table_address"].as_str().unwrap_or("?"),
                        data["slot_index"],
                        data["declared_virtual_slot_index"]
                    )?;
                    writeln!(
                        out,
                        "  native-checked source association only; not applied/current analyst types, \
                         authorization or a resolved virtual-call target"
                    )?;
                }
                Some("limitation") => {
                    writeln!(out, "limitation ({source}/{status}): {}", row["text"].as_str().unwrap_or("?"))?;
                }
                _ => writeln!(out, "<unreadable debug layout evidence>")?,
            }
        }
        if receipt["ok"] == true {
            writeln!(
                out,
                "{} of {} evidence rows shown, starting at offset {} (pages never select writes)",
                details.len(),
                receipt["details_total"],
                receipt["offset"]
            )?;
        }
    }
    if receipt["byte_capped"] == true {
        writeln!(out, "evidence page byte-capped; whole review hash and operation counts retained")?;
    }
    if let Some(next) = receipt["next_offset"].as_u64() {
        writeln!(
            out,
            "more evidence: --offset {next} --limit {} (omit --apply and --review-sha256)",
            receipt["limit"]
        )?;
    }
    if let Some(hash) = receipt["review_sha256"].as_str() {
        if receipt["status"] == "preview" {
            writeln!(out, "to apply the complete reviewed batch: --apply --review-sha256 {hash}")?;
        }
        writeln!(out, "hash binds all reviewed evidence, not just this page; changes require re-review")?;
        writeln!(out, "undo is same-process only; it is not recovered after CLI exit")?;
    }
    if let Some(error) = receipt["error"].as_str() {
        writeln!(out, "error: {error}")?;
        if receipt["error_truncated"] == true {
            writeln!(out, "error detail truncated")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod debug_layout_output_tests {
    use std::io::{self, BufWriter, Write};

    use super::write_debug_layout_receipt;

    #[test]
    fn readable_virtual_rows_keep_unknown_projection_facts_candidate_confidence_and_exact_method_entry() {
        let receipt = serde_json::json!({
            "status": "preview", "details": [
                {
                    "kind": "projection", "source": "virtual_evidence", "status": "read_only",
                    "type_name": "opaque_record", "data": {
                        "kind": "opaque_vptr", "pointer_byte_size": null, "member_alignment": null,
                        "pointer_id": { "unit_offset": 0, "die_offset": 3 },
                        "pointee_pointer_id": { "unit_offset": 0, "die_offset": 4 },
                        "subroutine_id": { "unit_offset": 0, "die_offset": 5 },
                    },
                },
                {
                    "kind": "vtable", "source": "virtual_evidence", "status": "read_only",
                    "table_address": "0x800000", "data": {
                        "header": "unverified_prefix", "confidence": "raw_named_vtable_evidence",
                        "offset_to_top": null, "raw_offset_word": "0xfffffffffffffff8",
                        "scan_limit": "0x800020", "scan_end": "0x800018", "stop": "non_function",
                    },
                },
                {
                    "kind": "vtable_slot", "source": "virtual_evidence", "status": "read_only",
                    "table_address": "0x800000", "data": {
                        "index": 7, "address": "0x800048", "raw_value": "0x400030", "target": "0x400030",
                    },
                },
                {
                    "kind": "virtual_method", "source": "virtual_evidence", "status": "read_only",
                    "table_address": "0x800000", "data": {
                        "slot_index": 7, "declared_virtual_slot_index": 7, "method_address": "0x400030",
                        "verification": "native_checked_source_evidence", "linkage_name": "misleading\"λ",
                    },
                },
                { "kind": "warning", "source": "virtual_evidence", "status": "read_only", "text": "raw warning" },
                {
                    "kind": "limitation", "source": "virtual_evidence", "status": "read_only",
                    "text": "not virtual-call targets",
                },
            ],
        });
        let mut output = Vec::new();
        super::render_debug_layout_receipt(&mut output, &receipt).unwrap();
        let output = String::from_utf8(output).unwrap();
        for text in [
            "opaque consumer storage projection for opaque_record",
            "void pointer is storage only",
            "pointer -> pointer -> subroutine",
            "null facts remain unknown",
            "raw_named_vtable_evidence",
            "unverified_prefix",
            "0xfffffffffffffff8",
            "0x800020",
            "non_function",
            "candidate slot 7 of table 0x800000",
            "exact method entry 0x400030",
            "declared virtual slot 7",
            "native_checked_source_evidence",
            "not applied/current analyst types",
            "warning (virtual_evidence): raw warning",
            "limitation (virtual_evidence/read_only): not virtual-call targets",
        ] {
            assert!(output.contains(text), "{text}: {output}");
        }
        assert!(!output.contains("<unreadable debug layout evidence>"), "{output}");
    }

    #[derive(Default)]
    struct FlushFailure {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl Write for FlushFailure {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Err(io::Error::other("simulated flush failure"))
        }
    }

    #[test]
    fn buffered_flush_failure_reports_committed_apply_status_for_json_and_readable_output() {
        let receipt = serde_json::json!({
            "ok": true, "status": "applied", "apply_requested": true, "whole_apply_succeeded": true,
            "types_total": 1, "fields_total": 6, "functions_total": 9, "approved_total": 9,
            "applied_total": 9, "preserved_total": 0, "imported_types_total": 1,
            "warnings_total": 0, "producer_types_total": 1, "producer_fields_total": 6,
            "producer_functions_total": 9, "producer_warnings_total": 0, "details": [],
        });
        let text = receipt.to_string();
        for json in [true, false] {
            let mut out = BufWriter::new(FlushFailure::default());
            let error = write_debug_layout_receipt(&mut out, &text, &receipt, json).unwrap_err().to_string();
            assert_eq!(out.get_ref().flushes, 1);
            assert!(!out.get_ref().bytes.is_empty(), "all writes succeeded before the flush failed");
            for phrase in [
                "status=applied",
                "whole_apply_succeeded=true",
                "applied_total=9",
                "imported_types_total=1",
                "simulated flush failure",
            ] {
                assert!(error.contains(phrase), "{phrase}: {error}");
            }
            assert!(!error.contains("nothing imported"), "{error}");
            assert!(!error.contains("no action"), "{error}");
            if json {
                assert_eq!(out.get_ref().bytes, text.as_bytes());
            } else {
                let output = std::str::from_utf8(&out.get_ref().bytes).unwrap();
                assert!(output.contains("whole apply succeeded"), "{output}");
            }
        }
    }
}

pub fn import_pdb_names(out: &mut impl Write, args: &crate::args::ImportPdbNamesArgs, options: &Options) -> Result<()> {
    let result = serde_json::to_value(&args.pdb)
        .map_err(|error| {
            anyhow::anyhow!(
                "explicit PDB path cannot be represented as UTF-8 in shared JSON: {error}; nothing imported"
            )
        })
        .and_then(|pdb| {
            let project = open(&args.file, options)?;
            Ok(rampage_api::tools::call(
                &rampage_api::tools::tools(),
                &project,
                "import_pdb_names",
                serde_json::json!({
                    "pdb": pdb,
                    "apply": args.apply,
                    "offset": args.offset,
                    "limit": args.limit,
                }),
            ))
        });
    let (text, failed) = match result {
        Ok(result) => result,
        Err(error) => (rampage_api::tools::pdb_import_error(&format!("{error:#}"), Some(args.apply)), true),
    };
    let receipt: serde_json::Value = serde_json::from_str(&text)?;
    if options.json {
        out.write_all(text.as_bytes())?;
    } else {
        render_pdb_receipt(out, &receipt)?;
    }
    if failed {
        out.flush()?;
        anyhow::bail!("{}", receipt["error"].as_str().unwrap_or("PDB import rejected; nothing imported"));
    }
    Ok(())
}

fn render_pdb_receipt(out: &mut impl Write, receipt: &serde_json::Value) -> Result<()> {
    if let Some(guid) = receipt["identity"]["guid"].as_str() {
        writeln!(out, "PDB identity: GUID {guid}, age {}", receipt["identity"]["age"])?;
    }
    match receipt["status"].as_str() {
        Some("preview") => writeln!(out, "preview only; annotations unchanged (whole apply not requested)")?,
        Some("applied") => {
            writeln!(out, "whole apply succeeded; all eligible names applied as one atomic annotation batch")?
        }
        _ => writeln!(out, "import rejected; whole apply did not succeed; no names applied")?,
    }
    if !receipt["preview_total"].is_null() {
        writeln!(
            out,
            "{} preview functions, {} applied, {} preserved, {} warnings",
            receipt["preview_total"], receipt["applied_total"], receipt["preserved_total"], receipt["warnings_total"]
        )?;
    }
    if let Some(details) = receipt["details"].as_array() {
        for detail in details {
            match detail["kind"].as_str() {
                Some("function") => {
                    let address = detail["address"].as_str().unwrap_or("<unreadable address>");
                    let name = detail["name"].as_str().unwrap_or("<unreadable name>");
                    let status = detail["status"].as_str().unwrap_or("unreadable status");
                    writeln!(out, "{address} {name} [{status}]")?;
                    if detail["name_truncated"] == true {
                        writeln!(out, "  name truncated ({} bytes in full name)", detail["name_bytes"])?;
                    }
                }
                Some("warning") => {
                    writeln!(out, "warning: {}", detail["text"].as_str().unwrap_or("<unreadable warning>"))?;
                    if detail["text_truncated"] == true {
                        writeln!(out, "  warning truncated ({} bytes in full warning)", detail["text_bytes"])?;
                    }
                }
                _ => writeln!(out, "<unreadable PDB detail>")?,
            }
        }
        if let Some(total) = receipt["details_total"].as_u64() {
            writeln!(
                out,
                "{} of {total} details shown, starting at offset {} (details do not select writes)",
                details.len(),
                receipt["offset"]
            )?;
        }
    }
    if receipt["byte_capped"] == true {
        writeln!(out, "details byte-capped to keep the receipt bounded")?;
    }
    if let Some(next) = receipt["next_offset"].as_u64() {
        writeln!(out, "more details: --offset {next} --limit {}", receipt["limit"])?;
    }
    if let Some(error) = receipt["error"].as_str() {
        writeln!(out, "error: {error}")?;
        if receipt["error_truncated"] == true {
            writeln!(out, "error detail truncated")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod pdb_receipt_tests {
    use super::render_pdb_receipt;

    #[test]
    fn human_receipt_keeps_truncation_paging_and_unreadable_details_visible() {
        let receipt = serde_json::json!({
            "status": "preview",
            "identity": { "guid": "1234", "age": 7 },
            "preview_total": 3,
            "applied_total": 0,
            "preserved_total": 1,
            "warnings_total": 2,
            "details_total": 5,
            "offset": 1,
            "limit": 4,
            "details": [
                { "kind": "function", "address": "0x1000", "name": "partial",
                  "status": "eligible", "name_truncated": true, "name_bytes": 3000 },
                { "kind": "warning", "text": "unreadable symbol", "text_truncated": true, "text_bytes": 4000 },
                { "kind": "unrecognized" },
            ],
            "byte_capped": true,
            "next_offset": 4,
            "error": "partial error",
            "error_truncated": true,
        });
        let mut output = Vec::new();
        render_pdb_receipt(&mut output, &receipt).unwrap();
        let text = String::from_utf8(output).unwrap();
        for phrase in [
            "preview only",
            "3 preview functions, 0 applied, 1 preserved, 2 warnings",
            "partial [eligible]",
            "name truncated (3000 bytes",
            "warning: unreadable symbol",
            "warning truncated (4000 bytes",
            "<unreadable PDB detail>",
            "details byte-capped",
            "--offset 4 --limit 4",
            "error detail truncated",
        ] {
            assert!(text.contains(phrase), "{phrase}: {text}");
        }
        assert!(!text.contains("whole apply succeeded"), "{text}");
    }
}

pub fn signatures(out: &mut impl Write, path: &Path, output: Option<&Path>, options: &Options) -> Result<()> {
    let database = open(path, options)?.build_signatures();
    let json = database.to_json();
    if let Some(output) = output {
        std::fs::write(output, &json)?;
        let (signatures, callee_keys) = (database.len(), database.callee_keys());
        writeln!(out, "wrote {signatures} signatures and {callee_keys} callee keys to {}", output.display())?;
    } else {
        writeln!(out, "{json}")?;
    }
    Ok(())
}

fn load_signature_database(db: &Path) -> Result<rampage_api::SignatureDb> {
    let text = rampage_api::read_bounded(db, rampage_api::MAX_SIGNATURE_DB_BYTES, "signature database")?;
    Ok(rampage_api::SignatureDb::from_json(&text)?)
}

pub fn identify(
    out: &mut impl Write,
    path: &Path,
    db: Option<&Path>,
    no_bundled: bool,
    apply: bool,
    options: &Options,
) -> Result<()> {
    let user = match db {
        Some(db) => Some(load_signature_database(db)?),
        None => None,
    };
    let result = open(path, options)?.identify_functions(user.as_ref(), !no_bundled, apply)?;
    if options.json {
        return write_json(out, &result);
    }
    writeln!(out, "{} matched, {} applied", result.matched, result.applied)?;
    for item in result.matches {
        let mark = if item.unnamed { "" } else { " (already named)" };
        writeln!(out, "{:#x}  {}{}  [{}]", item.address, item.name, mark, item.source)?;
    }
    Ok(())
}

pub fn capabilities(out: &mut impl Write, path: &Path, options: &Options) -> Result<()> {
    let capabilities = open(path, options)?.capabilities();
    render_capabilities(out, &capabilities, "no capabilities detected", options)
}

/// Capabilities as JSON, or one `[category] name (evidence)` line each, or `empty` when there are none.
fn render_capabilities(
    out: &mut impl Write,
    capabilities: &[Capability],
    empty: &str,
    options: &Options,
) -> Result<()> {
    if options.json {
        return write_json(out, &capabilities);
    }
    if capabilities.is_empty() {
        writeln!(out, "{empty}")?;
    }
    for capability in capabilities {
        writeln!(out, "[{}] {} ({})", capability.category, capability.name, capability.evidence.join(", "))?;
    }
    Ok(())
}

pub fn dotnet(out: &mut impl Write, path: &Path, query: &rampage_api::DotNetQuery, options: &Options) -> Result<()> {
    let Some(summary) = open(path, options)?.dotnet_metadata(query)? else {
        if options.json {
            return write_json(out, &serde_json::Value::Null);
        }
        writeln!(out, "not a .NET assembly (no CLI header)")?;
        return Ok(());
    };
    if options.json {
        return write_json(out, &summary);
    }
    if let Some(assembly) = &summary.assembly {
        writeln!(out, "assembly   {} {}", assembly.name, assembly.version)?;
    }
    if let Some(module) = &summary.module {
        let mvid = module.mvid.as_deref().map(|mvid| format!(" (mvid {mvid})")).unwrap_or_default();
        writeln!(out, "module     {}{mvid}", module.name)?;
    }
    match &summary.entry_point {
        Some(EntryPoint::Method { token, method }) => {
            writeln!(out, "entry      {} (token {token:#x})", method.as_deref().unwrap_or("unresolved method"))?
        }
        Some(EntryPoint::File { token }) => writeln!(out, "entry      in another module (file token {token:#x})")?,
        Some(EntryPoint::Native { rva }) => writeln!(out, "entry      native code at RVA {rva:#x}")?,
        None => writeln!(out, "entry      none")?,
    }
    let cli = &summary.cli;
    writeln!(out, "runtime    {} (CLI {}.{})", summary.runtime_version, cli.runtime_major, cli.runtime_minor)?;
    for reference in &summary.assembly_refs {
        writeln!(out, "references {} {}", reference.name, reference.version)?;
    }
    let counts = &summary.counts;
    let resource_count = dotnet_resource_count_text(
        counts.resources,
        summary.resource_counts.declared_known,
        summary.resource_counts.truncated,
    );
    writeln!(
        out,
        concat!(
            "{} types, {} methods ({} IL, {} native), {} properties, {} events, ",
            "{} P/Invoke imports, {} attributes, {}"
        ),
        counts.types,
        counts.methods,
        counts.il_methods,
        counts.native_methods,
        counts.properties,
        counts.events,
        counts.pinvokes,
        counts.custom_attributes,
        resource_count
    )?;
    let list = label(&summary.list);
    if let Some(types) = &summary.types {
        dotnet_types(out, types)?;
        more_hint(out, types, "types", &list)?;
    }
    if let Some(pinvokes) = &summary.pinvokes {
        dotnet_pinvokes(out, pinvokes)?;
        more_hint(out, pinvokes, "P/Invoke imports", &list)?;
    }
    if let Some(attributes) = &summary.custom_attributes {
        dotnet_attributes(out, attributes)?;
        more_hint(out, attributes, "attributes", &list)?;
    }
    if let Some(resources) = &summary.resources {
        dotnet_resource_inventory(out, &summary)?;
        dotnet_resources(out, resources)?;
        more_hint(out, resources, "resources", &list)?;
    }
    for warning in &summary.warnings {
        writeln!(out, "warning: {warning}")?;
    }
    Ok(())
}

pub fn dotnet_il(
    out: &mut impl Write,
    path: &Path,
    query: &rampage_api::DotNetIlQuery,
    options: &Options,
) -> Result<()> {
    let Some(il) = open(path, options)?.dotnet_il(query)? else {
        if options.json {
            return write_json(out, &serde_json::Value::Null);
        }
        writeln!(out, "not a .NET assembly (no CLI header)")?;
        return Ok(());
    };
    if options.json {
        return write_json(out, &il);
    }
    writeln!(out, "method     {} (token {:#010x})", il.method, il.token)?;
    writeln!(out, "signature  {}", il.signature)?;
    writeln!(
        out,
        "body       {} header, {} bytes of IL at RVA {:#x}, max stack {}",
        label(&il.body.header),
        il.body.code_size,
        il.rva,
        il.body.max_stack
    )?;
    if !il.locals.is_empty() {
        let locals: Vec<String> =
            il.locals.iter().enumerate().map(|(index, ty)| format!("[{index}] {ty} V_{index}")).collect();
        let init = if il.init_locals { "init " } else { "" };
        writeln!(out, ".locals {init}({})", locals.join(", "))?;
    }
    if il.locals_truncated {
        writeln!(out, "... {} more locals not listed", il.locals_total - il.locals.len())?;
    }
    for clause in &il.exception_clauses {
        writeln!(out, "{}", clause.text())?;
    }
    writeln!(out)?;
    for instruction in &il.instructions.items {
        writeln!(out, "{}", instruction.text())?;
    }
    let page = &il.instructions;
    let shown = page.offset + page.items.len();
    if shown < page.total {
        writeln!(
            out,
            "\n... {} more instructions (page with --il {} --offset {shown})",
            page.total - shown,
            query.method
        )?;
    }
    if il.truncated {
        writeln!(out, "listing truncated before the end of the body")?;
    }
    for warning in &il.warnings {
        writeln!(out, "warning: {warning}")?;
    }
    Ok(())
}

fn dotnet_types(out: &mut impl Write, types: &rampage_api::Page<rampage_loaders::dotnet::TypeDef>) -> Result<()> {
    if types.items.is_empty() {
        writeln!(out, "\nno types match")?;
    }
    for ty in &types.items {
        let base = ty.extends.as_deref().map(|base| format!(" : {base}")).unwrap_or_default();
        writeln!(out, "\n{}{base}", ty.full_name())?;
        for field in &ty.fields {
            if let Some(constant) = &field.enum_constant {
                writeln!(
                    out,
                    "  metadata enum constant {} (token {:#010x}): {} {}",
                    field.name, field.token, constant.underlying_integral_type, constant.value
                )?;
            }
        }
        for method in &ty.methods {
            let body = match &method.il {
                Some(il) => format!("{} bytes of IL at {:#x}", il.code_size, method.rva),
                None => label(&method.body),
            };
            let names =
                if method.params.is_empty() { String::new() } else { format!("  [{}]", method.params.join(", ")) };
            writeln!(out, "  {}{names}  {body}", method_text(method))?;
        }
        for property in &ty.properties {
            let signature = if property.signature == rampage_loaders::dotnet::UNREADABLE {
                format!("{}(...) <unreadable signature>", property.name)
            } else {
                property.signature.clone()
            };
            writeln!(out, "  property {signature} (token {:#010x})", property.token)?;
            for accessor in &property.accessors {
                writeln!(
                    out,
                    "    metadata accessor {:#010x}, semantics {:#x}",
                    accessor.method_token, accessor.semantics
                )?;
            }
        }
        for event in &ty.events {
            writeln!(
                out,
                "  event {} {} (token {:#010x}, flags {:#x})",
                event.event_type, event.name, event.token, event.flags
            )?;
            for accessor in &event.accessors {
                writeln!(
                    out,
                    "    metadata accessor {:#010x}, semantics {:#x}",
                    accessor.method_token, accessor.semantics
                )?;
            }
        }
    }
    Ok(())
}

/// A method's rendered signature, or its name when the signature blob could not be decoded.
fn method_text(method: &rampage_loaders::dotnet::MethodDef) -> String {
    if method.signature == rampage_loaders::dotnet::UNREADABLE {
        format!("{}(...) <unreadable signature>", method.name)
    } else {
        method.signature.clone()
    }
}

fn dotnet_pinvokes(out: &mut impl Write, pinvokes: &rampage_api::Page<rampage_loaders::dotnet::PInvoke>) -> Result<()> {
    writeln!(out)?;
    if pinvokes.items.is_empty() {
        writeln!(out, "no P/Invoke imports match")?;
    }
    for pinvoke in &pinvokes.items {
        let module = pinvoke.module.as_deref().unwrap_or("?");
        let method = pinvoke.method.as_deref().unwrap_or("unresolved method");
        writeln!(out, "pinvoke    {module}!{} <- {method}", pinvoke.import_name)?;
    }
    Ok(())
}

fn dotnet_attributes(
    out: &mut impl Write,
    attributes: &rampage_api::Page<rampage_loaders::dotnet::CustomAttribute>,
) -> Result<()> {
    writeln!(out)?;
    if attributes.items.is_empty() {
        writeln!(out, "no attributes match")?;
    }
    for attribute in &attributes.items {
        let arguments = match &attribute.arguments {
            Some(arguments) => format!("({})", arguments.join(", ")),
            None => format!(" ({} byte value, not decoded)", attribute.blob_length),
        };
        let attribute_type = attribute.attribute_type.as_deref().unwrap_or("unresolved type");
        let parent = attribute.parent.as_deref().unwrap_or("unresolved target");
        writeln!(out, "attribute  [{attribute_type}{arguments}] on {parent}")?;
        if let Some(named) = &attribute.named_arguments {
            for argument in named {
                writeln!(
                    out,
                    "  {} {} {} = {}",
                    label(&argument.kind),
                    argument.argument_type,
                    serde_json::to_string(&argument.name)?,
                    argument.value
                )?;
            }
        }
        if let Some(error) = &attribute.arguments_error {
            writeln!(out, "  unreadable arguments: {error}")?;
        }
    }
    Ok(())
}

fn dotnet_resource_count_text(retained: usize, declared_known: bool, truncated: bool) -> String {
    if !declared_known {
        format!("{retained} retained resource rows (declared count unknown)")
    } else if truncated {
        format!("{retained} retained resource rows (inventory truncated)")
    } else {
        format!("{retained} resources")
    }
}

fn dotnet_resource_inventory(out: &mut impl Write, summary: &rampage_api::DotNetSummary) -> Result<()> {
    let counts = &summary.resource_counts;
    let declared = if counts.declared_known { counts.declared.to_string() } else { "unknown".to_owned() };
    writeln!(
        out,
        "\nresource metadata: {declared} declared, {} readable rows, {} retained, {} returned",
        counts.readable, counts.retained, counts.returned
    )?;
    if counts.truncated {
        writeln!(out, "resource inventory or name text truncated by metadata/work limits")?;
    }
    Ok(())
}

fn dotnet_resources(
    out: &mut impl Write,
    resources: &rampage_api::Page<rampage_loaders::dotnet::ManifestResource>,
) -> Result<()> {
    use rampage_loaders::dotnet::ResourceAvailability;

    writeln!(out, "metadata links only; resource lengths/payload extents not validated; no external files read")?;
    if resources.items.is_empty() {
        writeln!(out, "no retained resource rows on this page")?;
    }
    for resource in &resources.items {
        let name = resource.name.as_deref().unwrap_or("<unreadable name>");
        writeln!(
            out,
            "resource {:#010x} {}: flags {:#x}, offset {:#x}, implementation_raw {:#x}",
            resource.token,
            serde_json::to_string(name)?,
            resource.flags,
            resource.offset,
            resource.implementation_raw
        )?;
        if resource.name_truncated {
            writeln!(out, "  resource name truncated")?;
        }
        dotnet_resource_implementation(out, &resource.implementation)?;
        match &resource.availability {
            ResourceAvailability::Embedded { rva, status } => {
                let rva = rva.map(|rva| format!("{rva:#x}")).unwrap_or_else(|| "unavailable".to_owned());
                writeln!(out, "  availability embedded: RVA {rva}, status {} (location evidence only)", label(status))?;
            }
            ResourceAvailability::External => writeln!(out, "  availability external: metadata link; target not read")?,
            ResourceAvailability::Unavailable => writeln!(out, "  availability unavailable")?,
        }
    }
    Ok(())
}

fn dotnet_resource_implementation(
    out: &mut impl Write,
    implementation: &rampage_loaders::dotnet::ResourceImplementation,
) -> Result<()> {
    use rampage_loaders::dotnet::ResourceImplementation;

    match implementation {
        ResourceImplementation::Embedded => writeln!(out, "  implementation embedded")?,
        ResourceImplementation::File { row, token, status, name, name_truncated, .. }
        | ResourceImplementation::AssemblyRef { row, token, status, name, name_truncated } => {
            let kind =
                if matches!(implementation, ResourceImplementation::File { .. }) { "file" } else { "assembly_ref" };
            let token = token.map(|token| format!("{token:#010x}")).unwrap_or_else(|| "unresolved".to_owned());
            let name = name.as_deref().unwrap_or("<unreadable target name>");
            writeln!(
                out,
                "  implementation {kind}: row {row}, token {token}, status {}, target {}",
                label(status),
                serde_json::to_string(name)?
            )?;
            if *name_truncated {
                writeln!(out, "  target name truncated")?;
            }
            if let ResourceImplementation::File { flags, .. } = implementation {
                match flags {
                    Some(flags) => writeln!(out, "  target File flags {flags:#x}")?,
                    None => writeln!(out, "  target File flags unreadable")?,
                }
            }
        }
        ResourceImplementation::ExportedType { row, token, status } => {
            let token = token.map(|token| format!("{token:#010x}")).unwrap_or_else(|| "unresolved".to_owned());
            writeln!(
                out,
                "  implementation exported_type: row {row}, token {token}, status {} (unsupported resource link)",
                label(status)
            )?;
        }
        ResourceImplementation::Invalid { tag, row } => {
            writeln!(out, "  implementation invalid: reserved tag {tag}, row {row}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod dotnet_resource_tests {
    use rampage_loaders::dotnet::{
        EmbeddedResourceStatus, ManifestResource, ResourceAvailability, ResourceImplementation, ResourceReferenceStatus,
    };

    use super::{dotnet_resource_count_text, dotnet_resource_inventory, dotnet_resources, more_hint};

    #[test]
    fn unknown_declared_resources_are_distinct_from_known_zero_and_keep_truncation_visible() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/bin/Microsoft.Bcl.HashCode.dll");
        let project = rampage_api::Project::new(rampage_loaders::Binary::open(path).unwrap());
        let query = rampage_api::DotNetQuery { list: rampage_api::DotNetList::Resources, ..Default::default() };
        let mut summary = project.dotnet_metadata(&query).unwrap().unwrap();
        let page = rampage_api::Page { total: 0, offset: 0, items: Vec::new() };
        for (declared, declared_known, truncated, expected) in
            [(0, false, true, "unknown declared"), (0, true, false, "0 declared"), (17, true, true, "17 declared")]
        {
            let counts = &mut summary.resource_counts;
            counts.declared = declared;
            counts.declared_known = declared_known;
            counts.readable = 0;
            counts.retained = 0;
            counts.returned = 0;
            counts.truncated = truncated;
            let mut output = Vec::new();
            dotnet_resource_inventory(&mut output, &summary).unwrap();
            dotnet_resources(&mut output, &page).unwrap();
            let text = String::from_utf8(output).unwrap();
            assert!(text.contains(expected), "{text}");
            assert!(text.contains("0 readable rows, 0 retained, 0 returned"), "{text}");
            assert_eq!(text.contains("resource inventory or name text truncated"), truncated, "{text}");
            assert!(text.contains("no retained resource rows on this page"), "{text}");
            assert!(!text.contains("no resources match"), "{text}");
            let count_text = dotnet_resource_count_text(0, declared_known, truncated);
            if !declared_known {
                assert_eq!(count_text, "0 retained resource rows (declared count unknown)");
                assert!(!text.contains("0 declared"), "{text}");
            } else {
                let expected_count =
                    if truncated { "0 retained resource rows (inventory truncated)" } else { "0 resources" };
                assert_eq!(count_text, expected_count);
                assert!(!text.contains("unknown declared"), "{text}");
            }
        }
    }

    #[test]
    fn human_resource_rows_keep_raw_metadata_typed_links_missing_names_and_truncation_visible() {
        let cases: &[(ResourceImplementation, ResourceAvailability, u32, &[&str])] = &[
            (
                ResourceImplementation::Embedded,
                ResourceAvailability::Embedded { rva: Some(0x1234), status: EmbeddedResourceStatus::ReadableLocation },
                0,
                &["implementation embedded", "RVA 0x1234", "status readable_location", "location evidence only"],
            ),
            (
                ResourceImplementation::File {
                    row: 1,
                    token: Some(0x2600_0001),
                    status: ResourceReferenceStatus::Readable,
                    name: Some("Part.netmodule".to_owned()),
                    name_truncated: true,
                    flags: Some(1),
                },
                ResourceAvailability::External,
                4,
                &[
                    "implementation file: row 1",
                    "token 0x26000001",
                    "Part.netmodule",
                    "target name truncated",
                    "target File flags 0x1",
                    "availability external: metadata link; target not read",
                ],
            ),
            (
                ResourceImplementation::AssemblyRef {
                    row: 2,
                    token: None,
                    status: ResourceReferenceStatus::OutOfRange,
                    name: None,
                    name_truncated: false,
                },
                ResourceAvailability::Unavailable,
                9,
                &[
                    "implementation assembly_ref: row 2",
                    "token unresolved",
                    "status out_of_range",
                    "<unreadable target name>",
                    "availability unavailable",
                ],
            ),
            (
                ResourceImplementation::ExportedType {
                    row: 1,
                    token: Some(0x2700_0001),
                    status: ResourceReferenceStatus::Readable,
                },
                ResourceAvailability::Unavailable,
                6,
                &["implementation exported_type", "token 0x27000001", "unsupported resource link"],
            ),
            (
                ResourceImplementation::Invalid { tag: 3, row: 0 },
                ResourceAvailability::Unavailable,
                3,
                &["implementation invalid: reserved tag 3, row 0", "availability unavailable"],
            ),
        ];
        for (implementation, availability, raw, evidence) in cases {
            let page = rampage_api::Page {
                total: 3,
                offset: 1,
                items: vec![ManifestResource {
                    token: 0x2800_0002,
                    name: None,
                    name_truncated: true,
                    flags: 2,
                    offset: 8,
                    implementation_raw: *raw,
                    implementation: implementation.clone(),
                    availability: availability.clone(),
                }],
            };
            let mut output = Vec::new();
            dotnet_resources(&mut output, &page).unwrap();
            more_hint(&mut output, &page, "resources", "resources").unwrap();
            let text = String::from_utf8(output).unwrap();
            for phrase in [
                "0x28000002",
                "<unreadable name>",
                "flags 0x2, offset 0x8",
                "resource name truncated",
                "resource lengths/payload extents not validated",
                "--list resources --offset 2",
            ]
            .iter()
            .chain(evidence.iter())
            {
                assert!(text.contains(*phrase), "{phrase}: {text}");
            }
            assert!(text.contains(&format!("implementation_raw {raw:#x}")), "{text}");
        }
    }

    #[test]
    fn human_embedded_resource_statuses_do_not_turn_location_evidence_into_validated_payloads() {
        for (status, expected) in [
            (EmbeddedResourceStatus::DirectoryAbsent, "directory_absent"),
            (EmbeddedResourceStatus::DirectoryOverflow, "directory_overflow"),
            (EmbeddedResourceStatus::OutsideDirectory, "outside_directory"),
            (EmbeddedResourceStatus::RvaOverflow, "rva_overflow"),
            (EmbeddedResourceStatus::Unmapped, "unmapped"),
            (EmbeddedResourceStatus::DirectoryUnreadable, "directory_unreadable"),
        ] {
            let page = rampage_api::Page {
                total: 1,
                offset: 0,
                items: vec![ManifestResource {
                    token: 0x2800_0001,
                    name: Some("Name".to_owned()),
                    name_truncated: false,
                    flags: 1,
                    offset: 0,
                    implementation_raw: 0,
                    implementation: ResourceImplementation::Embedded,
                    availability: ResourceAvailability::Embedded { rva: None, status },
                }],
            };
            let mut output = Vec::new();
            dotnet_resources(&mut output, &page).unwrap();
            let text = String::from_utf8(output).unwrap();
            assert!(text.contains(&format!("RVA unavailable, status {expected} (location evidence only)")), "{text}");
            assert!(text.contains("payload extents not validated"), "{text}");
            assert!(!text.contains("readable_location"), "{text}");
        }
    }
}

/// The `... N more` line for a page of `--list {list}` that does not reach the end of its list.
fn more_hint<T>(out: &mut impl Write, page: &rampage_api::Page<T>, what: &str, list: &str) -> Result<()> {
    let shown = page.offset + page.items.len();
    if shown < page.total {
        let more = page.total - shown;
        writeln!(
            out,
            "\n... {more} more {what} (page with --list {list} --offset {shown}, or filter with --contains)"
        )?;
    }
    Ok(())
}

pub fn detect(out: &mut impl Write, path: &Path, peid: Option<&Path>, options: &Options) -> Result<()> {
    let peid_text = match peid {
        Some(peid) => Some(rampage_api::read_bounded(peid, rampage_api::MAX_PEID_BYTES, "PeID database")?),
        None => None,
    };
    let found = open(path, options)?.detect_tools(peid_text.as_deref())?;
    if options.json {
        return write_json(out, &found);
    }
    if found.detections.is_empty() {
        writeln!(out, "no tool signatures matched")?;
    }
    for detection in &found.detections {
        let (kind, confidence) = (label(&detection.kind), label(&detection.confidence));
        writeln!(out, "[{kind}] {} ({confidence}): {}", detection.name, detection.evidence.join(", "))?;
    }
    // Pack problems already go to stderr with every other command's; only the PeID file's own are shown here.
    let pack_problems = options.packs.problems_for("peid");
    for warning in found.warnings.iter().filter(|warning| !pack_problems.contains(warning)) {
        writeln!(out, "warning: {warning}")?;
    }
    Ok(())
}

pub fn yara(out: &mut impl Write, path: &Path, rules: Option<&Path>, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let matches = match rules {
        Some(rules) => project.yara_scan_path(rules)?,
        None => project.yara_scan_packs()?,
    };
    if options.json {
        return write_json(out, &matches);
    }
    if matches.is_empty() {
        writeln!(out, "no rules matched")?;
    }
    for hit in matches {
        let tags = if hit.tags.is_empty() { String::new() } else { format!(" [{}]", hit.tags.join(", ")) };
        writeln!(out, "{}{tags} ({} string matches)", hit.identifier, hit.matched_strings.len())?;
    }
    Ok(())
}

pub fn capa(out: &mut impl Write, path: &Path, rules: Option<&Path>, options: &Options) -> Result<()> {
    let project = open(path, options)?;
    let capabilities = match rules {
        Some(rules) => project.detect_capa(rules)?,
        None => project.detect_capa_packs()?,
    };
    render_capabilities(out, &capabilities, "no capa rules matched", options)
}

pub fn packs_list(out: &mut impl Write, options: &Options) -> Result<()> {
    let packs = options.packs.listing();
    if options.json {
        return write_json(out, &packs);
    }
    for pack in &packs {
        render_pack(out, pack)?;
    }
    Ok(())
}

pub fn packs_check(out: &mut impl Write, directory: &Path, options: &Options) -> Result<()> {
    let pack = Packs::check(directory);
    if options.json {
        write_json(out, &pack)?;
    } else {
        render_pack(out, &pack)?;
    }
    if pack.error.is_some() || pack.contents.iter().any(|content| content.status != ContentStatus::Loaded) {
        out.flush()?;
        anyhow::bail!("pack {} does not fully load", directory.display());
    }
    Ok(())
}

fn render_pack(out: &mut impl Write, pack: &PackInfo) -> Result<()> {
    let location = match &pack.directory {
        Some(directory) => directory.display().to_string(),
        None => "built in".to_owned(),
    };
    match &pack.manifest {
        Some(manifest) => {
            writeln!(out, "{} {} ({}) [{location}]", manifest.name, manifest.version, manifest.license)?;
            writeln!(out, "  source: {}", manifest.source)?;
            writeln!(out, "  {}", manifest.description)?;
        }
        None => writeln!(out, "{location}")?,
    }
    if let Some(error) = &pack.error {
        writeln!(out, "  error: {error}")?;
    }
    for content in &pack.contents {
        let arch = content.arch.as_deref().map(|arch| format!(" [{arch}]")).unwrap_or_default();
        let status = label(&content.status);
        writeln!(out, "  {status}: {} {}{arch}: {}", content.kind, content.path, content.detail)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rampage_loaders::dotnet::{BodyKind, EventAccessor, EventDef, MethodDef, TypeDef, UNREADABLE};

    #[test]
    fn event_text_preserves_names_and_metadata_bindings_when_types_are_unreadable() {
        let types = rampage_api::Page {
            total: 1,
            offset: 0,
            items: vec![TypeDef {
                token: 0x0200_0001,
                namespace: "Fixture".to_owned(),
                name: "Owner".to_owned(),
                flags: 0,
                extends: None,
                enclosing: None,
                fields: Vec::new(),
                methods: Vec::new(),
                properties: Vec::new(),
                events: vec![EventDef {
                    token: 0x1400_0001,
                    name: "Changed".to_owned(),
                    flags: 0x200,
                    event_type: UNREADABLE.to_owned(),
                    accessors: vec![EventAccessor { semantics: 8, method_token: 0x0600_0001 }],
                }],
            }],
        };
        let mut out = Vec::new();
        super::dotnet_types(&mut out, &types).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("event <unreadable> Changed (token 0x14000001, flags 0x200)"), "{text}");
        assert!(text.contains("metadata accessor 0x06000001, semantics 0x8"), "{text}");
    }

    #[test]
    fn an_unreadable_method_signature_keeps_the_method_name() {
        let mut method = MethodDef {
            token: 0x0600_0001,
            name: "Run".to_owned(),
            signature: "void Run()".to_owned(),
            rva: 0,
            flags: 0,
            impl_flags: 0,
            body: BodyKind::None,
            il: None,
            params: Vec::new(),
        };
        assert_eq!(super::method_text(&method), "void Run()");
        method.signature = UNREADABLE.to_owned();
        assert_eq!(super::method_text(&method), "Run(...) <unreadable signature>");
    }
}
