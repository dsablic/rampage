//! Taking one side apart into components, pairing components across the versions, and resolving a component id.
//!
//! Ids: a top-level component is `image` (the input is one executable or Raw image), `stream:N` (the Nth compressed
//! component of a headerless container, in file order), `esp:LABEL` (an ESP flash partition, `esp:bootloader` and
//! `esp:partition_table`), `fs` (a filesystem image or APK), `tree` (a directory), `embedded:KIND#N` (the Nth image
//! of that kind `carve` validated inside a container) or `file` (bytes nothing else explains). A component inside a
//! filesystem is `PARENT::PATH::ID`: the file at PATH in PARENT, and the component ID of that file taken apart. Two
//! components paired across different ids are `OLD~NEW`.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use rampage_loaders::{Binary, Format, ImageAt};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{Run, display};

/// Bytes of a file read for ESP flash layouts and Raw images.
const MAX_WHOLE_READ: u64 = 64 << 20;
/// Embedded images taken from `carve` per side.
const MAX_EMBEDDED: usize = 16;
/// Compressed components decoded per side.
const MAX_STREAMS: usize = 16;
/// Time one compression probe may take.
const PROBE_MS: u64 = 10_000;

/// One side's selection: a path, optionally an embedded image, a nested image chain or a Raw selector.
#[derive(Debug, Clone, Default)]
pub struct SideInput {
    pub path: PathBuf,
    pub image_offset: Option<u64>,
    pub image_length: Option<u64>,
    pub inner: Vec<String>,
    /// A Raw project selector (as `raw` on the project tools) for headerless code.
    pub raw: Option<Value>,
}

impl SideInput {
    pub(crate) fn of(path: PathBuf) -> Self {
        Self { path, ..Self::default() }
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if self.image_length.is_some() && self.image_offset.is_none() {
            return Err("image_length needs image_offset".to_owned());
        }
        if self.raw.is_some() && (self.image_offset.is_some() || !self.inner.is_empty()) {
            return Err("a Raw selector cannot be combined with image_offset or inner".to_owned());
        }
        if self.inner.len() > 8 {
            return Err("inner names at most 8 nested images".to_owned());
        }
        Ok(())
    }

    /// Whether `other` selects the same part of its file.
    pub(super) fn same_selection(&self, other: &SideInput) -> bool {
        self.image_offset == other.image_offset
            && self.image_length == other.image_length
            && self.inner == other.inner
            && self.raw == other.raw
    }

    /// Writes the arguments that select this side, with `prefix` (`other_` for the new side).
    pub(super) fn write_arguments(&self, arguments: &mut Value, prefix: &str) {
        let path_key = if prefix.is_empty() { "path" } else { "other" };
        arguments[path_key] = json!(display(&self.path));
        if let Some(offset) = self.image_offset {
            arguments[format!("{prefix}image_offset")] = json!(format!("{offset:#x}"));
        }
        if let Some(length) = self.image_length {
            arguments[format!("{prefix}image_length")] = json!(length);
        }
        if !self.inner.is_empty() {
            arguments[format!("{prefix}inner")] = json!(self.inner);
        }
        if let Some(raw) = &self.raw {
            arguments[format!("{prefix}as_raw")] = raw.clone();
        }
    }
}

/// A filesystem to compare by entries.
#[derive(Debug, Clone)]
pub(crate) enum Tree {
    Image { path: PathBuf, at: rampage_unpack::At, inner: Vec<String> },
    Dir(PathBuf),
}

/// How a component's content is opened for a deeper comparison.
#[derive(Debug, Clone)]
pub(crate) enum Opener {
    /// Compared by digest only.
    Data,
    Native {
        path: PathBuf,
        image: Option<ImageAt>,
    },
    Raw {
        path: PathBuf,
        request: Value,
    },
    Tree(Tree),
    /// A bare DEX file: its Android facts.
    Dex,
}

impl Opener {
    pub(crate) fn is_code(&self) -> bool {
        matches!(self, Opener::Native { .. } | Opener::Raw { .. })
    }

    /// The arguments that open this code with the project tools, for a component read from the input files.
    pub(crate) fn tool_arguments(&self) -> Option<Value> {
        match self {
            Opener::Native { path, image } => {
                let mut arguments = json!({ "path": display(path) });
                if let Some(image) = image.filter(|image| !image.is_whole_file()) {
                    arguments["image_offset"] = json!(format!("{:#x}", image.offset()));
                    if let Some(length) = image.length() {
                        arguments["image_length"] = json!(length);
                    }
                }
                Some(arguments)
            }
            Opener::Raw { path, request } => Some(json!({ "path": display(path), "raw": request })),
            _ => None,
        }
    }
}

/// Decode parameters and the base a decoded stream was opened with, which the other side tries first.
#[derive(Debug, Clone)]
pub(crate) struct StreamReuse {
    decode: Value,
    base: Option<u64>,
    /// The fill choice the older side made between tied probe candidates, carried so both sides say so.
    fill_choice: Option<Value>,
}

/// One part of a side.
#[derive(Debug, Clone)]
pub(crate) struct Component {
    pub(crate) id: String,
    pub(crate) role: &'static str,
    pub(crate) facts: Map<String, Value>,
    /// SHA-256 of the content compared; equal digests mean unchanged.
    pub(crate) digest: Option<String>,
    pub(crate) open: Opener,
    /// An APK: its Android facts are compared too.
    pub(crate) android: bool,
    /// Materialised from inside a filesystem into scratch space: its path does not outlive the call.
    pub(crate) ephemeral: bool,
    pub(crate) reuse: Option<StreamReuse>,
}

impl Component {
    fn new(id: impl Into<String>, role: &'static str, open: Opener) -> Self {
        Self {
            id: id.into(),
            role,
            facts: Map::new(),
            digest: None,
            open,
            android: false,
            ephemeral: false,
            reuse: None,
        }
    }

    fn fact(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.facts.insert(key.to_owned(), value.into());
        self
    }

    pub(crate) fn facts_value(&self) -> Value {
        let mut facts = self.facts.clone();
        if let Some(digest) = &self.digest {
            facts.insert("sha256".to_owned(), json!(digest));
        }
        Value::Object(facts)
    }
}

/// What one side holds.
pub(crate) struct Layout {
    pub(crate) kind: &'static str,
    path: PathBuf,
    size: Option<u64>,
    /// SHA-256 of the whole input file.
    pub(crate) digest: Option<String>,
    facts: Map<String, Value>,
    pub(crate) components: Vec<Component>,
    notes: Vec<String>,
}

impl Layout {
    pub(crate) fn summary(&self) -> Value {
        let mut value = json!({ "path": display(&self.path), "kind": self.kind });
        if let Some(size) = self.size {
            value["size"] = json!(size);
        }
        if let Some(digest) = &self.digest {
            value["sha256"] = json!(digest);
        }
        for (key, fact) in &self.facts {
            value[key] = fact.clone();
        }
        if !self.notes.is_empty() {
            value["notes"] = json!(self.notes);
        }
        value
    }
}

/// Both sides' layouts; the new side reuses what decoding the old side found (codec parameters, base address).
pub(crate) fn layouts(old: &SideInput, new: &SideInput, run: &mut Run) -> Result<(Layout, Layout), String> {
    let old_layout = layout(old, run, &[]).map_err(|error| format!("`path`: {error}"))?;
    let reuse: Vec<StreamReuse> =
        old_layout.components.iter().filter_map(|component| component.reuse.clone()).collect();
    let new_layout = layout(new, run, &reuse).map_err(|error| format!("`other`: {error}"))?;
    Ok((old_layout, new_layout))
}

fn sha256_of(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

/// The SHA-256 of a whole file, charged to the byte budget; `None` when the budget cannot cover it.
pub(crate) fn file_digest(path: &Path, size: u64, run: &mut Run) -> Result<Option<String>, String> {
    if !run.budget.charge(size) {
        return Ok(None);
    }
    let mut file = std::fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = file.read(&mut buffer).map_err(|error| format!("read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Some(rampage_arch::hex::bytes(&hasher.finalize())))
}

/// Reads at most [`MAX_WHOLE_READ`] bytes of `path`, charged to the byte budget.
fn read_bounded(path: &Path, size: u64, run: &mut Run) -> Result<Option<Vec<u8>>, String> {
    let length = size.min(MAX_WHOLE_READ);
    if !run.budget.charge(length) {
        return Ok(None);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    std::fs::File::open(path)
        .and_then(|file| file.take(length).read_to_end(&mut bytes))
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(Some(bytes))
}

/// Takes one side apart. `reuse` holds the other side's decoded streams, tried first for this side's.
pub(crate) fn layout(side: &SideInput, run: &mut Run, reuse: &[StreamReuse]) -> Result<Layout, String> {
    let path = &side.path;
    let metadata = std::fs::metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut layout = Layout {
        kind: "file",
        path: path.clone(),
        size: None,
        digest: None,
        facts: Map::new(),
        components: Vec::new(),
        notes: Vec::new(),
    };
    if metadata.is_dir() {
        if side.raw.is_some() || side.image_offset.is_some() || !side.inner.is_empty() {
            return Err("a directory takes no Raw selector, image_offset or inner".to_owned());
        }
        layout.kind = "directory";
        layout.components.push(Component::new("tree", "directory", Opener::Tree(Tree::Dir(path.clone()))));
        return Ok(layout);
    }
    if !metadata.is_file() {
        return Err(format!("{} is neither a regular file nor a directory", path.display()));
    }
    let size = metadata.len();
    layout.size = Some(size);
    layout.digest = file_digest(path, size, run)?;

    if let Some(request) = &side.raw {
        layout.kind = "raw";
        let mut component =
            Component::new("image", "raw_image", Opener::Raw { path: path.clone(), request: request.clone() });
        component.facts.insert("selector".to_owned(), request.clone());
        layout.components.push(component);
        return Ok(layout);
    }
    let at = rampage_unpack::At { offset: side.image_offset.unwrap_or(0), length: side.image_length };
    let image_format = rampage_unpack::file_source(path, at).ok().and_then(|source| rampage_unpack::detect(&*source));
    if !side.inner.is_empty() || image_format.is_some() {
        let format = image_format.map_or("nested", rampage_unpack::Format::name);
        let apk = side.inner.is_empty()
            && side.image_offset.is_none()
            && image_format == Some(rampage_unpack::Format::Zip)
            && crate::android::diff_facts(path).is_ok_and(|facts| facts.contains_key("version"));
        layout.kind = if apk { "android_package" } else { "filesystem" };
        let tree = Tree::Image { path: path.clone(), at, inner: side.inner.clone() };
        let mut component =
            Component::new("fs", if apk { "android_package" } else { "filesystem" }, Opener::Tree(tree))
                .fact("format", format);
        if !side.inner.is_empty() {
            component = component.fact("inner", json!(side.inner));
        }
        component.android = apk;
        component.digest =
            if side.image_offset.is_none() && side.inner.is_empty() { layout.digest.clone() } else { None };
        layout.components.push(component);
        return Ok(layout);
    }
    if let Some(offset) = side.image_offset {
        let image = ImageAt::new(offset, side.image_length);
        let binary = Binary::open_image(path, Some(image), None).map_err(|error| error.to_string())?;
        layout.kind = "embedded_executable";
        layout.components.push(native_component(
            "image",
            &binary,
            Opener::Native { path: path.clone(), image: Some(image) },
        ));
        return Ok(layout);
    }
    if crate::android::sniff(path) == Some("dex") {
        layout.kind = "dex";
        let mut component = Component::new("dex", "dex", Opener::Dex);
        component.digest = layout.digest.clone();
        component.android = true;
        component.facts.insert("path".to_owned(), json!(display(path)));
        layout.components.push(component);
        return Ok(layout);
    }
    if let Ok(binary) = Binary::open_image(path, None, None)
        && binary.format != Format::Raw
    {
        layout.kind = "executable";
        let mut component = native_component("image", &binary, Opener::Native { path: path.clone(), image: None });
        component.digest = layout.digest.clone();
        layout.components.push(component);
        return Ok(layout);
    }
    let Some(bytes) = read_bounded(path, size, run)? else {
        layout.notes.push("the byte budget ran out before the file could be read".to_owned());
        return Ok(layout);
    };
    if esp_layout(path, &bytes, &mut layout) {
        return Ok(layout);
    }
    headerless_layout(path, &bytes, size, run, reuse, &mut layout)?;
    Ok(layout)
}

fn native_component(id: &str, binary: &Binary, open: Opener) -> Component {
    let mut component = Component::new(id, "executable", open)
        .fact("format", format!("{:?}", binary.format).to_lowercase())
        .fact("arch", binary.arch.to_string());
    if let Some(entry) = binary.entry {
        component = component.fact("entry", format!("{entry:#x}"));
    }
    component
}

/// An ESP flash dump (bootloader, partition table, partitions) or a single ESP app image; false when it is neither.
fn esp_layout(path: &Path, bytes: &[u8], layout: &mut Layout) -> bool {
    use rampage_loaders::esp;
    let app = |id: String, role: &'static str, offset: u64| -> Option<Component> {
        let image = esp::parse_app_image(bytes, offset).ok()?;
        let end = usize::try_from(offset + image.length).ok()?;
        let mut component = if image.chip.xtensa() {
            let request = json!({"profile": "xtensa", "format": "esp", "offset": format!("{offset:#x}")});
            Component::new(id, role, Opener::Raw { path: path.to_owned(), request })
        } else {
            Component::new(id, role, Opener::Data)
        };
        component.digest = bytes.get(usize::try_from(offset).ok()?..end).map(sha256_of);
        component = component
            .fact("offset", format!("{offset:#x}"))
            .fact("length", image.length)
            .fact("chip", image.chip.name())
            .fact("entry", format!("{:#x}", image.entry))
            .fact("segments", image.segments.len())
            .fact("checksum_valid", image.checksum.valid);
        if let Some(sha) = &image.sha256 {
            component = component.fact("sha256_valid", sha.valid);
        }
        if let Some(desc) = &image.app_desc {
            component = component
                .fact("project", desc.project_name.clone())
                .fact("version", desc.version.clone())
                .fact("idf_version", desc.idf_version.clone())
                .fact("secure_version", desc.secure_version)
                .fact("compiled", format!("{} {}", desc.compile_date, desc.compile_time));
        }
        if let Some(desc) = &image.bootloader_desc {
            component =
                component.fact("bootloader_version", desc.version).fact("idf_version", desc.idf_version.clone());
        }
        Some(component)
    };
    let Some(flash) = esp::flash_layout(bytes) else {
        if esp::looks_like_app_image(bytes, 0)
            && let Some(component) = app("image".to_owned(), "esp_app", 0)
        {
            layout.kind = "esp_app_image";
            layout.components.push(component);
            return true;
        }
        return false;
    };
    layout.kind = "esp_flash";
    layout.facts.insert("chip".to_owned(), json!(flash.chip.name()));
    if let Some(bootloader) = &flash.bootloader
        && let Some(component) = app("esp:bootloader".to_owned(), "esp_bootloader", bootloader.offset)
    {
        layout.components.push(component);
    }
    let Some(table) = &flash.partition_table else { return true };
    let start = usize::try_from(table.offset).unwrap_or(usize::MAX);
    let mut component = Component::new("esp:partition_table", "partition_table", Opener::Data)
        .fact("offset", format!("{:#x}", table.offset))
        .fact(
            "partitions",
            table
                .partitions
                .iter()
                .map(|p| format!("{} {}/{} at {:#x}, {:#x} bytes", p.label, p.kind, p.subtype, p.offset, p.size))
                .collect::<Vec<_>>(),
        );
    if let Some(md5) = &table.md5 {
        component = component.fact("md5_valid", md5.valid);
    }
    component.digest = bytes.get(start..start.saturating_add(0xc00).min(bytes.len())).map(sha256_of);
    layout.components.push(component);
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for partition in &table.partitions {
        let count = seen.entry(partition.label.clone()).or_default();
        *count += 1;
        let id =
            if *count == 1 { format!("esp:{}", partition.label) } else { format!("esp:{}#{count}", partition.label) };
        let is_app = partition.kind == "app"
            && usize::try_from(partition.offset).is_ok_and(|offset| esp::looks_like_app_image(bytes, offset));
        let found = if is_app { app(id.clone(), "esp_app", partition.offset) } else { None };
        let mut component = found.unwrap_or_else(|| {
            let mut component = Component::new(id.clone(), "partition", Opener::Data);
            let begin = usize::try_from(partition.offset).unwrap_or(usize::MAX).min(bytes.len());
            let end =
                usize::try_from(partition.offset.saturating_add(partition.size)).unwrap_or(usize::MAX).min(bytes.len());
            component.digest = Some(sha256_of(&bytes[begin..end.max(begin)]));
            if end < usize::try_from(partition.offset.saturating_add(partition.size)).unwrap_or(usize::MAX) {
                component.facts.insert("note".to_owned(), json!("runs past the end of the dump"));
            }
            component
        });
        component.facts.insert("partition".to_owned(), json!(format!("{}/{}", partition.kind, partition.subtype)));
        component.facts.insert("partition_offset".to_owned(), json!(format!("{:#x}", partition.offset)));
        component.facts.insert("partition_size".to_owned(), json!(partition.size));
        if partition.encrypted {
            component.facts.insert("encrypted".to_owned(), json!(true));
        }
        layout.components.push(component);
    }
    true
}

/// A headerless file: compressed components a header describes, a Cortex-M image with its vector table at the
/// start, images `carve` validates inside it, or opaque bytes.
fn headerless_layout(
    path: &Path,
    bytes: &[u8],
    size: u64,
    run: &mut Run,
    reuse: &[StreamReuse],
    layout: &mut Layout,
) -> Result<(), String> {
    let report = crate::file_layout(path, &crate::FileLayoutRequest { hints: Some(true), ..Default::default() })
        .map_err(|error| error.to_string())?;
    layout.facts.insert("occupied_bytes".to_owned(), json!(report.summary.occupied_bytes));
    layout.facts.insert("occupied_regions".to_owned(), json!(report.summary.occupied_regions));
    let streams: Vec<crate::layout_containers::ContainerCandidate> =
        report.hints.iter().filter_map(|hint| hint.container.clone()).collect();
    let vectors_at_start =
        report.hints.iter().any(|hint| hint.kind == "cortex_m_vector_table_candidate" && hint.offset == 0);
    if !streams.is_empty() {
        layout.kind = "container";
        if streams.len() > MAX_STREAMS {
            layout.notes.push(format!("{} compressed components; the first {MAX_STREAMS} are compared", streams.len()));
        }
        for (index, stream) in streams.iter().take(MAX_STREAMS).enumerate() {
            let component = stream_component(path, index, stream, run, reuse.get(index));
            layout.components.push(component);
        }
    } else if vectors_at_start && size <= rampage_loaders::MAX_RAW_NATIVE_BYTES as u64 {
        layout.kind = "raw_image";
        let found = rampage_loaders::raw_base::base_candidates(bytes, None, &[]);
        match found.candidates.first() {
            Some(base) => {
                let request = json!({
                    "profile": "cortex-m", "offset": 0, "length": size,
                    "base_address": format!("{:#x}", base.base_address), "vector_table": true,
                });
                let mut component =
                    Component::new("image", "raw_image", Opener::Raw { path: path.to_owned(), request })
                        .fact("profile", "cortex-m")
                        .fact("base_address", format!("{:#x}", base.base_address))
                        .fact("base_confidence", serde_json::to_value(base.confidence).unwrap_or_default());
                component.digest = layout.digest.clone();
                layout.components.push(component);
            }
            None => {
                layout.notes.push(
                    "a Cortex-M vector table starts the file but no load address fits; pass as_raw with base_address"
                        .to_owned(),
                );
            }
        }
    }
    let carved = crate::carve(path, Some(256)).ok();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for candidate in carved.iter().flat_map(|carving| &carving.candidates) {
        if layout.components.iter().filter(|component| component.id.starts_with("embedded:")).count() >= MAX_EMBEDDED {
            layout.notes.push(format!("more embedded images than {MAX_EMBEDDED}; the rest are not compared"));
            break;
        }
        if candidate.confidence != rampage_loaders::carve::Confidence::Validated || candidate.offset == 0 {
            continue;
        }
        let kind = serde_json::to_value(candidate.kind).ok();
        let kind = kind.as_ref().and_then(Value::as_str).unwrap_or("unknown").to_owned();
        let (role, open) = match kind.as_str() {
            "elf" | "pe" | "mach_o" => {
                let image = ImageAt::new(candidate.offset, candidate.extent);
                ("executable", Opener::Native { path: path.to_owned(), image: Some(image) })
            }
            "squashfs" | "ext" | "android_sparse" | "ota_payload" | "cpio" | "tar" | "zip" | "ubi" | "ubifs" => {
                let at = rampage_unpack::At { offset: candidate.offset, length: candidate.extent };
                ("filesystem", Opener::Tree(Tree::Image { path: path.to_owned(), at, inner: Vec::new() }))
            }
            _ => continue,
        };
        let count = counts.entry(kind.clone()).or_default();
        let mut component = Component::new(format!("embedded:{kind}#{count}"), role, open)
            .fact("offset", format!("{:#x}", candidate.offset));
        *count += 1;
        if let Some(extent) = candidate.extent {
            component = component.fact("extent", extent);
            let start = usize::try_from(candidate.offset).unwrap_or(usize::MAX);
            let end = usize::try_from(candidate.offset.saturating_add(extent)).unwrap_or(usize::MAX);
            if end <= bytes.len() {
                component.digest = Some(sha256_of(&bytes[start..end]));
            }
        }
        layout.components.push(component);
    }
    if layout.components.is_empty() {
        layout.kind = "opaque";
        let mut component = Component::new("file", "data", Opener::Data)
            .fact("entropy_bits_per_byte", json!(report.entropy.whole_range));
        component.digest = layout.digest.clone();
        layout.components.push(component);
    }
    if size > MAX_WHOLE_READ {
        layout.notes.push(format!("only the first {MAX_WHOLE_READ} bytes were searched for components"));
    }
    Ok(())
}

/// A compressed component: decoded with the other side's parameters when they fit, else probed; opened as Cortex-M
/// code at the best base candidate when one fits.
fn stream_component(
    path: &Path,
    index: usize,
    stream: &crate::layout_containers::ContainerCandidate,
    run: &mut Run,
    reuse: Option<&StreamReuse>,
) -> Component {
    let id = format!("stream:{index}");
    let mut component = Component::new(id.clone(), "compressed_stream", Opener::Data)
        .fact("header_offset", format!("{:#x}", stream.header_offset))
        .fact("payload_offset", format!("{:#x}", stream.payload_offset))
        .fact("payload_length", stream.payload_length)
        .fact("checksum", stream.checksum_field.map_or_else(|| json!("none found"), |field| json!(field.kind)));
    let expected = stream.decoded_size_candidates.first().map(|word| u64::from(word.value));
    if let Some(size) = expected {
        component = component.fact("decoded_size_field", size);
    }
    // The compressed bytes identify the stream until it is decoded.
    let charged = run.budget.charge(stream.payload_length);
    component.digest = std::fs::File::open(path).ok().filter(|_| charged).and_then(|file| {
        use std::io::{Seek, SeekFrom};
        let mut file = file;
        file.seek(SeekFrom::Start(stream.payload_offset)).ok()?;
        let mut hasher = Sha256::new();
        let mut payload = file.take(stream.payload_length);
        let mut buffer = vec![0u8; 1 << 16];
        loop {
            let read = payload.read(&mut buffer).ok()?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Some(rampage_arch::hex::bytes(&hasher.finalize()))
    });
    let Ok(length) = usize::try_from(stream.payload_length) else { return component };
    let mut decoded: Option<(Value, Vec<u8>, usize)> = None;
    let mut fill_choice = None;
    if let (Some(reuse), Some(size)) = (reuse, expected)
        && run.budget.time_left()
    {
        let mut decode = reuse.decode.clone();
        decode["expected_output_size"] = json!(size);
        if let Ok(bytes) = decode_bytes(path, stream.payload_offset, length, &decode, run) {
            decoded = Some((decode, bytes.0, bytes.1));
            component.facts.insert("decoded_with".to_owned(), json!("the other version's parameters"));
            if let Some(choice) = &reuse.fill_choice {
                component.facts.insert("dictionary_fill_ambiguous".to_owned(), json!(true));
                fill_choice = Some(choice.clone());
            }
        }
    }
    if decoded.is_none() && run.budget.time_left() {
        let request = crate::ProbeCompressionRequest {
            offset: crate::FileOffset(stream.payload_offset),
            length: crate::FileOffset(stream.payload_length),
            expected_output_size: expected.map(crate::FileOffset),
            candidate_limit: Some(3),
            timeout_ms: Some(PROBE_MS.min(run.budget.remaining().as_millis() as u64).max(1)),
            preview_size: Some(0),
        };
        match crate::probe_compression(path, &request) {
            Ok(report) => {
                let usable = |candidate: &&crate::compression_probe::ProbeCandidate| {
                    candidate.decode_check == "reproduced"
                        && candidate.open_as_raw.is_some()
                        && matches!(candidate.verdict, "confident" | "plausible")
                };
                let first = report.candidates.iter().find(usable);
                // Alternatives that read the same tokens into different bytes (an exercised ring fill) tie in the
                // probe. Each is decoded, and the one whose bytes read best as an image is taken: the most
                // plausible Cortex-M vector words, then the strongest base candidate; else the probe's order.
                let mut best: Option<Decoded> = None;
                let mut tried = Vec::new();
                for candidate in report.candidates.iter().filter(usable) {
                    let Some(first) = first else { break };
                    if !run.budget.time_left() {
                        break;
                    }
                    let alternative = first.dictionary_fill_exercised == Some(true)
                        && candidate.output_size == first.output_size
                        && candidate.input_consumed == first.input_consumed;
                    if !std::ptr::eq(candidate, first) && !alternative {
                        continue;
                    }
                    let Some(raw) = &candidate.open_as_raw else { continue };
                    let decode = raw["decode"].clone();
                    let Ok((bytes, consumed)) = decode_bytes(path, stream.payload_offset, length, &decode, run) else {
                        continue;
                    };
                    let base =
                        candidate.base_candidates.as_ref().and_then(|bases| bases.first()).map_or(0, |b| b.score);
                    let score = (plausible_vector_words(&bytes), base);
                    tried.push(json!({
                        "dictionary_fill": decode["dictionary_fill"],
                        "vector_words": score.0,
                        "base_score": score.1,
                    }));
                    if best.as_ref().is_none_or(|best| score > best.score) {
                        best = Some(Decoded { decode, bytes, consumed, verdict: candidate.verdict, score });
                    }
                }
                match best {
                    Some(best) => {
                        // Only a real tie is reported: more than one candidate decoded the same tokens.
                        if tried.len() > 1 {
                            component.facts.insert("dictionary_fill_ambiguous".to_owned(), json!(true));
                            fill_choice = Some(json!({
                                "candidates": tried,
                                "chosen": best.decode["dictionary_fill"],
                                "by": "plausible Cortex-M vector words, then the base-candidate score",
                            }));
                        }
                        component.facts.insert("probe_verdict".to_owned(), json!(best.verdict));
                        decoded = Some((best.decode, best.bytes, best.consumed));
                    }
                    None => {
                        component.facts.insert("decoded".to_owned(), json!(false));
                        run.skip(&id, "probe_compression found no reproducible decoder for this payload");
                    }
                }
            }
            Err(error) => run.skip(&id, format!("probe_compression: {error}")),
        }
    }
    if let Some(choice) = &fill_choice {
        component.facts.insert("fill_choice".to_owned(), choice.clone());
    }
    let Some((decode, bytes, consumed)) = decoded else { return component };
    component.digest = Some(sha256_of(&bytes));
    component.facts.insert("codec".to_owned(), decode["codec"].clone());
    component.facts.insert("decoded_size".to_owned(), json!(bytes.len()));
    let hints = crate::container_record::find_in_file(path, stream.payload_offset, length, consumed, bytes.len())
        .map(|record| record.hints())
        .unwrap_or_default();
    let found = rampage_loaders::raw_base::base_candidates(&bytes, None, &hints);
    let preferred = reuse.and_then(|reuse| reuse.base);
    let base = found
        .candidates
        .iter()
        .find(|candidate| Some(candidate.base_address) == preferred)
        .or(found.candidates.first());
    component.reuse =
        Some(StreamReuse { decode: decode.clone(), base: base.map(|base| base.base_address), fill_choice });
    let Some(base) = base else {
        component.facts.insert("base_address".to_owned(), json!(null));
        run.skip(&id, "decoded, but no Cortex-M load address fits the bytes; compared by digest (pass as_raw)");
        return component;
    };
    component.facts.insert("base_address".to_owned(), json!(format!("{:#x}", base.base_address)));
    component.facts.insert("base_confidence".to_owned(), serde_json::to_value(base.confidence).unwrap_or_default());
    let request = json!({
        "profile": "cortex-m",
        "offset": format!("{:#x}", stream.payload_offset),
        "length": stream.payload_length,
        "decode": decode,
        "base_address": format!("{:#x}", base.base_address),
        "vector_table": base.evidence.vector_table,
    });
    component.open = Opener::Raw { path: path.to_owned(), request };
    component
}

/// A probe candidate decoded: its parameters, bytes, input consumed, verdict and how well the bytes read as an image.
struct Decoded {
    decode: Value,
    bytes: Vec<u8>,
    consumed: usize,
    verdict: &'static str,
    score: (usize, u64),
}

/// Words 2..16 of a Cortex-M vector table at the start of `bytes` that are zero or an odd (Thumb) code address.
fn plausible_vector_words(bytes: &[u8]) -> usize {
    (2..16)
        .filter_map(|slot| bytes.get(slot * 4..slot * 4 + 4))
        .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
        .filter(|&word| word == 0 || (word & 1 == 1 && word > 1 && word < 0x2000_0000))
        .count()
}

/// Decodes `length` bytes at `offset` with a Raw region's `decode` parameters: the bytes and the input consumed.
fn decode_bytes(
    path: &Path,
    offset: u64,
    length: usize,
    decode: &Value,
    run: &mut Run,
) -> Result<(Vec<u8>, usize), String> {
    if !run.budget.time_left() {
        return Err("the time budget ran out".to_owned());
    }
    // The decoder's own deadline is what is left of the call's, and at most its default.
    let remaining = (run.budget.remaining().as_millis() as u64).clamp(1, 3000);
    let decode: crate::raw_project::RawRegionDecode =
        serde_json::from_value(decode.clone()).map_err(|error| error.to_string())?;
    let expected = usize::try_from(decode.expected_output_size.0).map_err(|_| "decoded size too large".to_owned())?;
    let request = crate::DecodeFileRequest {
        codec: decode.codec,
        lzss: decode.lzss,
        offset,
        length,
        expected_output_size: expected,
        initial_write_offset: decode
            .initial_write_offset
            .unwrap_or_else(|| crate::default_initial_write_offset(decode.codec)),
        dictionary_fill: decode.dictionary_fill.unwrap_or(0),
        timeout_ms: decode.timeout_ms.unwrap_or(3000).min(remaining),
        preview_offset: 0,
        preview_size: 0,
    };
    if !run.budget.charge(length as u64) {
        return Err("the byte budget ran out".to_owned());
    }
    let decoded = crate::decode_file_range(path, &request).map_err(|error| error.to_string())?;
    Ok((decoded.bytes().to_vec(), decoded.receipt.input_consumed))
}

/// Container-level differences between the two layouts as a whole.
pub(crate) fn container_changes(old: &Layout, new: &Layout) -> Vec<String> {
    let mut changes = Vec::new();
    if old.kind != new.kind {
        changes.push(format!("kind: {} -> {}", old.kind, new.kind));
    }
    if old.size != new.size
        && let (Some(a), Some(b)) = (old.size, new.size)
    {
        changes.push(format!("size: {a} -> {b} bytes"));
    }
    changes.extend(differing(&old.facts, &new.facts));
    let ids = |layout: &Layout| layout.components.iter().map(|component| component.id.clone()).collect::<Vec<_>>();
    if ids(old) != ids(new) {
        let list = |ids: Vec<String>| {
            let total = ids.len();
            let mut shown: Vec<String> = ids.into_iter().take(12).collect();
            if total > shown.len() {
                shown.push(format!("{} more", total - shown.len()));
            }
            shown.join(", ")
        };
        changes.push(format!("components: {} -> {}", list(ids(old)), list(ids(new))));
    }
    changes
}

/// The facts of a component pair that differ.
pub(crate) fn fact_changes(old: &Component, new: &Component) -> Vec<String> {
    let mut changes = differing(&old.facts, &new.facts);
    if let (Some(Value::Array(a)), Some(Value::Array(b))) = (old.facts.get("partitions"), new.facts.get("partitions")) {
        changes.retain(|change| !change.starts_with("partitions:"));
        let labels = |rows: &[Value]| -> BTreeMap<String, String> {
            rows.iter()
                .filter_map(Value::as_str)
                .map(|row| (row.split(' ').next().unwrap_or_default().to_owned(), row.to_owned()))
                .collect()
        };
        let (a, b) = (labels(a), labels(b));
        for (label, row) in &b {
            match a.get(label) {
                None => changes.push(format!("partition added: {row}")),
                Some(old_row) if old_row != row => changes.push(format!("partition changed: {old_row} -> {row}")),
                Some(_) => {}
            }
        }
        for (label, row) in &a {
            if !b.contains_key(label) {
                changes.push(format!("partition removed: {row}"));
            }
        }
    }
    changes
}

/// Facts about how a side was read rather than what it holds: they differ between versions without anything in
/// the update changing, so they are not reported as changes.
const PROVENANCE_FACTS: [&str; 4] = ["decoded_with", "probe_verdict", "path", "fill_choice"];

fn differing(old: &Map<String, Value>, new: &Map<String, Value>) -> Vec<String> {
    let mut keys: Vec<&String> = old.keys().chain(new.keys()).collect();
    keys.sort();
    keys.dedup();
    let text = |value: Option<&Value>| -> String {
        let text = value.map_or_else(
            || "absent".to_owned(),
            |value| match value {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            },
        );
        if text.len() > 200 { format!("{}...", &text[..text.floor_char_boundary(200)]) } else { text }
    };
    keys.into_iter()
        .filter(|key| !PROVENANCE_FACTS.contains(&key.as_str()))
        .filter(|key| old.get(*key) != new.get(*key))
        .map(|key| format!("{key}: {} -> {}", text(old.get(key)), text(new.get(key))))
        .collect()
}

/// Pairs components across the versions: by id, then compressed streams in order by similar size, then the only
/// remaining code image on each side. Sorted by id.
pub(crate) type Paired = (String, &'static str, Option<Component>, Option<Component>);

pub(crate) fn pair(old: Vec<Component>, new: Vec<Component>) -> Vec<Paired> {
    let mut new: Vec<Option<Component>> = new.into_iter().map(Some).collect();
    let mut pairs = Vec::new();
    let mut left = Vec::new();
    for component in old {
        match new.iter().position(|other| other.as_ref().is_some_and(|other| other.id == component.id)) {
            Some(index) => {
                let other = new[index].take();
                pairs.push((component.id.clone(), "id", Some(component), other));
            }
            None => left.push(component),
        }
    }
    let mut new: Vec<Component> = new.into_iter().flatten().collect();
    // Streams whose count changed: in order, each to the next one of comparable size.
    let mut old_left = Vec::new();
    let mut cursor = 0;
    for component in left {
        if component.role == "compressed_stream" {
            let size = |component: &Component| {
                component.facts.get("decoded_size").or(component.facts.get("payload_length")).and_then(Value::as_u64)
            };
            let found = new.iter().enumerate().skip(cursor).find(|(_, other)| {
                other.role == "compressed_stream"
                    && match (size(&component), size(other)) {
                        (Some(a), Some(b)) => a.max(b) <= 2 * a.min(b).max(1),
                        _ => false,
                    }
            });
            if let Some((index, _)) = found {
                let other = new.remove(index);
                cursor = index;
                pairs.push((
                    format!("{}~{}", component.id, other.id),
                    "stream_order_size",
                    Some(component),
                    Some(other),
                ));
                continue;
            }
        }
        old_left.push(component);
    }
    // The only code image, or the only filesystem, left on each side: the same part in another form (a plain
    // image and a compressed one, an extracted directory and an image).
    type Kind = (&'static str, fn(&Component) -> bool);
    let kinds: [Kind; 2] = [
        ("only_remaining_code", |component| component.open.is_code()),
        ("only_remaining_tree", |component| matches!(component.open, Opener::Tree(_))),
    ];
    for (paired_by, kind) in kinds {
        let count = |components: &[Component]| components.iter().filter(|component| kind(component)).count();
        if count(&old_left) == 1 && count(&new) == 1 {
            let a = old_left.iter().position(kind).expect("one");
            let b = new.iter().position(kind).expect("one");
            let (a, b) = (old_left.remove(a), new.remove(b));
            pairs.push((format!("{}~{}", a.id, b.id), paired_by, Some(a), Some(b)));
        }
    }
    pairs.extend(old_left.into_iter().map(|component| (component.id.clone(), "id", Some(component), None)));
    pairs.extend(new.into_iter().map(|component| (component.id.clone(), "id", None, Some(component))));
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
}

/// The component pair `id` names, taking filesystems apart along its path.
pub(crate) fn resolve(
    id: &str,
    old: Layout,
    new: Layout,
    run: &mut Run,
) -> Result<(Option<Component>, Option<Component>), String> {
    let segments: Vec<&str> = id.split("::").collect();
    if segments.len().is_multiple_of(2) {
        return Err(format!("`{id}` is not a component id: PARENT::PATH must be followed by ::ID"));
    }
    let (mut old_components, mut new_components) = (old.components, new.components);
    let mut found = pick(segments[0], &mut old_components, &mut new_components, id)?;
    for step in segments[1..].chunks(2) {
        let (path, sub) = (step[0], step[1]);
        let materialise = |run: &mut Run, component: &Option<Component>| -> Result<Option<Layout>, String> {
            let Some(component) = component else { return Ok(None) };
            let Opener::Tree(tree) = &component.open else {
                return Err(format!("`{}` is not a filesystem, so `{path}` is not inside it", component.id));
            };
            let Some(file) = super::tree::materialise_one(run, tree, path)? else { return Ok(None) };
            let mut layout = layout(&SideInput::of(file), run, &[])?;
            // A directory's files are real paths; an image's are scratch copies.
            let ephemeral = matches!(tree, Tree::Image { .. });
            for component in &mut layout.components {
                component.ephemeral = ephemeral;
            }
            Ok(Some(layout))
        };
        let old_layout = materialise(run, &found.0)?;
        let new_layout = materialise(run, &found.1)?;
        if old_layout.is_none() && new_layout.is_none() {
            return Err(format!("`{path}` is in neither version"));
        }
        old_components = old_layout.map(|layout| layout.components).unwrap_or_default();
        new_components = new_layout.map(|layout| layout.components).unwrap_or_default();
        found = pick(sub, &mut old_components, &mut new_components, id)?;
    }
    Ok(found)
}

/// The pair `segment` (an id or `OLD~NEW`) names among the components.
fn pick(
    segment: &str,
    old: &mut Vec<Component>,
    new: &mut Vec<Component>,
    id: &str,
) -> Result<(Option<Component>, Option<Component>), String> {
    let (a, b) = segment.split_once('~').unwrap_or((segment, segment));
    let take = |components: &mut Vec<Component>, wanted: &str| {
        components.iter().position(|component| component.id == wanted).map(|index| components.remove(index))
    };
    let pair = (take(old, a), take(new, b));
    if pair.0.is_none() && pair.1.is_none() {
        return Err(format!("no component `{segment}` (in `{id}`) on either side; ids come from a previous result"));
    }
    Ok(pair)
}
