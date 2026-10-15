use std::collections::{BTreeMap, BTreeSet};

use rampage_decompiler::layout::{
    LayoutField, LayoutOrganization, LayoutScalar, LayoutType, PlainStructLayout, ScalarKind,
};
use sha2::{Digest, Sha256};

mod review;

pub use review::DebugLayoutReview;

use crate::{
    ApiError, Project,
    annotations::{Annotations, Field},
};

pub(crate) const TYPE_MAGIC: &str = "!rampage-plain-layout-v1\n";
const SIGNATURE_MAGIC: &str = "!rampage-layout-signature-v1\n";
pub(crate) const LANGUAGE: &str = "x86:LE:64:default:gcc";
pub(crate) const MAX_LAYOUTS: usize = 16;
pub(crate) const MAX_FIELDS: usize = 512;
pub(crate) const MAX_FUNCTIONS: usize = 128;
pub(crate) const MAX_BUNDLE_BYTES: usize = 384 * 1024;
pub(crate) const MAX_IMPORT_TEXT: usize = 512 * 1024;
const MAX_SIGNATURE_BYTES: usize = 8192;
const MAX_NAME_WORK: usize = 1024 * 1024;
const MAX_CHECKED_IMAGE_BYTES: usize = 128 * 1024 * 1024;

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(format!("checked debug layout: {message}"))
}

fn digest_text(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

fn hex_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|character: char| !character.is_ascii_alphanumeric() && character != '_').filter(|word| !word.is_empty())
}

pub(crate) fn check_backing(project: &Project) -> Result<(), ApiError> {
    project.binary.validate_backing_source().map_err(|error| invalid(&error.to_string()))
}

pub(crate) fn image_digest(project: &Project) -> Result<[u8; 32], ApiError> {
    check_backing(project)?;
    let bytes = project.binary.image_bytes();
    if bytes.len() > MAX_CHECKED_IMAGE_BYTES {
        return Err(invalid("selected image exceeds the checked hash/native-work byte budget"));
    }
    let digest = Sha256::digest(bytes).into();
    check_backing(project)?;
    Ok(digest)
}

type SpecIdentity = rampage_decompiler::VerifiedBundledContext;

fn specification_identity() -> Result<SpecIdentity, ApiError> {
    rampage_decompiler::require_verified_bundled_native_context().map_err(|error| invalid(&error.to_string()))
}

pub(crate) fn current_specification_digest() -> Result<String, ApiError> {
    let specifications = specification_identity()?;
    let mut hash = Sha256::new();
    specifications.feed_manifest_identity(|bytes| hash.update(bytes));
    Ok(rampage_arch::hex::bytes(&hash.finalize()))
}

pub(crate) fn validate_replay_source(project: &Project, annotations: &Annotations) -> Result<(), ApiError> {
    if annotations.has_checked_layouts() {
        check_backing(project)?;
        annotations.preflight_checked().map_err(ApiError::Invalid)?;
        specification_identity()?;
        validate_replay_budget(annotations)?;
        validate_native_work(project)?;
    }
    Ok(())
}

fn validate_native_work(project: &Project) -> Result<(), ApiError> {
    let binary = &project.binary;
    if binary.image_bytes().len() > MAX_CHECKED_IMAGE_BYTES {
        return Err(invalid("selected image exceeds the checked hash/native-work byte budget"));
    }
    if binary.symbols.len() > 8192
        || binary.exports.len() > 8192
        || binary.function_starts.len() > 8192
        || binary.imports.len() > 1024
        || binary.import_slots.len() > 1024
        || binary.segments.len() > 256
    {
        return Err(invalid("image metadata exceeds the checked native-work budget"));
    }
    let mut mapped_bytes = 0usize;
    for segment in &binary.segments {
        if segment.size == 0 || segment.file_size == 0 || !(segment.perms.read || segment.perms.execute) {
            continue;
        }
        let bytes = binary.read_to_segment_end(segment.address).map_or(0, <[u8]>::len);
        mapped_bytes = mapped_bytes
            .checked_add(bytes)
            .filter(|&bytes| bytes <= MAX_CHECKED_IMAGE_BYTES)
            .ok_or_else(|| invalid("aggregate mapped bytes exceed the checked native-copy budget"))?;
    }
    let mut text = 0usize;
    for name in binary
        .symbols
        .iter()
        .map(|symbol| &symbol.name)
        .chain(binary.exports.iter().map(|export| &export.name))
        .chain(binary.import_slots.iter().map(|slot| &slot.name))
    {
        text = text.checked_add(name.len()).ok_or_else(|| invalid("native name work overflow"))?;
        if name.len() > 4095 || text > MAX_NAME_WORK {
            return Err(invalid("native name work budget exceeded"));
        }
    }
    if project.cached_analysis().is_some_and(|analysis| {
        analysis.program.functions.len() > 16_384
            || analysis.program.functions.len().saturating_mul(binary.symbols.len().max(1)) > 262_144
    }) {
        return Err(invalid("symbol/function resolution exceeds the checked native-work budget"));
    }
    Ok(())
}

pub(crate) fn validate_replay_budget(annotations: &Annotations) -> Result<(), ApiError> {
    if annotations.types().len() + annotations.globals().len() + annotations.signatures().len() > 1024 {
        return Err(invalid("existing declaration count exceeds the checked native-work budget"));
    }
    let mut bytes = 0usize;
    let mut sealed = 0usize;
    for text in
        annotations.types().values().chain(annotations.globals().values()).chain(annotations.signatures().values())
    {
        bytes = bytes.checked_add(text.len()).ok_or_else(|| invalid("replay byte count overflow"))?;
        sealed += usize::from(text.starts_with(SIGNATURE_MAGIC));
        if bytes > MAX_NAME_WORK || sealed > MAX_FUNCTIONS {
            return Err(invalid("replay text/signature native-work budget exceeded"));
        }
    }
    Ok(())
}

pub(crate) struct StoredLayout {
    pub(crate) layout: PlainStructLayout,
    pub(crate) digest: String,
}

pub(crate) struct LayoutBundle {
    pub(crate) image: String,
    pub(crate) specifications: String,
    pub(crate) layouts: Vec<StoredLayout>,
}

impl LayoutBundle {
    pub(crate) fn decode(text: &str) -> Result<Option<Self>, ApiError> {
        if !text.starts_with(TYPE_MAGIC) {
            if text.starts_with('!') {
                return Err(invalid("unknown type bundle version"));
            }
            return Ok(None);
        }
        if text.len() > MAX_BUNDLE_BYTES {
            return Err(invalid("type bundle byte limit exceeded"));
        }
        let mut lines = text[TYPE_MAGIC.len()..].lines();
        let image = lines.next().filter(|text| hex_digest(text)).ok_or_else(|| invalid("invalid bundle image"))?;
        if lines.next() != Some(LANGUAGE) {
            return Err(invalid("unsupported bundle compiler identity"));
        }
        let specifications = lines
            .next()
            .filter(|text| hex_digest(text))
            .ok_or_else(|| invalid("invalid bundle specification identity"))?;
        let mut layouts = Vec::new();
        let mut names = BTreeSet::new();
        let mut fields = 0usize;
        for line in lines {
            if layouts.len() == MAX_LAYOUTS {
                return Err(invalid("type bundle layout limit exceeded"));
            }
            let layout = PlainStructLayout::from_wire(line.as_bytes()).map_err(|error| invalid(&error.to_string()))?;
            fields += layout.fields.len();
            if fields > MAX_FIELDS || !names.insert(layout.name.clone()) {
                return Err(invalid("duplicate layout or cumulative field limit exceeded"));
            }
            let canonical = serde_json::to_string(&layout).map_err(|error| invalid(&error.to_string()))?;
            let digest =
                digest_text(format!("{TYPE_MAGIC}{image}\n{LANGUAGE}\n{specifications}\n{canonical}").as_bytes());
            layouts.push(StoredLayout { layout, digest });
        }
        if layouts.is_empty() {
            return Err(invalid("empty type bundle"));
        }
        Ok(Some(Self { image: image.to_owned(), specifications: specifications.to_owned(), layouts }))
    }

    pub(crate) fn encode(image: &[u8; 32], layouts: &[PlainStructLayout]) -> Result<String, ApiError> {
        if layouts.is_empty() || layouts.len() > MAX_LAYOUTS {
            return Err(invalid("invalid layout count"));
        }
        let specifications = current_specification_digest()?;
        let mut text = format!("{TYPE_MAGIC}{}\n{LANGUAGE}\n{specifications}\n", rampage_arch::hex::bytes(image));
        let mut fields = 0usize;
        for layout in layouts {
            layout.validate().map_err(|error| invalid(&error.to_string()))?;
            fields += layout.fields.len();
            if fields > MAX_FIELDS {
                return Err(invalid("cumulative field limit exceeded"));
            }
            text.push_str(&serde_json::to_string(layout).map_err(|error| invalid(&error.to_string()))?);
            text.push('\n');
            if text.len() > MAX_BUNDLE_BYTES {
                return Err(invalid("type bundle byte limit exceeded"));
            }
        }
        Self::decode(&text)?;
        Ok(text)
    }
}

pub(crate) fn declaration(layout: &PlainStructLayout) -> String {
    let mut text = format!("struct {} {{\n", layout.name);
    for field in &layout.fields {
        let ty = match &field.ty {
            LayoutType::Scalar { scalar } => scalar.name.clone(),
            LayoutType::Pointer { name, pointee, .. } => {
                if name.is_empty() {
                    format!("{} *", pointee.name)
                } else {
                    name.clone()
                }
            }
        };
        text.push_str(&format!(" {ty} {};\n", field.name));
    }
    text.push_str("};");
    text
}

pub(crate) fn seal_signature(declaration: &str, dependencies: &[&StoredLayout]) -> Result<String, ApiError> {
    if dependencies.is_empty() || dependencies.len() > MAX_LAYOUTS || declaration.len() > 4095 {
        return Err(invalid("invalid signature dependency count or declaration length"));
    }
    let mut text = SIGNATURE_MAGIC.to_owned();
    for dependency in dependencies {
        text.push_str(&format!("{} {}\n", dependency.layout.name, dependency.digest));
    }
    text.push('\n');
    text.push_str(declaration);
    if text.len() > MAX_SIGNATURE_BYTES {
        return Err(invalid("sealed signature byte limit exceeded"));
    }
    Ok(text)
}

pub(crate) fn signature<'a>(text: &'a str, layouts: &BTreeMap<String, String>) -> Result<&'a str, ApiError> {
    if !text.starts_with(SIGNATURE_MAGIC) {
        if text.starts_with('!') {
            return Err(invalid("unknown signature bundle version"));
        }
        return Ok(text);
    }
    if text.len() > MAX_SIGNATURE_BYTES {
        return Err(invalid("sealed signature byte limit exceeded"));
    }
    let (dependencies, declaration) = text[SIGNATURE_MAGIC.len()..]
        .split_once("\n\n")
        .ok_or_else(|| invalid("missing signature dependency terminator"))?;
    let mut seen = BTreeSet::new();
    for line in dependencies.lines() {
        let (name, digest) = line.split_once(' ').ok_or_else(|| invalid("invalid signature dependency"))?;
        if seen.len() == MAX_LAYOUTS
            || !seen.insert(name)
            || !hex_digest(digest)
            || layouts.get(name).map(String::as_str) != Some(digest)
            || !words(declaration).any(|word| word == name)
        {
            return Err(invalid("missing, incompatible or unused signature layout assertion"));
        }
    }
    if seen.is_empty() || declaration.len() > 4095 {
        return Err(invalid("empty signature dependencies or oversized declaration"));
    }
    for name in layouts.keys() {
        if words(declaration).any(|word| word == name) && !seen.contains(name.as_str()) {
            return Err(invalid("unsealed signature layout dependency"));
        }
    }
    Ok(declaration)
}

pub(crate) fn stored_layouts(annotations: &Annotations) -> Result<BTreeMap<String, String>, ApiError> {
    let mut layouts = BTreeMap::new();
    let mut bytes = 0usize;
    let mut fields = 0usize;
    for text in annotations.types().values().filter(|text| text.starts_with('!')) {
        bytes = bytes.checked_add(text.len()).ok_or_else(|| invalid("bundle byte overflow"))?;
        if bytes > MAX_IMPORT_TEXT {
            return Err(invalid("cumulative bundle byte limit exceeded"));
        }
        let bundle = LayoutBundle::decode(text)?.ok_or_else(|| invalid("invalid type bundle"))?;
        for stored in bundle.layouts {
            fields += stored.layout.fields.len();
            if layouts.len() == MAX_LAYOUTS
                || fields > MAX_FIELDS
                || layouts.insert(stored.layout.name, stored.digest).is_some()
            {
                return Err(invalid("duplicate layout or cumulative layout/field limit exceeded"));
            }
        }
    }
    Ok(layouts)
}

pub(crate) fn validate_transition(previous: &Annotations, candidate: &Annotations) -> Result<(), String> {
    if previous.types() == candidate.types() {
        return Ok(());
    }
    let old = stored_layouts(previous).map_err(|error| error.to_string())?;
    if old.is_empty() {
        return Ok(());
    }
    let new = stored_layouts(candidate).map_err(|error| error.to_string())?;
    let missing: BTreeSet<_> =
        old.iter().filter(|(name, digest)| new.get(*name) != Some(*digest)).map(|(name, _)| name).collect();
    if missing.is_empty() {
        return Ok(());
    }
    let mut bytes = 0usize;
    for text in candidate.types().values().chain(candidate.signatures().values()).chain(candidate.globals().values()) {
        bytes = bytes.checked_add(text.len()).ok_or_else(|| "layout dependency scan overflow".to_owned())?;
        if bytes > MAX_NAME_WORK {
            return Err("layout dependency scan byte limit exceeded".to_owned());
        }
        if words(text).any(|word| missing.iter().any(|name| name.as_str() == word)) {
            return Err("cannot remove a layout assertion while remaining declarations depend on it".to_owned());
        }
    }
    Ok(())
}

pub(crate) fn preserve_bundle(previous: Option<&str>, value: Option<&str>) -> Result<(), String> {
    if previous.is_some_and(|text| text.starts_with(TYPE_MAGIC)) && value.is_some() && previous != value {
        return Err(
            "assertion-backed types cannot be overwritten; remove their dependent declarations first".to_owned()
        );
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DebugLayoutType {
    pub original_name: String,
    pub unit_offset: u64,
    pub die_offset: u64,
    pub layout: PlainStructLayout,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DebugLayoutFunction {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub original_name: String,
    pub unit_offset: u64,
    pub die_offset: u64,
    pub declaration: String,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DebugLayoutReport {
    pub types: Vec<DebugLayoutType>,
    pub functions: Vec<DebugLayoutFunction>,
    pub warnings: Vec<String>,
}

/// Immutable consent for one exact project's retained mapping, selected image and compiler options.
/// This is process-local and deliberately has no deserialization or project-rebinding API.
pub struct DebugLayoutPreview<'project> {
    project: &'project Project,
    image_sha256: [u8; 32],
    options: rampage_decompiler::DecompilerOptions,
    specifications: SpecIdentity,
    compiler_spec_sha256: [u8; 32],
    producer: Option<rampage_loaders::debug::DebugLayoutReport>,
    report: DebugLayoutReport,
    approved: Vec<DebugLayoutFunction>,
    preserved: Vec<u64>,
}

impl std::fmt::Debug for DebugLayoutPreview<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DebugLayoutPreview")
            .field("image_sha256", &self.image_sha256)
            .field("report", &self.report)
            .field("approved", &self.approved)
            .field("preserved", &self.preserved)
            .finish_non_exhaustive()
    }
}

impl DebugLayoutPreview<'_> {
    pub fn image_sha256(&self) -> &[u8; 32] {
        &self.image_sha256
    }
    pub fn compiler_spec_sha256(&self) -> &[u8; 32] {
        &self.compiler_spec_sha256
    }
    pub fn report(&self) -> &DebugLayoutReport {
        &self.report
    }
    pub fn approved(&self) -> &[DebugLayoutFunction] {
        &self.approved
    }
    pub fn preserved(&self) -> &[u64] {
        &self.preserved
    }
    /// Exact bounded loader facts, including unknown producer alignments and preview-only candidates.
    pub fn producer_report(&self) -> Option<&rampage_loaders::debug::DebugLayoutReport> {
        self.producer.as_ref()
    }
}

#[derive(Debug, serde::Serialize)]
pub struct DebugLayoutImport {
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub applied: Vec<u64>,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub preserved: Vec<u64>,
    pub imported_types: Vec<String>,
}

fn reserved(annotations: &Annotations) -> Result<BTreeSet<String>, ApiError> {
    let mut bytes = 0usize;
    let mut names = BTreeSet::new();
    for text in annotations
        .types()
        .values()
        .chain(annotations.globals().values())
        .chain(annotations.signatures().values())
        .chain(annotations.names().values())
    {
        bytes = bytes.checked_add(text.len()).ok_or_else(|| invalid("name scan overflow"))?;
        if bytes > MAX_NAME_WORK {
            return Err(invalid("name scan byte limit exceeded"));
        }
        for word in words(text) {
            if names.len() == 8192 && !names.contains(word) {
                return Err(invalid("name scan token limit exceeded"));
            }
            names.insert(word.to_owned());
        }
    }
    if annotations.types().len() + annotations.globals().len() + annotations.signatures().len() > 1024 {
        return Err(invalid("existing declaration count exceeds the checked native-work budget"));
    }
    Ok(names)
}

fn validate_report(report: &DebugLayoutReport) -> Result<(), ApiError> {
    if report.types.len() > MAX_LAYOUTS || report.functions.len() > MAX_FUNCTIONS || report.warnings.len() > 128 {
        return Err(invalid("producer report count limit exceeded"));
    }
    let mut bytes = 0usize;
    let mut fields = 0usize;
    let mut names = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut functions = BTreeSet::new();
    for ty in &report.types {
        ty.layout.validate().map_err(|error| invalid(&error.to_string()))?;
        bytes += ty.original_name.len();
        fields += ty.layout.fields.len();
        if ty.original_name.len() > 128 || !names.insert(ty.layout.name.as_str()) || fields > MAX_FIELDS {
            return Err(invalid("ambiguous type identity or cumulative field/name limit exceeded"));
        }
        for field in &ty.layout.fields {
            if matches!(&field.ty, LayoutType::Pointer { name, .. } if !name.is_empty()) {
                return Err(invalid("named pointer aliases require unsupported declaration dependencies"));
            }
        }
        bytes += serde_json::to_string(&ty.layout).map_err(|error| invalid(&error.to_string()))?.len();
    }
    for function in &report.functions {
        if function.original_name.len() > 128
            || function.declaration.len() > 4095
            || function.dependencies.is_empty()
            || function.dependencies.len() > MAX_LAYOUTS
            || !addresses.insert(function.address)
            || !functions.insert(&function.original_name)
        {
            return Err(invalid("ambiguous function identity or signature limit exceeded"));
        }
        bytes += function.original_name.len() + function.declaration.len();
        let mut seen = BTreeSet::new();
        for dependency in &function.dependencies {
            if dependency.len() > 128 || !names.contains(dependency.as_str()) || !seen.insert(dependency.as_str()) {
                return Err(invalid("missing or duplicate producer type dependency"));
            }
            bytes += dependency.len();
        }
        for name in &names {
            if words(&function.declaration).any(|word| word == *name) != seen.contains(name) {
                return Err(invalid("producer declaration and exact dependency closure disagree"));
            }
        }
    }
    for warning in &report.warnings {
        if warning.len() > 1024 {
            return Err(invalid("producer warning byte limit exceeded"));
        }
        bytes += warning.len();
    }
    if bytes > MAX_IMPORT_TEXT {
        return Err(invalid("producer report text limit exceeded"));
    }
    Ok(())
}

impl Project {
    /// Checks embedded producer layouts separately from the legacy scalar-only debug importer.
    /// Explicit producer struct alignment is required; optional leaf alignment is never promoted to a producer fact.
    pub fn preview_debug_layouts(&self) -> Result<DebugLayoutPreview<'_>, ApiError> {
        let digest = image_digest(self)?;
        check_backing(self)?;
        let producer = rampage_loaders::debug::layout_signatures(&self.binary);
        check_backing(self)?;
        let producer = producer.map_err(|error| invalid(&error.to_string()))?;
        let report = adapt_producer(&producer)?;
        let mut preview = self.preview_debug_layout_plan(report)?;
        if preview.image_sha256 != digest {
            return Err(invalid("selected image changed during producer discovery"));
        }
        let eligible: BTreeSet<_> = preview.report.functions.iter().map(|function| function.address).collect();
        preview.preserved.extend(
            producer
                .signatures
                .iter()
                .filter(|function| !eligible.contains(&function.address))
                .map(|function| function.address),
        );
        preview.preserved.sort_unstable();
        preview.preserved.dedup();
        preview.producer = Some(producer);
        Ok(preview)
    }

    pub(crate) fn preview_debug_layout_plan(
        &self,
        mut report: DebugLayoutReport,
    ) -> Result<DebugLayoutPreview<'_>, ApiError> {
        let image_sha256 = image_digest(self)?;
        let specifications = specification_identity()?;
        validate_report(&report)?;
        check_backing(self)?;
        let analysis = self.analysis();
        check_backing(self)?;
        let analysis = analysis?;
        if analysis.program.functions.len() > 16_384 {
            return Err(invalid("discovered function count exceeds the checked native-work budget"));
        }
        validate_native_work(self)?;
        let entries: BTreeSet<_> = analysis.program.functions.iter().map(|function| function.address).collect();
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        self.check_layout_options(&options)?;
        let snapshot = self.annotations().checked_snapshot()?;
        let (approved, preserved) = (|| {
            let reserved = reserved(&snapshot)?;
            let mut approved = Vec::new();
            let mut preserved = Vec::new();
            for function in &mut report.functions {
                function.declaration = crate::debug_import::safe_declaration_names(&function.declaration, &reserved);
                if entries.contains(&function.address)
                    && self.binary.is_code(function.address)
                    && layout_function_eligible(&snapshot, function)
                {
                    approved.push(function.clone());
                } else {
                    preserved.push(function.address);
                }
            }
            let (changes, imported_types) = layout_changes(&report, &approved, &image_sha256)?;
            let needed: BTreeSet<_> = imported_types.iter().map(String::as_str).collect();
            let types: Vec<_> =
                report.types.iter().filter(|ty| needed.contains(ty.layout.name.as_str())).cloned().collect();
            self.check_layout_type_names(&types, &reserved)?;
            let mut candidate = snapshot.snapshot();
            for (field, address, value) in changes {
                candidate.set(field, address, value).map_err(ApiError::Invalid)?;
            }
            check_backing(self)?;
            let validated = self.validate_annotation_snapshot(&state, &options, &candidate);
            check_backing(self)?;
            validated.map_err(ApiError::Invalid)?;
            if image_digest(self)? != image_sha256 {
                return Err(invalid("selected image changed during preview"));
            }
            if specification_identity()? != specifications {
                return Err(invalid("processor specifications changed during preview"));
            }
            Ok((approved, preserved))
        })()?;
        let mut hash = Sha256::new();
        specifications.feed_manifest_identity(|bytes| hash.update(bytes));
        let compiler_spec_sha256 = hash.finalize().into();
        Ok(DebugLayoutPreview {
            project: self,
            image_sha256,
            options,
            specifications,
            compiler_spec_sha256,
            producer: None,
            report,
            approved,
            preserved,
        })
    }

    /// Applies only cached preview-approved functions and their necessary type dependencies in one undo step.
    /// Observable source changes are refused, without claiming an atomic filesystem snapshot or authentication.
    pub fn apply_debug_layouts(&self, preview: &DebugLayoutPreview<'_>) -> Result<DebugLayoutImport, ApiError> {
        if !std::ptr::eq(self, preview.project) {
            return Err(invalid("preview belongs to a different project; preview again"));
        }
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        if options != preview.options
            || image_digest(self)? != preview.image_sha256
            || specification_identity()? != preview.specifications
        {
            return Err(invalid("selected image or compiler options changed since preview"));
        }
        self.check_layout_options(&options)?;
        self.annotations.write().expect("annotations lock").locked_staged_checked(|annotations| {
            let reserved = reserved(annotations)?;
            let mut preserved = preview.preserved.clone();
            let mut approved = Vec::new();
            for function in &preview.approved {
                if layout_function_eligible(annotations, function) {
                    if crate::debug_import::safe_declaration_names(&function.declaration, &reserved)
                        != function.declaration
                    {
                        return Err(invalid("declaration identifiers now conflict with analyst declarations"));
                    }
                    approved.push(function.clone());
                } else {
                    preserved.push(function.address);
                }
            }
            let (changes, imported_types) = layout_changes(&preview.report, &approved, &preview.image_sha256)?;
            let needed: BTreeSet<_> = imported_types.iter().map(String::as_str).collect();
            let types: Vec<_> =
                preview.report.types.iter().filter(|ty| needed.contains(ty.layout.name.as_str())).cloned().collect();
            self.check_layout_type_names(&types, &reserved)?;
            if image_digest(self)? != preview.image_sha256 {
                return Err(invalid("selected image changed before commit validation"));
            }
            let applied: Vec<_> = approved.iter().map(|function| function.address).collect();
            preserved.sort_unstable();
            annotations
                .set_batch_validated(&changes, |candidate| {
                    check_backing(self).map_err(|error| error.to_string())?;
                    let validated = self.validate_annotation_snapshot(&state, &options, candidate);
                    check_backing(self).map_err(|error| error.to_string())?;
                    validated?;
                    if image_digest(self).map_err(|error| error.to_string())? != preview.image_sha256 {
                        return Err("selected image changed after commit validation".to_owned());
                    }
                    if specification_identity().map_err(|error| error.to_string())? != preview.specifications {
                        return Err("processor specifications changed after commit validation".to_owned());
                    }
                    Ok(())
                })
                .map_err(ApiError::Invalid)?;
            Ok(DebugLayoutImport { applied, preserved, imported_types })
        })
    }

    fn check_layout_options(&self, options: &rampage_decompiler::DecompilerOptions) -> Result<(), ApiError> {
        if self.binary.format != rampage_loaders::Format::Elf
            || self.binary.arch != rampage_arch::Arch::X86_64
            || self.binary.big_endian
            || options.platform != rampage_decompiler::Platform::Default
            || options.compiler.as_deref().is_some_and(|compiler| compiler != "gcc")
            || options.arm_be8
        {
            return Err(invalid("requires embedded x86-64 little-endian ELF and the default gcc specification"));
        }
        Ok(())
    }

    fn check_layout_type_names(&self, types: &[DebugLayoutType], reserved: &BTreeSet<String>) -> Result<(), ApiError> {
        for ty in types {
            if reserved.contains(&ty.layout.name) || self.symbol_address(&ty.layout.name).is_some() {
                return Err(invalid("producer type name conflicts with existing declarations or image names"));
            }
        }
        Ok(())
    }
}

fn layout_function_eligible(annotations: &Annotations, function: &DebugLayoutFunction) -> bool {
    !annotations.signatures().contains_key(&function.address) && !annotations.types().contains_key(&function.address)
}

type LayoutChanges = Vec<(Field, u64, Option<String>)>;

fn layout_changes(
    report: &DebugLayoutReport,
    functions: &[DebugLayoutFunction],
    image: &[u8; 32],
) -> Result<(LayoutChanges, Vec<String>), ApiError> {
    let Some(owner) = functions.first() else { return Ok((Vec::new(), Vec::new())) };
    let dependencies: BTreeSet<_> = functions.iter().flat_map(|function| function.dependencies.iter()).collect();
    let layouts: Vec<_> =
        report.types.iter().filter(|ty| dependencies.contains(&ty.layout.name)).map(|ty| ty.layout.clone()).collect();
    let text = LayoutBundle::encode(image, &layouts)?;
    let bundle = LayoutBundle::decode(&text)?.ok_or_else(|| invalid("invalid generated bundle"))?;
    let mut changes = vec![(Field::Types, owner.address, Some(text))];
    for function in functions {
        let dependencies: Vec<_> = function
            .dependencies
            .iter()
            .map(|name| {
                bundle
                    .layouts
                    .iter()
                    .find(|stored| stored.layout.name == *name)
                    .ok_or_else(|| invalid("missing generated signature dependency"))
            })
            .collect::<Result<_, _>>()?;
        changes.push((Field::Signature, function.address, Some(seal_signature(&function.declaration, &dependencies)?)));
    }
    let imported = bundle.layouts.iter().map(|stored| stored.layout.name.clone()).collect();
    Ok((changes, imported))
}

fn scalar_descriptor(scalar: &rampage_loaders::debug::DebugLayoutScalar) -> Result<LayoutScalar, ApiError> {
    use rampage_loaders::debug::DebugLayoutScalarKind;
    let size = u32::try_from(scalar.byte_size).map_err(|_| invalid("scalar size overflow"))?;
    let semantic_encoding = match scalar.kind {
        DebugLayoutScalarKind::SignedInteger => scalar.encoding == 5 || (scalar.encoding == 6 && size == 1),
        DebugLayoutScalarKind::UnsignedInteger => scalar.encoding == 7 || (scalar.encoding == 8 && size == 1),
        DebugLayoutScalarKind::Float => scalar.encoding == 4,
        DebugLayoutScalarKind::Boolean => scalar.encoding == 2,
    };
    if !semantic_encoding {
        return Err(invalid("producer scalar encoding/category disagreement"));
    }
    let (name, kind) = match (scalar.kind, size) {
        (DebugLayoutScalarKind::SignedInteger, 1 | 2 | 4 | 8) => (format!("int{size}"), ScalarKind::SignedInteger),
        (DebugLayoutScalarKind::UnsignedInteger, 1 | 2 | 4 | 8) => (format!("uint{size}"), ScalarKind::UnsignedInteger),
        (DebugLayoutScalarKind::Float, 4 | 8) => (format!("float{size}"), ScalarKind::Float),
        (DebugLayoutScalarKind::Boolean, 1) => ("bool".to_owned(), ScalarKind::Bool),
        _ => return Err(invalid("unsupported producer scalar")),
    };
    let producer_declaration = match scalar.kind {
        DebugLayoutScalarKind::SignedInteger => format!("int{}_t", size * 8),
        DebugLayoutScalarKind::UnsignedInteger => format!("uint{}_t", size * 8),
        DebugLayoutScalarKind::Float if size == 4 => "float".to_owned(),
        DebugLayoutScalarKind::Float => "double".to_owned(),
        DebugLayoutScalarKind::Boolean => "bool".to_owned(),
    };
    if scalar.declaration != producer_declaration {
        return Err(invalid("producer scalar declaration disagrees with its verified semantic encoding"));
    }
    // These are required consumer facts, verified by the native assertion, not inferred producer facts.
    let alignment = size;
    if scalar.producer_alignment.is_some_and(|producer| producer != u64::from(alignment)) {
        return Err(invalid("producer scalar alignment conflicts with the admitted consumer organization"));
    }
    Ok(LayoutScalar { name, kind, size, alignment })
}

fn leaf_descriptor(leaf: &rampage_loaders::debug::DebugLayoutLeaf) -> Result<LayoutType, ApiError> {
    use rampage_loaders::debug::DebugLayoutLeaf;
    match leaf {
        DebugLayoutLeaf::Scalar { scalar } => Ok(LayoutType::Scalar { scalar: scalar_descriptor(scalar)? }),
        DebugLayoutLeaf::Pointer { byte_size, producer_alignment, pointee, .. } => {
            if *byte_size != 8 || producer_alignment.is_some_and(|alignment| alignment != 8) {
                return Err(invalid("producer pointer facts conflict with the admitted consumer organization"));
            }
            let pointee = match pointee {
                Some(scalar) => scalar_descriptor(scalar)?,
                None => LayoutScalar { name: "void".to_owned(), kind: ScalarKind::Void, size: 0, alignment: 1 },
            };
            Ok(LayoutType::Pointer { name: String::new(), size: 8, alignment: 8, pointee })
        }
    }
}

fn leaf_text(leaf: &rampage_loaders::debug::DebugLayoutLeaf) -> Result<String, ApiError> {
    match leaf_descriptor(leaf)? {
        LayoutType::Scalar { scalar } => Ok(scalar.name),
        LayoutType::Pointer { pointee, .. } => Ok(format!("{} *", pointee.name)),
    }
}

fn value_text(
    value: &rampage_loaders::debug::DebugLayoutValue,
    types: &BTreeMap<rampage_loaders::debug::DebugLayoutTypeId, String>,
    allow_struct: bool,
) -> Result<String, ApiError> {
    use rampage_loaders::debug::DebugLayoutValue;
    match value {
        DebugLayoutValue::Void => Ok("void".to_owned()),
        DebugLayoutValue::Leaf { leaf } => leaf_text(leaf),
        DebugLayoutValue::StructPointer { layout_id, byte_size, producer_alignment, .. }
            if allow_struct && *byte_size == 8 =>
        {
            if producer_alignment.is_some_and(|alignment| alignment != 8) {
                return Err(invalid("producer struct-pointer alignment conflicts with the consumer organization"));
            }
            let name = types.get(layout_id).ok_or_else(|| invalid("missing applicable producer struct dependency"))?;
            Ok(format!("{name} *"))
        }
        _ => Err(invalid("unsupported struct value or pointer width")),
    }
}

fn adapt_producer(producer: &rampage_loaders::debug::DebugLayoutReport) -> Result<DebugLayoutReport, ApiError> {
    if producer.layouts.len() > MAX_LAYOUTS
        || producer.signatures.len() > MAX_FUNCTIONS
        || producer.warnings.len() > 128
    {
        return Err(invalid("producer report count limit exceeded"));
    }
    let mut report = DebugLayoutReport { warnings: producer.warnings.clone(), ..DebugLayoutReport::default() };
    let mut types = BTreeMap::new();
    let mut ids = BTreeSet::new();
    let mut bytes = 0usize;
    let mut fields = 0usize;
    for layout in &producer.layouts {
        if !ids.insert(layout.id) || layout.fields.len() > 128 || layout.emitted_name.len() > 128 {
            return Err(invalid("ambiguous producer type identity or field/name limit exceeded"));
        }
        fields += layout.fields.len();
        bytes += layout.emitted_name.len() + layout.original_name.as_ref().map_or(0, String::len);
        for field in &layout.fields {
            bytes += field.emitted_name.len() + field.original_name.as_ref().map_or(0, String::len);
            if field.emitted_name.len() > 128 || field.original_name.as_ref().is_some_and(|name| name.len() > 128) {
                return Err(invalid("producer field name byte limit exceeded"));
            }
        }
        if fields > MAX_FIELDS || bytes > MAX_IMPORT_TEXT {
            return Err(invalid("producer field/text limit exceeded"));
        }
        let Some(alignment) = layout.producer_alignment.filter(|_| layout.eligible_for_native_verification) else {
            continue;
        };
        let mut converted = Vec::new();
        for field in &layout.fields {
            let ty = leaf_descriptor(&field.leaf)?;
            let consumer_alignment = match &ty {
                LayoutType::Scalar { scalar } => scalar.alignment,
                LayoutType::Pointer { alignment, .. } => *alignment,
            };
            if field.producer_alignment.is_some_and(|producer| producer != u64::from(consumer_alignment)) {
                return Err(invalid("explicit member alignment differs from the exact consumer field descriptor"));
            }
            converted.push(LayoutField {
                name: field.emitted_name.clone(),
                offset: u32::try_from(field.offset).map_err(|_| invalid("field offset overflow"))?,
                size: u32::try_from(field.byte_size).map_err(|_| invalid("field size overflow"))?,
                ty,
            });
        }
        let native = PlainStructLayout {
            name: layout.emitted_name.clone(),
            size: u32::try_from(layout.byte_size).map_err(|_| invalid("struct size overflow"))?,
            alignment: u32::try_from(alignment).map_err(|_| invalid("struct alignment overflow"))?,
            organization: LayoutOrganization {
                pointer_size: 8,
                int_size: 4,
                long_size: 8,
                scalar_alignments: [1, 2, 4, 8],
            },
            fields: converted,
        };
        native.validate().map_err(|error| invalid(&error.to_string()))?;
        types.insert(layout.id, native.name.clone());
        report.types.push(DebugLayoutType {
            original_name: layout.original_name.clone().unwrap_or_default(),
            unit_offset: layout.id.unit_offset,
            die_offset: layout.id.die_offset,
            layout: native,
        });
    }
    let mut seen = BTreeSet::new();
    for function in &producer.signatures {
        let original_name = method_identity_name(function)?;
        if !seen.insert(function.id)
            || function.parameters.len() > 32
            || function.dependencies.len() > MAX_LAYOUTS
            || function.emitted_name.len() > 128
            || function.original_name.len() > 128
            || function.declaration.len() > 4095
        {
            return Err(invalid("producer function identity/parameter/name limit exceeded"));
        }
        bytes += function.emitted_name.len() + function.original_name.len() + function.declaration.len();
        for parameter in &function.parameters {
            bytes += parameter.emitted_name.len() + parameter.original_name.as_ref().map_or(0, String::len);
            if parameter.emitted_name.len() > 128
                || parameter.original_name.as_ref().is_some_and(|name| name.len() > 128)
            {
                return Err(invalid("producer parameter name limit exceeded"));
            }
        }
        if bytes > MAX_IMPORT_TEXT {
            return Err(invalid("producer cumulative text limit exceeded"));
        }
        if !function.eligible_for_native_verification || function.dependencies.iter().any(|id| !types.contains_key(id))
        {
            continue;
        }
        let mut parameters = Vec::new();
        for parameter in &function.parameters {
            parameters.push(format!("{} {}", value_text(&parameter.ty, &types, true)?, parameter.emitted_name));
        }
        let declaration = format!(
            "{} {}({});",
            value_text(&function.return_type, &types, false)?,
            function.emitted_name,
            if parameters.is_empty() { "void".to_owned() } else { parameters.join(", ") }
        );
        report.functions.push(DebugLayoutFunction {
            address: function.address,
            original_name: original_name.to_owned(),
            unit_offset: function.id.unit_offset,
            die_offset: function.id.die_offset,
            declaration,
            dependencies: function.dependencies.iter().map(|id| types[id].clone()).collect(),
        });
    }
    validate_report(&report)?;
    Ok(report)
}

fn method_identity_name(function: &rampage_loaders::debug::DebugLayoutSignature) -> Result<&str, ApiError> {
    let Some(method) = &function.method else { return Ok(&function.original_name) };
    let unit = function.id.unit_offset;
    if method.linkage_name.is_empty()
        || method.linkage_name.len() > 128
        || method.record_id.unit_offset != unit
        || method.declaration_id.unit_offset != unit
        || method.object_pointer_id.unit_offset != unit
        || function.parameters.first().is_none_or(|parameter| {
            parameter.id != method.object_pointer_id
                || !matches!(&parameter.ty,
                    rampage_loaders::debug::DebugLayoutValue::StructPointer { layout_id, .. }
                    if *layout_id == method.record_id)
        })
        || !function.dependencies.contains(&method.record_id)
    {
        return Err(invalid("C++ method projection lacks its exact object-pointer/record/linkage association"));
    }
    Ok(&method.linkage_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TestFiles {
        log: PathBuf,
    }

    impl TestFiles {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Self { log: std::env::temp_dir().join(format!("rampage-layout-core-{}-{index}.jsonl", std::process::id())) }
        }
    }

    impl Drop for TestFiles {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.log);
            let _ = std::fs::remove_file(PathBuf::from(format!("{}.lock", self.log.display())));
        }
    }

    pub(super) fn binary() -> rampage_loaders::Binary {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
        rampage_loaders::Binary::open(fixture).unwrap()
    }

    fn layout() -> PlainStructLayout {
        PlainStructLayout {
            name: "owned_record".to_owned(),
            size: 16,
            alignment: 8,
            organization: LayoutOrganization {
                pointer_size: 8,
                int_size: 4,
                long_size: 8,
                scalar_alignments: [1, 2, 4, 8],
            },
            fields: vec![
                LayoutField {
                    name: "serial".to_owned(),
                    offset: 0,
                    size: 8,
                    ty: LayoutType::Scalar {
                        scalar: LayoutScalar {
                            name: "uint8".to_owned(),
                            kind: ScalarKind::UnsignedInteger,
                            size: 8,
                            alignment: 8,
                        },
                    },
                },
                LayoutField {
                    name: "count".to_owned(),
                    offset: 8,
                    size: 4,
                    ty: LayoutType::Scalar {
                        scalar: LayoutScalar {
                            name: "int4".to_owned(),
                            kind: ScalarKind::SignedInteger,
                            size: 4,
                            alignment: 4,
                        },
                    },
                },
            ],
        }
    }

    pub(super) fn plan(project: &Project) -> DebugLayoutReport {
        let address = project.resolve("debug_mix").unwrap();
        DebugLayoutReport {
            types: vec![DebugLayoutType {
                original_name: "owned_record".to_owned(),
                unit_offset: 0,
                die_offset: 1,
                layout: layout(),
            }],
            functions: vec![DebugLayoutFunction {
                address,
                original_name: "debug_mix".to_owned(),
                unit_offset: 0,
                die_offset: 2,
                declaration: "int4 debug_mix(owned_record *record);".to_owned(),
                dependencies: vec!["owned_record".to_owned()],
            }],
            warnings: Vec::new(),
        }
    }

    #[test]
    fn bounded_wire_rejects_duplicate_keys_and_unknown_versions() {
        let valid = LayoutBundle::encode(&[7; 32], &[layout()]).unwrap();
        let bad = valid.replace("\"size\":16", "\"size\":16,\"size\":16");
        assert!(LayoutBundle::decode(&bad).is_err());
        assert!(LayoutBundle::decode("!rampage-plain-layout-v2\n").is_err());
        assert!(LayoutBundle::decode(&format!("{TYPE_MAGIC}{}", " ".repeat(MAX_BUNDLE_BYTES))).is_err());
    }

    #[test]
    fn pinned_manifest_fingerprint_matches_the_independent_sha2_implementation() {
        let specifications = specification_identity().unwrap();
        let mut reference = Sha256::new();
        specifications.feed_manifest_identity(|bytes| reference.update(bytes));
        let reference: [u8; 32] = reference.finalize().into();
        assert_eq!(specifications.manifest_sha256(), reference);
        assert_eq!(current_specification_digest().unwrap(), rampage_arch::hex::bytes(&reference));
    }

    #[test]
    fn type_and_prototype_bundle_fails_closed_without_its_exact_assertion() {
        let text = LayoutBundle::encode(&[7; 32], &[layout()]).unwrap();
        let bundle = LayoutBundle::decode(&text).unwrap().unwrap();
        let sealed = seal_signature("int4 f(owned_record *record);", &[&bundle.layouts[0]]).unwrap();
        assert!(text.starts_with('!') && sealed.starts_with('!'));
        assert!(signature(&sealed, &BTreeMap::new()).is_err());
        let mut altered = BTreeMap::new();
        altered.insert("owned_record".to_owned(), "0".repeat(64));
        assert!(signature(&sealed, &altered).is_err());
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Types, 1, Some(text.clone())).unwrap();
        annotations.set(Field::Signature, 1, Some(sealed.clone())).unwrap();
        assert!(annotations.set(Field::Types, 1, None).is_err());
        assert!(annotations.set(Field::Types, 1, Some(declaration(&layout()))).is_err());
        let changes = [(Field::Signature, 1, None), (Field::Types, 1, None)];
        annotations.set_batch_validated(&changes, |_| Ok(())).unwrap();
        assert!(annotations.types().is_empty() && annotations.signatures().is_empty());
    }

    #[test]
    fn producer_declaration_dependency_ambiguity_is_rejected_before_native_work() {
        let project = Project::new(binary());
        let mut report = plan(&project);
        report.functions[0].dependencies.clear();
        assert!(validate_report(&report).is_err());
        let mut report = plan(&project);
        let mut duplicate = report.functions[0].clone();
        duplicate.address += 1;
        report.functions.push(duplicate);
        assert!(validate_report(&report).is_err());
    }

    #[test]
    fn scalar_semantics_do_not_follow_display_names_and_explicit_pointer_alignment_is_checked() {
        use rampage_loaders::debug::{DebugLayoutScalar, DebugLayoutScalarKind, DebugLayoutTypeId, DebugLayoutValue};
        let id = DebugLayoutTypeId { unit_offset: 0, die_offset: 1 };
        let scalar = DebugLayoutScalar {
            id,
            kind: DebugLayoutScalarKind::SignedInteger,
            byte_size: 1,
            encoding: 6,
            producer_alignment: None,
            original_name: Some("misleading_float_name".to_owned()),
            declaration: "int8_t".to_owned(),
        };
        let descriptor = scalar_descriptor(&scalar).unwrap();
        assert_eq!(descriptor.name, "int1");
        assert_eq!(descriptor.kind, ScalarKind::SignedInteger);
        let types = BTreeMap::from([(id, "owned_record".to_owned())]);
        let value = DebugLayoutValue::StructPointer {
            pointer_id: DebugLayoutTypeId { unit_offset: 0, die_offset: 2 },
            layout_id: id,
            byte_size: 8,
            producer_alignment: Some(4),
        };
        assert!(value_text(&value, &types, true).is_err());
    }

    #[test]
    fn replay_rejects_selected_and_aggregate_mapping_bytes_before_native_copying() {
        struct OwnedImage(PathBuf);
        impl Drop for OwnedImage {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        for (length, aliases, reason) in [
            (MAX_CHECKED_IMAGE_BYTES + 1, 1, "selected image exceeds"),
            (MAX_CHECKED_IMAGE_BYTES / 2, 3, "aggregate mapped bytes exceed"),
        ] {
            let files = TestFiles::new();
            let path = files.log.with_extension("sparse.elf");
            let mut output = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
            let _owned = OwnedImage(path.clone());
            let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
            std::io::copy(&mut std::fs::File::open(fixture).unwrap(), &mut output).unwrap();
            output.set_len(length as u64).unwrap();
            drop(output);
            let mut binary = rampage_loaders::Binary::open(&path).unwrap();
            if aliases > 1 {
                let mut segment = binary.segments[0].clone();
                segment.address = 0x1000;
                segment.size = length as u64;
                segment.file_offset = 0;
                segment.file_size = length as u64;
                segment.perms.read = true;
                binary.segments = vec![segment; aliases];
            }
            let project = Project::new(binary);
            let mut annotations = Annotations::in_memory();
            let envelope = LayoutBundle::encode(&[0; 32], &[layout()]).unwrap();
            annotations.set(Field::Types, 0, Some(envelope)).unwrap();
            let error = validate_replay_source(&project, &annotations).unwrap_err().to_string();
            assert!(error.contains(reason), "unexpected pre-copy refusal: {error}");
        }
    }

    #[test]
    fn owned_plan_preview_is_read_only_and_batch_undo_reopens_with_assertions() {
        let files = TestFiles::new();
        let annotations = Annotations::open(files.log.clone()).unwrap();
        let project = Project::with_annotations(binary(), annotations);
        let report = plan(&project);
        let address = report.functions[0].address;
        let preview = project.preview_debug_layout_plan(report).unwrap();
        assert!(!files.log.exists());
        assert!(project.annotation_list().types.is_empty());
        assert!(project.undo().unwrap().is_empty());
        let imported = project.apply_debug_layouts(&preview).unwrap();
        assert_eq!(imported.applied, [address]);
        assert_eq!(imported.imported_types, ["owned_record"]);
        let reopened = Project::with_annotations(binary(), Annotations::open_checked(files.log.clone()).unwrap());
        let state = reopened.decompiler.lock().unwrap();
        let options = crate::decompile::default_options(&reopened.binary);
        reopened.validate_annotation_snapshot(&state, &options, &reopened.annotations()).unwrap();
        drop(state);
        let edits = project.undo().unwrap();
        assert_eq!(edits.len(), 2);
        assert!(project.annotation_list().types.is_empty());
        assert!(project.annotation_list().signatures.is_empty());
        project.redo().unwrap();
        assert_eq!(project.annotation_list().types.len(), 1);
    }

    #[test]
    fn foreign_receipt_compiler_change_layout_mismatch_and_type_collision_refuse() {
        let project = Project::new(binary());
        let report = plan(&project);
        let preview = project.preview_debug_layout_plan(report.clone()).unwrap();
        let other = Project::new(binary());
        assert!(other.apply_debug_layouts(&preview).unwrap_err().to_string().contains("different project"));
        project.set_decompiler_options(Some(rampage_decompiler::DecompilerOptions {
            compiler: Some("windows".to_owned()),
            ..rampage_decompiler::DecompilerOptions::default()
        }));
        assert!(project.apply_debug_layouts(&preview).is_err());
        project.set_decompiler_options(None);
        let mut wrong = report.clone();
        wrong.types[0].layout.size = 24;
        assert!(project.preview_debug_layout_plan(wrong).is_err());
        project.set_types(0, Some("typedef int4 owned_record;")).unwrap();
        assert!(project.preview_debug_layout_plan(report).is_err());
        assert!(project.annotation_list().signatures.is_empty());
    }

    #[test]
    fn shared_edits_shrink_consent_and_clears_do_not_enlarge_it_or_leave_orphan_types() {
        let files = TestFiles::new();
        let project = Project::with_annotations(binary(), Annotations::open(files.log.clone()).unwrap());
        let address = project.resolve("debug_mix").unwrap();
        let original = "int4 analyst(void);".to_owned();
        let mut external = Annotations::open(files.log.clone()).unwrap();
        external.set(Field::Signature, address, Some(original.clone())).unwrap();
        let preserved_preview = project.preview_debug_layout_plan(plan(&project)).unwrap();
        assert!(preserved_preview.approved().is_empty());
        external.set(Field::Signature, address, None).unwrap();
        let imported = project.apply_debug_layouts(&preserved_preview).unwrap();
        assert!(imported.applied.is_empty() && imported.imported_types.is_empty());
        let approved_preview = project.preview_debug_layout_plan(plan(&project)).unwrap();
        external.set(Field::Signature, address, Some(original.clone())).unwrap();
        let imported = project.apply_debug_layouts(&approved_preview).unwrap();
        assert_eq!(imported.preserved, [address]);
        assert!(imported.imported_types.is_empty() && project.annotation_list().types.is_empty());
        assert_eq!(project.annotations().signatures().get(&address), Some(&original));
    }

    #[test]
    fn late_failed_native_validation_keeps_cache_and_external_disk_edits_unpublished() {
        let files = TestFiles::new();
        let project = Project::with_annotations(binary(), Annotations::open(files.log.clone()).unwrap());
        project.comment(1, Some("earlier undo step")).unwrap();
        let preview = project.preview_debug_layout_plan(plan(&project)).unwrap();
        let mut external = Annotations::open(files.log.clone()).unwrap();
        external.set(Field::Comment, 1, Some("external comment".to_owned())).unwrap();
        external.set(Field::Types, 0, Some("this is not a C declaration;".to_owned())).unwrap();
        let bytes = std::fs::read(&files.log).unwrap();
        let before = serde_json::to_string(&project.annotation_list()).unwrap();
        assert!(project.apply_debug_layouts(&preview).is_err());
        assert_eq!(serde_json::to_string(&project.annotation_list()).unwrap(), before);
        assert_eq!(std::fs::read(&files.log).unwrap(), bytes);
        assert!(project.refresh_annotations().unwrap());
        assert_eq!(project.comment_at(1).as_deref(), Some("external comment"));
    }
}
