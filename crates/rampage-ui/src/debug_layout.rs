//! Explicit review of checked embedded layouts; only a current review can authorize the synchronous apply.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use egui::{Key, Modifiers, RichText, Ui};
use rampage_api::{DebugLayoutProjection, DebugLayoutReview, DebugLayoutType, Project};
use rampage_arch::Arch;
use rampage_loaders::{Format, debug};

use crate::theme;
use crate::workspace::{Job, Workspace};

const STALE: &str = "Review is no longer current. Preview again and review the changes before applying.";
const PENDING: &str = "A previous preview is still running. Wait for it to finish, then preview again.";
const SCOPE: &str = concat!(
    "Scope: embedded x86_64 little-endian ELF DWARF, default gcc; C flat structs and producer-described ",
    "base-free C++ records with explicit mutable this methods, including checked opaque vptr storage projections."
);

#[derive(Clone, Default)]
pub(crate) struct PreviewGate(Arc<AtomicBool>);

impl PreviewGate {
    fn is_running(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn try_acquire(&self) -> Option<PreviewPermit> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| PreviewPermit(Arc::clone(&self.0)))
    }
}

struct PreviewPermit(Arc<AtomicBool>);

impl Drop for PreviewPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct Binding {
    instance: Arc<()>,
    project: Arc<Project>,
    epoch: Arc<()>,
    revision: Arc<()>,
}

impl Binding {
    fn capture(workspace: &Workspace, revision: &Arc<()>) -> Self {
        Self {
            instance: Arc::clone(&workspace.instance),
            project: Arc::clone(&workspace.project),
            epoch: Arc::clone(&workspace.annotations_epoch),
            revision: Arc::clone(revision),
        }
    }

    fn matches(&self, workspace: &Workspace, revision: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.instance, &workspace.instance)
            && Arc::ptr_eq(&self.project, &workspace.project)
            && Arc::ptr_eq(&self.epoch, &workspace.annotations_epoch)
            && Arc::ptr_eq(&self.revision, revision)
    }
}

struct Reply {
    binding: Binding,
    review: DebugLayoutReview,
}

pub(crate) struct DebugLayouts {
    shown: bool,
    blocking: bool,
    gate: PreviewGate,
    revision: Arc<()>,
    /// Retained until completion, even while hidden, so native preview work stays bounded to one job.
    job: Job<DebugLayoutReview>,
    job_binding: Option<Binding>,
    reply: Option<Reply>,
    error: Option<String>,
}

impl Default for DebugLayouts {
    fn default() -> Self {
        Self {
            shown: false,
            blocking: false,
            gate: PreviewGate::default(),
            revision: Arc::new(()),
            job: Job::Idle,
            job_binding: None,
            reply: None,
            error: None,
        }
    }
}

impl DebugLayouts {
    pub fn with_gate(gate: PreviewGate) -> Self {
        Self { gate, ..Self::default() }
    }

    pub fn shown(&self) -> bool {
        self.shown
    }

    pub fn invalidate(&mut self) {
        self.revision = Arc::new(());
        if self.job.is_running() || self.reply.is_some() {
            self.error = Some(STALE.to_owned());
        }
    }

    fn close(&mut self) {
        self.invalidate();
        self.shown = false;
        self.reply = None;
        self.error = None;
    }

    pub fn start(&mut self, workspace: &Workspace, ctx: &egui::Context, blocking: bool) {
        let project = Arc::clone(&workspace.project);
        self.start_job(workspace, ctx, blocking, move || project.review_debug_layouts().map_err(error_text));
    }

    fn start_job(
        &mut self,
        workspace: &Workspace,
        ctx: &egui::Context,
        blocking: bool,
        work: impl FnOnce() -> Result<DebugLayoutReview, String> + Send + 'static,
    ) {
        self.invalidate();
        self.shown = true;
        self.blocking = blocking;
        self.reply = None;
        self.error = None;
        self.poll(workspace);
        if self.job.is_running() {
            self.error = Some(PENDING.to_owned());
            return;
        }
        self.error = None;
        let binary = &workspace.project.binary;
        if binary.format != Format::Elf || binary.arch != Arch::X86_64 || binary.big_endian {
            self.error = Some("This image is outside the supported checked layout scope.".to_owned());
            return;
        }
        let Some(permit) = self.gate.try_acquire() else {
            self.error = Some(PENDING.to_owned());
            return;
        };
        self.job_binding = Some(Binding::capture(workspace, &self.revision));
        self.job.start(blocking, ctx, move || {
            let _permit = permit;
            work()
        });
        self.poll(workspace);
    }

    pub fn poll(&mut self, workspace: &Workspace) {
        self.job.poll();
        if matches!(self.job, Job::Done(_)) {
            let Job::Done(result) = std::mem::replace(&mut self.job, Job::Idle) else { unreachable!() };
            match self.job_binding.take() {
                Some(binding) if self.shown && binding.matches(workspace, &self.revision) => match result {
                    Ok(review) => self.reply = Some(Reply { binding, review }),
                    Err(error) => self.error = Some(error),
                },
                _ if self.shown => self.error = Some(STALE.to_owned()),
                _ => {}
            }
        }
        if self.error.is_none()
            && self.reply.as_ref().is_some_and(|reply| {
                reply.review.imported.is_none() && !reply.binding.matches(workspace, &self.revision)
            })
        {
            self.error = Some(STALE.to_owned());
        }
    }

    fn can_apply(&self, workspace: &Workspace) -> bool {
        self.shown
            && !self.job.is_running()
            && !self.gate.is_running()
            && self.error.is_none()
            && self.reply.as_ref().is_some_and(|reply| {
                reply.binding.matches(workspace, &self.revision)
                    && !reply.review.approved.is_empty()
                    && reply.review.imported.is_none()
            })
    }

    fn apply(&mut self, workspace: &mut Workspace) {
        if !self.can_apply(workspace) {
            self.invalidate();
            self.error = Some(STALE.to_owned());
            return;
        }
        let Some(reply) = &self.reply else { return };
        // Synchronous: the workspace cannot be replaced between the final binding check and the write.
        let result = workspace.project.apply_reviewed_debug_layouts(&reply.review.review_sha256);
        self.invalidate();
        match result {
            Ok(review) => {
                workspace.annotations_changed(None);
                self.reply = Some(Reply { binding: Binding::capture(workspace, &self.revision), review });
                self.error = None;
            }
            Err(error) => {
                self.error = Some(format!("{} No automatic retry; preview again explicitly.", error_text(error)));
            }
        }
    }

    fn can_navigate(&self, workspace: &Workspace) -> bool {
        self.shown
            && !self.job.is_running()
            && !self.gate.is_running()
            && self.error.is_none()
            && self.reply.as_ref().is_some_and(|reply| reply.binding.matches(workspace, &self.revision))
    }

    fn goto_exact_method_entry(&self, workspace: &mut Workspace, address: u64) -> bool {
        if !self.can_navigate(workspace)
            || !self.reply.as_ref().is_some_and(|reply| {
                reply
                    .review
                    .virtual_evidence
                    .tables
                    .iter()
                    .flat_map(|table| &table.methods)
                    .any(|method| method.method_address == address)
            })
        {
            return false;
        }
        workspace.goto(address);
        true
    }

    fn contents(&mut self, ui: &mut Ui, workspace: &mut Workspace) {
        ui.label(SCOPE);
        ui.label(
            "Preview changes nothing. Apply rechecks the complete review fingerprint, \
             then writes one atomic undo step. \
             Producer facts are not proof of ABI compatibility or authentication.",
        );
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.job.is_running() && !self.gate.is_running(), egui::Button::new("Preview again"))
                .clicked()
            {
                self.start(workspace, ui.ctx(), self.blocking);
            }
            if ui.add_enabled(self.can_apply(workspace), egui::Button::new("Apply reviewed changes")).clicked() {
                self.apply(workspace);
            }
            if self.job.is_running() || self.gate.is_running() {
                ui.spinner();
                ui.label("Checking embedded layouts…");
            }
        });
        if let Some(error) = &self.error {
            ui.label(RichText::new(error).color(theme::WARNING));
        }
        let navigation_enabled = self.can_navigate(workspace);
        let Some(reply) = &self.reply else { return };
        let review = &reply.review;
        if let Some(imported) = &review.imported {
            ui.label(
                RichText::new(format!(
                    "Applied {} functions; preserved {} functions; imported {} types. \
                     Undo uses the existing undo command.",
                    imported.applied.len(),
                    imported.preserved.len(),
                    imported.imported_types.len(),
                ))
                .strong(),
            );
        } else if review.approved.is_empty() {
            ui.label("No approved changes. Apply is disabled; producer facts below are preview-only.");
        } else {
            ui.label(format!(
                "Proposed: {} functions, {} necessary types. Preserved: {} functions.",
                review.approved.len(),
                proposed_types(review).len(),
                review.preserved.len(),
            ));
        }
        let mut goto_method = None;
        egui::ScrollArea::vertical().id_salt("checked-layout-review").max_height(470.0).show(ui, |ui| {
            identities(ui, review);
            if let Some(imported) = &review.imported {
                ui.collapsing("Actual applied batch (not the proposal)", |ui| {
                    for address in &imported.applied {
                        ui.label(RichText::new(format!("Applied {address:#x}")).monospace());
                    }
                    for address in &imported.preserved {
                        ui.label(RichText::new(format!("Preserved {address:#x}")).monospace());
                    }
                    for name in &imported.imported_types {
                        ui.label(format!("Imported type: {name}"));
                    }
                });
            }
            proposals(ui, review);
            opaque_projections(ui, review);
            goto_method = virtual_evidence(ui, review, navigation_enabled);
            producer_facts(ui, review);
            warnings(ui, "Checked preview warnings", &review.report.warnings);
        });
        if let Some(address) = goto_method {
            self.goto_exact_method_entry(workspace, address);
        }
    }
}

pub(crate) fn show(ctx: &egui::Context, workspace: &mut Workspace) {
    let mut state = std::mem::take(&mut workspace.debug_layout);
    state.poll(workspace);
    if state.shown {
        let mut shown = true;
        egui::Window::new("Checked debug layout review")
            .open(&mut shown)
            .collapsible(false)
            .default_size(egui::vec2(920.0, 640.0))
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 65.0))
            .show(ctx, |ui| state.contents(ui, workspace));
        let escape = ctx.input_mut(|input| input.consume_key(Modifiers::NONE, Key::Escape));
        if !shown || escape {
            state.close();
        }
    }
    workspace.debug_layout = state;
}

fn error_text(error: rampage_api::ApiError) -> String {
    let mut text = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        text.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    text
}

fn identities(ui: &mut Ui, review: &DebugLayoutReview) {
    ui.heading("Review identities (SHA-256)");
    for (label, digest) in [
        ("Image", &review.image_sha256),
        ("Compiler specification", &review.compiler_spec_sha256),
        ("Complete review", &review.review_sha256),
    ] {
        ui.label(RichText::new(format!("{label}: {digest}")).monospace());
    }
    ui.label("These associate exact review content; they are not authentication or a portable project receipt.");
}

fn proposed_types(review: &DebugLayoutReview) -> BTreeSet<&str> {
    review
        .report
        .functions
        .iter()
        .filter(|function| review.approved.contains(&function.address))
        .flat_map(|function| function.dependencies.iter().map(String::as_str))
        .collect()
}

fn proposals(ui: &mut Ui, review: &DebugLayoutReview) {
    ui.heading(if review.imported.is_some() {
        "Reviewed proposal (see actual applied batch above)"
    } else {
        "Proposed additions from approved functions only"
    });
    for function in review.report.functions.iter().filter(|function| review.approved.contains(&function.address)) {
        ui.label(RichText::new(format!("{:#x} — {}", function.address, function.original_name)).strong());
        ui.label(RichText::new(&function.declaration).monospace());
        ui.label(format!("Necessary types: {}", function.dependencies.join(", ")));
    }
    let needed = proposed_types(review);
    for ty in review.report.types.iter().filter(|ty| needed.contains(ty.layout.name.as_str())) {
        checked_type(ui, ty, true);
    }
    ui.collapsing("Preserved addresses / preview-only final declarations (not proposed additions)", |ui| {
        ui.label("No per-address refusal reason is supplied by the checked API; see its warnings and producer facts.");
        for address in &review.preserved {
            ui.label(RichText::new(format!("Preserved {address:#x}")).monospace());
        }
        for function in review.report.functions.iter().filter(|function| !review.approved.contains(&function.address)) {
            ui.label(RichText::new(format!("{:#x}: {}", function.address, function.declaration)).monospace());
        }
        for ty in review.report.types.iter().filter(|ty| !needed.contains(ty.layout.name.as_str())) {
            checked_type(ui, ty, false);
        }
    });
}

fn checked_type(ui: &mut Ui, ty: &DebugLayoutType, verified: bool) {
    ui.push_id((&ty.layout.name, ty.unit_offset, ty.die_offset), |ui| {
        ui.collapsing(format!("Checked consumer layout: {}", ty.layout.name), |ui| {
            ui.label(if verified {
                "Verified within an approved source closure; see the actual applied batch for import status."
            } else {
                "Unverified consumer layout/fields: not needed by any approved source closure."
            });
            ui.label(format!(
                "Original: {}; unit {:#x}, DIE {:#x}; size {}, consumer alignment {} bytes",
                ty.original_name, ty.unit_offset, ty.die_offset, ty.layout.size, ty.layout.alignment,
            ));
            for (index, field) in ty.layout.fields.iter().enumerate() {
                if ty.projections.iter().any(|projection| match projection {
                    DebugLayoutProjection::OpaqueVptr { field_index, .. } => *field_index == index,
                }) {
                    ui.label("Projected opaque consumer storage below; not an exact producer void pointer type.");
                }
                ui.label(
                    RichText::new(format!(
                        "{}: offset {}, size {}; consumer type/alignment: {:?}",
                        field.name, field.offset, field.size, field.ty,
                    ))
                    .monospace(),
                );
            }
        });
    });
}

fn alignment(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown (not inferred)".to_owned(), |value| format!("{value} bytes (explicit)"))
}

fn producer_id(id: &debug::DebugLayoutTypeId) -> String {
    format!("unit {:#x}, DIE {:#x}", id.unit_offset, id.die_offset)
}

fn opaque_projections(ui: &mut Ui, review: &DebugLayoutReview) {
    if review.report.types.iter().all(|ty| ty.projections.is_empty()) {
        return;
    }
    ui.collapsing("Opaque consumer storage projections (read-only)", |ui| {
        ui.label(
            "The consumer void pointer is storage only, not an exact producer void pointer or function pointer. \
             Producer roles establish pointer -> pointer -> subroutine, not an exact callback ABI. \
             Unknown widths and alignments remain unknown. No object-to-named-table proof is implied.",
        );
        for ty in &review.report.types {
            for projection in &ty.projections {
                let DebugLayoutProjection::OpaqueVptr {
                    field_index,
                    record_id,
                    member_id,
                    source,
                    record_byte_size,
                    record_alignment,
                    member_offset,
                    member_byte_size,
                    member_alignment,
                    pointer_id,
                    pointer_byte_size,
                    pointer_alignment,
                    pointee_pointer_id,
                    pointee_pointer_byte_size,
                    pointee_pointer_alignment,
                    subroutine_id,
                } = projection;
                ui.label(RichText::new(format!("{}: opaque_vptr, field {field_index}", ty.layout.name)).strong());
                ui.label(format!(
                    "Source CU {:#x}, DWARF language code {:#x}, DWARF {}, address size {}",
                    source.unit_offset, source.language, source.dwarf_version, source.address_size,
                ));
                ui.label(format!(
                    "Record {}: size {record_byte_size}, alignment {record_alignment}",
                    producer_id(record_id),
                ));
                ui.label(format!(
                    "Member {}: offset {member_offset}, declared size {}, alignment {}",
                    producer_id(member_id),
                    alignment(*member_byte_size),
                    alignment(*member_alignment),
                ));
                for (role, id, size, align) in [
                    ("Pointer", pointer_id, pointer_byte_size, pointer_alignment),
                    ("Pointee pointer", pointee_pointer_id, pointee_pointer_byte_size, pointee_pointer_alignment),
                ] {
                    ui.label(format!(
                        "{role} {}: declared size {}, alignment {}",
                        producer_id(id),
                        alignment(*size),
                        alignment(*align),
                    ));
                }
                ui.label(format!("Subroutine role: {} (not an exact callback type)", producer_id(subroutine_id)));
            }
        }
    });
}

fn virtual_evidence(ui: &mut Ui, review: &DebugLayoutReview, navigation_enabled: bool) -> Option<u64> {
    let evidence = &review.virtual_evidence;
    if evidence.tables.is_empty() && evidence.warnings.is_empty() && evidence.limitations.is_empty() {
        return None;
    }
    let mut goto_method = None;
    ui.heading("Read-only virtual evidence (not virtual-call targets)");
    ui.label(
        "Native-checked source associations are not applied/current analyst types or authorization. \
         They prove neither named-table ownership nor that an arbitrary object's vptr uses the table. \
         Navigation uses only the retained exact method entry; no names, thunks or containing-function fallback.",
    );
    ui.collapsing("Raw named tables / header confidence", |ui| {
        for table in &evidence.tables {
            let raw = &table.raw;
            ui.label(RichText::new(format!("Raw named table {:#x}: {}", raw.address, raw.vtable_symbol)).strong());
            ui.label(format!("Display name: {}; source {}; confidence {}", raw.name, raw.source, raw.confidence));
            ui.label(format!(
                "Header: {:?}; pointer size {}; raw offset word {:#x}; offset-to-top {}",
                raw.header,
                raw.pointer_size,
                raw.raw_offset_word,
                raw.offset_to_top.map_or_else(|| "unknown (not inferred)".to_owned(), |value| value.to_string()),
            ));
            ui.label(format!(
                "RTTI candidate {:#x}: {:?}; symbol {}",
                raw.rtti_candidate.address,
                raw.rtti_candidate.classification,
                raw.rtti_candidate.symbol.as_deref().unwrap_or("unknown"),
            ));
            ui.label(format!(
                "Bound {}; scan limit {:#x}; scan end {:#x}; stop {:?}",
                raw.bound, raw.scan_limit, raw.scan_end, raw.stop,
            ));
        }
        ui.label("UnverifiedPrefix retains candidate positions only, not a proven address point or offset-to-top.");
    });
    ui.collapsing("Raw table slots (candidate positions)", |ui| {
        for table in &evidence.tables {
            for slot in &table.raw.slots {
                ui.label(format!(
                    "Table {:#x}, candidate slot {} at {:#x}: raw {:#x}, {:?}, target {}",
                    table.raw.address,
                    slot.index,
                    slot.address,
                    slot.raw_value,
                    slot.classification,
                    slot.target.map_or_else(|| "unknown".to_owned(), |address| format!("{address:#x}")),
                ));
            }
        }
    });
    ui.collapsing("Exact method entry associations (source evidence only)", |ui| {
        for table in &evidence.tables {
            for method in &table.methods {
                ui.push_id((table.raw.address, method.slot_index, method.method_address), |ui| {
                    ui.label(format!(
                        "Table {:#x}, candidate slot {}, declared virtual slot {}; exact method entry {:#x}",
                        table.raw.address, method.slot_index, method.declared_virtual_slot_index, method.method_address,
                    ));
                    ui.label(format!(
                        "{}; layout {}; {}",
                        method.linkage_name, method.layout_name, method.verification,
                    ));
                    for (role, id) in [
                        ("Definition", &method.definition_id),
                        ("Record", &method.record_id),
                        ("Declaration", &method.declaration_id),
                        ("Object pointer", &method.object_pointer_id),
                    ] {
                        ui.label(format!("{role}: {}", producer_id(id)));
                    }
                    if ui
                        .add_enabled(
                            navigation_enabled,
                            egui::Button::new(format!("Go to exact method entry {:#x}", method.method_address)),
                        )
                        .clicked()
                    {
                        goto_method = Some(method.method_address);
                    }
                });
            }
        }
    });
    warnings(ui, "Virtual evidence warnings", &evidence.warnings);
    warnings(ui, "Virtual evidence limitations", &evidence.limitations);
    goto_method
}

fn producer_facts(ui: &mut Ui, review: &DebugLayoutReview) {
    ui.heading("Producer facts (read-only, not proposed additions)");
    let Some(producer) = &review.producer_report else {
        ui.label("No producer facts available.");
        return;
    };
    for layout in &producer.layouts {
        ui.push_id(("producer-layout", layout.id.unit_offset, layout.id.die_offset), |ui| {
            ui.collapsing(format!("Producer layout: {}", layout.emitted_name), |ui| {
                ui.label(format!(
                    "Original: {}; unit {:#x}, DIE {:#x}",
                    layout.original_name.as_deref().unwrap_or("unnamed"),
                    layout.id.unit_offset,
                    layout.id.die_offset,
                ));
                ui.label(format!(
                    "Size {}; producer struct alignment: {}",
                    layout.byte_size,
                    alignment(layout.producer_alignment),
                ));
                ui.label(format!(
                    "DWARF language code {:#x}, DWARF {}, address size {}; strict producer applicability: {}; \
                     eligible for native verification: {}",
                    layout.source.language,
                    layout.source.dwarf_version,
                    layout.source.address_size,
                    layout.strictly_applicable,
                    layout.eligible_for_native_verification,
                ));
                for field in &layout.fields {
                    if matches!(&field.leaf, debug::DebugLayoutLeaf::OpaqueVptr { .. }) {
                        ui.label(format!("Opaque producer member role: {}", producer_id(&field.id)));
                    }
                    ui.label(format!(
                        "{}: offset {}, size {}; producer field alignment: {}",
                        field.emitted_name,
                        field.offset,
                        field.byte_size,
                        alignment(field.producer_alignment),
                    ));
                    producer_leaf(ui, &field.leaf);
                }
            });
        });
    }
    ui.collapsing("Producer declarations (raw, not final API declarations)", |ui| {
        for function in &producer.signatures {
            ui.label(RichText::new(format!("{:#x}: {}", function.address, function.declaration)).monospace());
            ui.label(format!(
                "Strict producer applicability: {}; eligible for native verification: {}",
                function.strictly_applicable, function.eligible_for_native_verification,
            ));
            ui.label("Producer return facts:");
            producer_value(ui, &function.return_type);
            for parameter in &function.parameters {
                ui.label(format!("Producer parameter {}:", parameter.emitted_name));
                producer_value(ui, &parameter.ty);
            }
        }
    });
    warnings(ui, "Producer warnings", &producer.warnings);
}

fn producer_value(ui: &mut Ui, value: &debug::DebugLayoutValue) {
    match value {
        debug::DebugLayoutValue::Void => {
            ui.label("void");
        }
        debug::DebugLayoutValue::Leaf { leaf } => producer_leaf(ui, leaf),
        debug::DebugLayoutValue::StructPointer { layout_id, byte_size, producer_alignment, .. } => {
            ui.label(format!(
                "Pointer to layout unit {:#x}, DIE {:#x}: size {byte_size}, producer pointer alignment {}",
                layout_id.unit_offset,
                layout_id.die_offset,
                alignment(*producer_alignment),
            ));
        }
    }
}

fn producer_leaf(ui: &mut Ui, leaf: &debug::DebugLayoutLeaf) {
    match leaf {
        debug::DebugLayoutLeaf::Scalar { scalar } => {
            ui.label(format!(
                "Producer scalar {}: size {}, alignment {}",
                scalar.declaration,
                scalar.byte_size,
                alignment(scalar.producer_alignment),
            ));
        }
        debug::DebugLayoutLeaf::Pointer { byte_size, producer_alignment, pointee, .. } => {
            ui.label(format!("Producer pointer: size {byte_size}, alignment {}", alignment(*producer_alignment)));
            if let Some(scalar) = pointee {
                ui.label(format!(
                    "Producer pointee {}: size {}, alignment {}",
                    scalar.declaration,
                    scalar.byte_size,
                    alignment(scalar.producer_alignment),
                ));
            }
        }
        debug::DebugLayoutLeaf::OpaqueVptr {
            pointer_id,
            pointer_byte_size,
            producer_alignment,
            pointee_pointer_id,
            pointee_pointer_byte_size,
            pointee_pointer_alignment,
            subroutine_id,
            member_byte_size,
            byte_size,
        } => {
            ui.label(format!(
                "Producer opaque_vptr: projected storage size {byte_size}; declared member size {}",
                alignment(*member_byte_size),
            ));
            ui.label(format!(
                "Pointer {}: declared size {}, alignment {}",
                producer_id(pointer_id),
                alignment(*pointer_byte_size),
                alignment(*producer_alignment),
            ));
            ui.label(format!(
                "Pointee pointer {}: declared size {}, alignment {}",
                producer_id(pointee_pointer_id),
                alignment(*pointee_pointer_byte_size),
                alignment(*pointee_pointer_alignment),
            ));
            ui.label(format!("Subroutine role: {} (not an exact callback type)", producer_id(subroutine_id)));
            ui.label("Consumer void pointer is opaque storage only, not the exact producer field type.");
        }
    }
}

fn warnings(ui: &mut Ui, title: &str, warnings: &[String]) {
    ui.heading(title);
    if warnings.is_empty() {
        ui.label("None reported.");
    }
    for warning in warnings {
        ui.label(RichText::new(warning).color(theme::WARNING));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_api::{DebugLayoutReport, Session};

    fn path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf")
    }

    fn workspace(session: &Session) -> Workspace {
        Workspace::open(session, path(), None, None, &egui::Context::default(), true).unwrap()
    }

    fn review() -> DebugLayoutReview {
        DebugLayoutReview {
            review_sha256: "0".repeat(64),
            image_sha256: "1".repeat(64),
            compiler_spec_sha256: "2".repeat(64),
            report: DebugLayoutReport::default(),
            producer_report: None,
            virtual_evidence: Default::default(),
            approved: vec![0x400000],
            preserved: Vec::new(),
            imported: None,
        }
    }

    fn review_with_method(address: u64) -> DebugLayoutReview {
        use rampage_analysis::classes::{
            ClassEvidence, HeaderClassification, RttiClassification, RttiEvidence, ScanStop, SlotClassification,
            VtableSlot,
        };
        let id = |die_offset| debug::DebugLayoutTypeId { unit_offset: 0, die_offset };
        DebugLayoutReview {
            virtual_evidence: rampage_api::DebugLayoutVirtualEvidence {
                tables: vec![rampage_api::DebugLayoutVtableEvidence {
                    raw: ClassEvidence {
                        name: "misleading display name".to_owned(),
                        vtable_symbol: "not a resolvable symbol".to_owned(),
                        address: 0x800000,
                        source: "named_itanium_vtable_symbol",
                        confidence: "raw_named_vtable_evidence",
                        pointer_size: 8,
                        header: HeaderClassification::UnverifiedPrefix,
                        raw_offset_word: u64::MAX,
                        offset_to_top: None,
                        rtti_candidate: RttiEvidence {
                            address: 0,
                            classification: RttiClassification::Null,
                            symbol: None,
                        },
                        bound: "symbol_size",
                        scan_limit: 0x800020,
                        scan_end: 0x800020,
                        slots: vec![
                            VtableSlot {
                                index: 0,
                                address: 0x800010,
                                raw_value: address,
                                classification: SlotClassification::Function,
                                target: Some(address),
                            },
                            VtableSlot {
                                index: 1,
                                address: 0x800018,
                                raw_value: address + 1,
                                classification: SlotClassification::Function,
                                target: Some(address + 1),
                            },
                        ],
                        stop: ScanStop::Bound,
                    },
                    methods: vec![rampage_api::DebugLayoutVirtualMethodEvidence {
                        slot_index: 0,
                        declared_virtual_slot_index: 0,
                        method_address: address,
                        definition_id: id(1),
                        record_id: id(2),
                        declaration_id: id(3),
                        object_pointer_id: id(4),
                        linkage_name: "also not a resolvable symbol".to_owned(),
                        layout_name: "not an analyst type".to_owned(),
                        verification: "native_checked_source_evidence",
                    }],
                }],
                ..Default::default()
            },
            ..review()
        }
    }

    fn other_entry(workspace: &Workspace) -> u64 {
        workspace
            .functions
            .ready()
            .unwrap()
            .iter()
            .find(|function| function.address != workspace.cursor)
            .unwrap()
            .address
    }

    #[test]
    fn producer_vptr_render_keeps_role_ids_and_unknown_widths_without_claiming_an_exact_callback_type() {
        use egui_kittest::Harness;
        use egui_kittest::kittest::Queryable;

        let id = |die_offset| debug::DebugLayoutTypeId { unit_offset: 16, die_offset };
        let leaf = debug::DebugLayoutLeaf::OpaqueVptr {
            pointer_id: id(32),
            pointer_byte_size: None,
            producer_alignment: None,
            pointee_pointer_id: id(40),
            pointee_pointer_byte_size: Some(8),
            pointee_pointer_alignment: None,
            subroutine_id: id(48),
            member_byte_size: None,
            byte_size: 8,
        };
        let mut harness = Harness::builder()
            .with_size(egui::vec2(1400.0, 800.0))
            .build_ui_state(|ui, leaf: &mut debug::DebugLayoutLeaf| producer_leaf(ui, leaf), leaf);
        harness.run();
        for label in [
            "Producer opaque_vptr: projected storage size 8; declared member size unknown (not inferred)",
            "Pointer unit 0x10, DIE 0x20: declared size unknown (not inferred), alignment unknown (not inferred)",
            "Pointee pointer unit 0x10, DIE 0x28: declared size 8 bytes (explicit), alignment unknown (not inferred)",
            "Subroutine role: unit 0x10, DIE 0x30 (not an exact callback type)",
            "Consumer void pointer is opaque storage only, not the exact producer field type.",
        ] {
            harness.get_by_label(label);
        }
    }

    #[test]
    fn exact_navigation_requires_a_retained_association_and_keeps_review_requests_annotations_and_editor_unchanged() {
        let mut workspace = workspace(&Session::default());
        let target = other_entry(&workspace);
        let mut state = DebugLayouts { shown: true, ..DebugLayouts::default() };
        state.reply =
            Some(Reply { binding: Binding::capture(&workspace, &state.revision), review: review_with_method(target) });
        let original_cursor = workspace.cursor;
        assert!(!state.goto_exact_method_entry(&mut workspace, target + 1), "raw slots are not associations");
        assert_eq!(workspace.cursor, original_cursor);
        let revision = Arc::clone(&state.revision);
        let epoch = Arc::clone(&workspace.annotations_epoch);
        let before = serde_json::to_value(workspace.project.annotation_list()).unwrap();
        workspace.begin_comment();
        workspace.editing.as_mut().unwrap().text = "unsaved analyst explanation".to_owned();
        assert!(state.goto_exact_method_entry(&mut workspace, target));
        assert_eq!(workspace.cursor, target);
        assert!(workspace.can_go_back());
        assert!(state.shown());
        assert!(state.can_apply(&workspace));
        assert!(Arc::ptr_eq(&revision, &state.revision));
        assert!(Arc::ptr_eq(&epoch, &workspace.annotations_epoch));
        assert!(matches!(state.job, Job::Idle));
        assert!(matches!(workspace.pseudocode, Job::Idle));
        assert_eq!(workspace.editing.as_ref().unwrap().text, "unsaved analyst explanation");
        assert_eq!(serde_json::to_value(workspace.project.annotation_list()).unwrap(), before);
        assert!(workspace.project.undo().unwrap().is_empty());
        let retained = &state.reply.as_ref().unwrap().review;
        assert!(retained.imported.is_none());
        assert_eq!(retained.virtual_evidence.tables[0].raw.offset_to_top, None);
        assert_eq!(retained.review_sha256, "0".repeat(64));
    }

    #[test]
    fn exact_navigation_refuses_stale_bindings_hidden_pending_gated_and_failed_reviews_without_side_effects() {
        for refusal in 0..9 {
            let session = Session::default();
            let mut workspace = workspace(&session);
            let target = other_entry(&workspace);
            let mut state = DebugLayouts { shown: true, ..DebugLayouts::default() };
            state.reply = Some(Reply {
                binding: Binding::capture(&workspace, &state.revision),
                review: review_with_method(target),
            });
            let mut permit = None;
            match refusal {
                0 => workspace.instance = Arc::new(()),
                1 => workspace.project = Arc::new(Project::new(rampage_loaders::Binary::open(path()).unwrap())),
                2 => workspace.annotations_changed(None),
                3 => state.invalidate(),
                4 => state.shown = false,
                5 => permit = state.gate.try_acquire(),
                6 => state.job = Job::Running(std::sync::mpsc::channel().1),
                7 => state.error = Some("preview refused".to_owned()),
                _ => state.reply = None,
            }
            let cursor = workspace.cursor;
            let revision = Arc::clone(&state.revision);
            let epoch = Arc::clone(&workspace.annotations_epoch);
            let before = serde_json::to_value(workspace.project.annotation_list()).unwrap();
            assert!(!state.goto_exact_method_entry(&mut workspace, target), "refusal {refusal}");
            assert_eq!(workspace.cursor, cursor);
            assert!(Arc::ptr_eq(&revision, &state.revision));
            assert!(Arc::ptr_eq(&epoch, &workspace.annotations_epoch));
            assert_eq!(serde_json::to_value(workspace.project.annotation_list()).unwrap(), before);
            assert!(workspace.project.undo().unwrap().is_empty());
            assert!(matches!(workspace.pseudocode, Job::Idle));
            drop(permit);
        }
    }

    #[test]
    fn binding_rejects_workspace_aba_even_when_session_reuses_the_project() {
        let session = Session::default();
        let first = workspace(&session);
        let revision = Arc::new(());
        let binding = Binding::capture(&first, &revision);
        assert!(binding.matches(&first, &revision));
        let mut replacement = workspace(&session);
        assert!(Arc::ptr_eq(&first.project, &replacement.project));
        assert!(!binding.matches(&replacement, &revision));
        let reopened = workspace(&session);
        assert!(Arc::ptr_eq(&first.project, &reopened.project));
        assert!(!binding.matches(&reopened, &revision));
        let mut state = DebugLayouts { shown: true, revision, ..DebugLayouts::default() };
        state.reply = Some(Reply { binding, review: review() });
        state.apply(&mut replacement);
        assert!(!state.can_apply(&replacement));
        assert!(first.project.annotation_list().types.is_empty());
        assert!(replacement.project.annotation_list().types.is_empty());
        assert!(first.project.undo().unwrap().is_empty());
    }

    #[test]
    fn binding_requires_exact_project_and_nonreused_epoch_and_request_revision() {
        let mut workspace = workspace(&Session::default());
        let revision = Arc::new(());
        let binding = Binding::capture(&workspace, &revision);
        let original_project = Arc::clone(&workspace.project);
        workspace.project = Arc::new(Project::new(rampage_loaders::Binary::open(path()).unwrap()));
        assert!(!binding.matches(&workspace, &revision));
        workspace.project = original_project;
        assert!(binding.matches(&workspace, &revision));
        assert!(!binding.matches(&workspace, &Arc::new(())));
        workspace.annotations_changed(None);
        assert!(!binding.matches(&workspace, &revision));
        workspace.annotations_changed(None);
        assert!(!binding.matches(&workspace, &revision));
    }

    #[test]
    fn late_background_reply_cannot_restore_approval_after_an_annotation_change() {
        let mut workspace = workspace(&Session::default());
        let mut state = DebugLayouts { shown: true, ..DebugLayouts::default() };
        let binding = Binding::capture(&workspace, &state.revision);
        let (sender, receiver) = std::sync::mpsc::channel();
        state.job = Job::Running(receiver);
        state.job_binding = Some(binding);
        workspace.annotations_changed(None);
        assert!(sender.send(Ok(review())).is_ok());
        state.poll(&workspace);
        assert!(state.reply.is_none());
        assert!(!state.can_apply(&workspace));
        assert_eq!(state.error.as_deref(), Some(STALE));
    }

    #[test]
    fn close_and_reopen_rejects_a_late_result_from_the_old_request() {
        let workspace = workspace(&Session::default());
        let mut state = DebugLayouts { shown: true, ..DebugLayouts::default() };
        let binding = Binding::capture(&workspace, &state.revision);
        state.reply = Some(Reply { binding: Binding::capture(&workspace, &state.revision), review: review() });
        assert!(state.can_apply(&workspace));
        state.close();
        assert!(state.reply.is_none());
        assert!(!state.can_apply(&workspace));
        state.shown = true;
        state.job_binding = Some(binding);
        state.job = Job::Done(Ok(review()));
        state.poll(&workspace);
        assert!(state.reply.is_none());
        assert!(!state.can_apply(&workspace));
    }

    #[test]
    fn repeated_start_close_and_restart_retain_one_pending_job_and_refuse_its_stale_completion() {
        let workspace = workspace(&Session::default());
        let ctx = egui::Context::default();
        let mut state = DebugLayouts { shown: true, ..DebugLayouts::default() };
        let binding = Binding::capture(&workspace, &state.revision);
        let original_revision = Arc::clone(&binding.revision);
        let (sender, receiver) = std::sync::mpsc::channel();
        state.job = Job::Running(receiver);
        state.job_binding = Some(binding);

        for _ in 0..4 {
            state.start(&workspace, &ctx, false);
            assert!(state.job.is_running());
            assert!(Arc::ptr_eq(&state.job_binding.as_ref().unwrap().revision, &original_revision));
            assert_eq!(state.error.as_deref(), Some(PENDING));
            assert!(state.reply.is_none());
            state.close();
            assert!(state.job.is_running());
            assert!(!state.shown());
            state.invalidate();
            assert!(state.job.is_running());
        }
        state.start(&workspace, &ctx, false);
        assert!(sender.send(Ok(review())).is_ok(), "the original receiver must remain attached");
        state.poll(&workspace);
        assert!(matches!(state.job, Job::Idle));
        assert!(state.job_binding.is_none());
        assert!(state.reply.is_none());
        assert_eq!(state.error.as_deref(), Some(STALE));
        assert!(!state.can_apply(&workspace));
        state.poll(&workspace);
        assert!(matches!(state.job, Job::Idle), "completion must not launch an automatic replacement preview");
    }

    #[test]
    fn a_closed_pending_job_is_drained_without_publishing_its_result_or_error() {
        let workspace = workspace(&Session::default());
        for result in [Ok(review()), Err("obsolete preview failure".to_owned())] {
            let mut state = DebugLayouts { shown: true, ..DebugLayouts::default() };
            state.job_binding = Some(Binding::capture(&workspace, &state.revision));
            let (sender, receiver) = std::sync::mpsc::channel();
            state.job = Job::Running(receiver);
            state.close();
            assert!(sender.send(result).is_ok());
            state.poll(&workspace);
            assert!(matches!(state.job, Job::Idle));
            assert!(state.job_binding.is_none());
            assert!(state.reply.is_none());
            assert!(state.error.is_none());
            assert!(!state.can_apply(&workspace));
        }
    }

    #[test]
    fn app_workspace_replacement_cannot_bypass_an_actual_pending_preview() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::mpsc::channel;
        use std::time::Duration;

        let ctx = egui::Context::default();
        let mut app = crate::App::blocking();
        app.open(&ctx, path(), None);
        let first = app.workspace.as_ref().unwrap();
        let original_project = Arc::clone(&first.project);
        let original_instance = Arc::clone(&first.instance);
        let gate = app.debug_layout_gate.clone();
        let (entered, entered_rx) = channel();
        let (finish, finish_rx) = channel();
        let (completed, completed_rx) = channel();
        let job_ctx = egui::Context::default();
        // Job requests repaint only after the closure and its permit have finished, even if its receiver was dropped.
        job_ctx.set_request_repaint_callback(move |_| {
            let _ = completed.send(());
        });
        let workspace = app.workspace.as_mut().unwrap();
        let mut state = std::mem::take(&mut workspace.debug_layout);
        state.start_job(workspace, &job_ctx, false, move || {
            entered.send(()).unwrap();
            finish_rx.recv().unwrap();
            Ok(review())
        });
        workspace.debug_layout = state;
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(gate.is_running());

        let attempted = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            app.open(&ctx, path(), None);
            let workspace = app.workspace.as_mut().unwrap();
            assert!(Arc::ptr_eq(&workspace.project, &original_project));
            assert!(!Arc::ptr_eq(&workspace.instance, &original_instance));
            workspace.begin_comment();
            workspace.editing.as_mut().unwrap().text = "unsaved analyst work".to_owned();
            let attempted = Arc::clone(&attempted);
            let mut state = std::mem::take(&mut workspace.debug_layout);
            state.start_job(workspace, &ctx, true, move || {
                attempted.fetch_add(1, Ordering::Relaxed);
                Ok(review())
            });
            assert!(matches!(state.job, Job::Idle));
            assert!(state.reply.is_none());
            assert_eq!(state.error.as_deref(), Some(PENDING));
            assert!(!state.can_apply(workspace));
            assert!(gate.is_running());
            workspace.debug_layout = state;
            assert_eq!(workspace.editing.as_ref().unwrap().text, "unsaved analyst work");
        }
        assert_eq!(attempted.load(Ordering::Relaxed), 0);
        finish.send(()).unwrap();
        completed_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(!gate.is_running());
        let workspace = app.workspace.as_mut().unwrap();
        workspace.poll(&ctx);
        assert!(matches!(workspace.debug_layout.job, Job::Idle));
        assert!(workspace.debug_layout.reply.is_none(), "the old workspace's late result must not publish");
        assert_eq!(attempted.load(Ordering::Relaxed), 0, "completion must not automatically launch another preview");

        let attempts = Arc::clone(&attempted);
        let mut state = std::mem::take(&mut workspace.debug_layout);
        state.start_job(workspace, &ctx, true, move || {
            attempts.fetch_add(1, Ordering::Relaxed);
            Ok(DebugLayoutReview { review_sha256: "f".repeat(64), ..review() })
        });
        assert_eq!(attempted.load(Ordering::Relaxed), 1);
        assert_eq!(state.reply.as_ref().unwrap().review.review_sha256, "f".repeat(64));
        assert!(state.can_apply(workspace));
        assert!(!gate.is_running());
        workspace.debug_layout = state;
        assert_eq!(workspace.editing.as_ref().unwrap().text, "unsaved analyst work");
    }

    #[test]
    fn preview_permit_releases_on_panic_and_an_explicit_new_preview_can_start() {
        let workspace = workspace(&Session::default());
        let ctx = egui::Context::default();
        let mut state = DebugLayouts::default();
        let gate = state.gate.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.start_job(&workspace, &ctx, true, || panic!("simulated preview failure"));
        }));
        assert!(result.is_err());
        assert!(!gate.is_running());
        state.start_job(&workspace, &ctx, true, || Ok(review()));
        assert!(state.can_apply(&workspace));
        assert!(!gate.is_running());
    }

    #[test]
    fn annotation_invalidation_keeps_unsaved_editor_contents_and_blocks_the_final_apply_check() {
        let mut workspace = workspace(&Session::default());
        let mut state = DebugLayouts { shown: true, ..DebugLayouts::default() };
        state.reply = Some(Reply { binding: Binding::capture(&workspace, &state.revision), review: review() });
        assert!(state.can_apply(&workspace));
        workspace.debug_layout = state;
        workspace.begin_comment();
        workspace.editing.as_mut().unwrap().text = "unsaved analyst work".to_owned();
        let original_epoch = Arc::clone(&workspace.annotations_epoch);
        workspace.annotations_changed(None);
        assert!(!Arc::ptr_eq(&original_epoch, &workspace.annotations_epoch));
        assert_eq!(workspace.editing.as_ref().unwrap().text, "unsaved analyst work");
        assert!(workspace.debug_layout.reply.is_some());
        let mut state = std::mem::take(&mut workspace.debug_layout);
        state.apply(&mut workspace);
        assert!(!state.can_apply(&workspace));
        assert!(workspace.project.annotation_list().types.is_empty());
        assert!(workspace.project.undo().unwrap().is_empty());
    }
}
