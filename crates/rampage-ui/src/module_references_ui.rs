use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rampage_api::{
    ModuleReferenceInput, ModuleReferenceName, ModuleReferenceQuery, ModuleReferenceStatus, ModuleReferenceView,
    QualifiedProjectAddress, prepare_module_reference_view,
};

use crate::workspace::Job;

#[derive(Default)]
struct ExecutionGate(Arc<AtomicBool>);

impl ExecutionGate {
    fn acquire(&self) -> Option<ExecutionPermit> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| ExecutionPermit(Arc::clone(&self.0)))
    }
}

struct ExecutionPermit(Arc<AtomicBool>);

impl Drop for ExecutionPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Default)]
struct Draft {
    source: Option<String>,
    slot: String,
    filter: String,
    page_size: String,
}

impl Draft {
    fn query(&self, inputs: &[ModuleReferenceInput]) -> Result<ModuleReferenceQuery, String> {
        if inputs.is_empty() || inputs.len() > 8 {
            return Err("Load between one and eight modules before applying a query.".into());
        }
        if self.source.as_ref().is_some_and(|id| !inputs.iter().any(|input| &input.module_id == id)) {
            return Err("The selected source module is no longer loaded.".into());
        }
        if self.filter.len() > 256 {
            return Err("Filter exceeds 256 UTF-8 bytes.".into());
        }
        let limit = if self.page_size.is_empty() {
            64
        } else {
            self.page_size.parse::<usize>().map_err(|_| "Page size must be an integer in 1..=256.")?
        };
        if !(1..=256).contains(&limit) {
            return Err("Page size must be in 1..=256.".into());
        }
        let source_slot = if self.slot.is_empty() {
            None
        } else {
            let hex = self.slot.strip_prefix("0x").ok_or("Source slot must start with 0x.")?;
            Some(u64::from_str_radix(hex, 16).map_err(|_| "Source slot must be a 64-bit hexadecimal address.")?)
        };
        Ok(ModuleReferenceQuery {
            matching_work_limit: None,
            source_module_id: self.source.clone(),
            source_slot,
            filter: (!self.filter.is_empty()).then(|| self.filter.clone()),
            offset: Some(0),
            limit: Some(limit),
        })
    }
}

pub(crate) struct ReferenceNavigation {
    pub(crate) inputs: Vec<ModuleReferenceInput>,
    pub(crate) address: QualifiedProjectAddress,
}

#[derive(Default)]
pub(crate) struct ModuleReferences {
    shown: bool,
    draft: Draft,
    gate: ExecutionGate,
    job: Option<Job<ModuleReferenceView>>,
    cancellation: Arc<AtomicBool>,
    binding: Vec<ModuleReferenceInput>,
    view: Option<ModuleReferenceView>,
    authority: bool,
    error: Option<String>,
}

fn same_inputs(left: &[ModuleReferenceInput], right: &[ModuleReferenceInput]) -> bool {
    left.len() == right.len()
        && left.iter().all(|expected| {
            right
                .iter()
                .any(|actual| actual.module_id == expected.module_id && Arc::ptr_eq(&actual.project, &expected.project))
        })
}

impl ModuleReferences {
    pub(crate) fn show(&mut self) {
        self.shown = true;
    }

    fn running(&self) -> bool {
        self.job.is_some() || self.gate.0.load(Ordering::Acquire)
    }

    fn invalidate(&mut self) {
        self.cancellation.store(true, Ordering::Release);
        self.authority = false;
    }

    pub(crate) fn navigation_failed(&mut self, error: String) {
        self.invalidate();
        self.error = Some(error);
    }

    fn close(&mut self) {
        self.invalidate();
        self.shown = false;
    }

    fn poll(&mut self, inputs: &[ModuleReferenceInput]) {
        if !same_inputs(&self.binding, inputs) {
            self.invalidate();
        }
        let Some(job) = &mut self.job else { return };
        job.poll();
        if !matches!(job, Job::Done(_)) {
            return;
        }
        let Some(Job::Done(result)) = self.job.take() else { unreachable!() };
        if self.cancellation.load(Ordering::Acquire) || !same_inputs(&self.binding, inputs) {
            return;
        }
        match result {
            Ok(view) => {
                self.view = Some(view);
                self.authority = true;
                self.error = None;
            }
            Err(error) => self.navigation_failed(error),
        }
    }

    fn start(
        &mut self,
        ctx: &egui::Context,
        blocking: bool,
        inputs: &[ModuleReferenceInput],
        query: ModuleReferenceQuery,
    ) {
        self.start_execution(ctx, blocking, inputs, move |inputs| {
            prepare_module_reference_view(inputs, &query).map_err(|error| error.to_string())
        });
    }

    fn start_execution(
        &mut self,
        ctx: &egui::Context,
        blocking: bool,
        inputs: &[ModuleReferenceInput],
        work: impl FnOnce(&[ModuleReferenceInput]) -> Result<ModuleReferenceView, String> + Send + 'static,
    ) {
        self.poll(inputs);
        if self.running() {
            self.error = Some("A module-reference query is still finishing; no new query was started.".into());
            return;
        }
        let Some(permit) = self.gate.acquire() else { return };
        self.invalidate();
        self.error = None;
        self.binding = inputs.to_vec();
        self.cancellation = Arc::new(AtomicBool::new(false));
        let cancellation = Arc::clone(&self.cancellation);
        let retained = inputs.to_vec();
        let mut job = Job::Idle;
        job.start(blocking, ctx, move || {
            let _permit = permit;
            if cancellation.load(Ordering::Acquire) {
                return Err("Query cancelled.".into());
            }
            let result = work(&retained);
            if cancellation.load(Ordering::Acquire) { Err("Query cancelled.".into()) } else { result }
        });
        self.job = Some(job);
        self.poll(inputs);
    }

    fn apply(&mut self, ctx: &egui::Context, blocking: bool, inputs: &[ModuleReferenceInput]) {
        match self.draft.query(inputs) {
            Ok(query) => self.start(ctx, blocking, inputs, query),
            Err(error) => self.navigation_failed(error),
        }
    }

    fn navigate(
        &mut self,
        inputs: &[ModuleReferenceInput],
        address: QualifiedProjectAddress,
    ) -> Option<ReferenceNavigation> {
        let view = self.view.as_ref()?;
        if !self.authority || !same_inputs(view.inputs(), inputs) {
            self.navigation_failed("Historical query no longer matches the loaded module set. Apply again.".into());
            return None;
        }
        let observed = view.report().rows.iter().any(|row| {
            (row.source_module_id == address.module_id && row.source_slot == address.address)
                || (row.status == ModuleReferenceStatus::DeclaredLink
                    && row.candidates.iter().any(|candidate| {
                        candidate.module_id == address.module_id
                            && candidate.address == Some(address.address)
                            && candidate.forwarder.is_none()
                            && !candidate.identity_only
                    }))
        });
        if !observed {
            self.navigation_failed("Address is not an inspectable declaration in the retained query.".into());
            return None;
        }
        if let Err(error) = view.revalidate_sources() {
            self.navigation_failed(format!("Original source validation failed: {error}"));
            return None;
        }
        Some(ReferenceNavigation { inputs: view.inputs().to_vec(), address })
    }
}

impl Drop for ModuleReferences {
    fn drop(&mut self) {
        self.cancellation.store(true, Ordering::Release);
    }
}

pub(crate) fn show(
    ctx: &egui::Context,
    state: &mut ModuleReferences,
    blocking: bool,
    inputs: &[ModuleReferenceInput],
) -> Option<ReferenceNavigation> {
    state.poll(inputs);
    if !state.shown {
        return None;
    }
    let mut open = true;
    let mut navigation = None;
    egui::Window::new("Module references").open(&mut open).default_width(760.0).show(ctx, |ui| {
        ui.label("Explicit loaded-module PE declaration metadata; no native analysis or SDK calls.");
        ui.label("Historical observations, not a source-freshness guarantee. Apply or Refresh explicitly.");
        ui.label("ELF, Mach-O and snapshots are unsupported; ordinals and forwarders are never followed.");
        let mut changed = false;
        ui.horizontal(|ui| {
            ui.label("Source module");
            let previous = state.draft.source.clone();
            egui::ComboBox::from_id_salt("module-reference-source")
                .selected_text(state.draft.source.as_deref().unwrap_or("All loaded modules"))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut state.draft.source, None, "All loaded modules");
                    for input in inputs.iter().take(8) {
                        ui.selectable_value(&mut state.draft.source, Some(input.module_id.clone()), &input.module_id);
                    }
                });
            changed |= previous != state.draft.source;
        });
        ui.horizontal(|ui| {
            ui.label("Source slot (optional 0x)");
            changed |= ui
                .add(egui::TextEdit::singleline(&mut state.draft.slot).id_salt("reference-slot").char_limit(18))
                .changed();
            ui.label("Page size (1–256; default 64)");
            changed |= ui
                .add(
                    egui::TextEdit::singleline(&mut state.draft.page_size)
                        .id_salt("reference-limit")
                        .char_limit(8)
                        .desired_width(70.0),
                )
                .changed();
        });
        ui.horizontal(|ui| {
            ui.label("Exact UTF-8 substring filter");
            changed |= ui
                .add(egui::TextEdit::singleline(&mut state.draft.filter).id_salt("reference-filter").char_limit(257))
                .changed();
        });
        if changed {
            state.invalidate();
        }
        ui.horizontal(|ui| {
            if ui.add_enabled(!state.running(), egui::Button::new("Apply / Refresh")).clicked() {
                state.apply(ctx, blocking, inputs);
            }
            if state.running() {
                ui.spinner();
                if ui.button("Cancel query").clicked() {
                    state.invalidate();
                }
                ui.label("Execution lease held until work finishes, including after cancellation.");
            }
        });
        if let Some(error) = &state.error {
            ui.label("Module reference error");
            ui.label(error);
        }
        if !state.authority && state.view.is_some() {
            ui.label("Historical rows only: navigation and paging disabled. Apply again explicitly.");
        }
        let mut requested = None;
        let mut next_query = None;
        if let Some(view) = &state.view {
            let enabled = state.authority && same_inputs(view.inputs(), inputs);
            egui::ScrollArea::vertical().max_height(760.0).show(ui, |ui| {
                render_report(ui, view, enabled, &mut requested);
                let report = view.report();
                if report.more
                    && let Some(offset) = report.next_offset
                    && ui.add_enabled(enabled && !state.running(), egui::Button::new("Next page")).clicked()
                {
                    let mut query = view.query().clone();
                    query.offset = Some(offset);
                    next_query = Some(query);
                }
            });
        } else {
            ui.label("No query has run. Opening this window and editing filters do not read source files.");
        }
        if let Some(query) = next_query {
            state.start(ctx, blocking, inputs, query);
        }
        if let Some(address) = requested {
            navigation = state.navigate(inputs, address);
        }
    });
    if !open {
        state.close();
        return None;
    }
    navigation
}

fn raw_name(name: &ModuleReferenceName) -> String {
    match &name.display {
        Some(display) => format!("{display:?} [raw 0x{}]", name.raw_hex),
        None => format!("0x{} (non-UTF-8)", name.raw_hex),
    }
}

fn render_report(
    ui: &mut egui::Ui,
    view: &ModuleReferenceView,
    enabled: bool,
    requested: &mut Option<QualifiedProjectAddress>,
) {
    let report = view.report();
    ui.separator();
    ui.label(format!("Policy: {}", report.matching_policy));
    ui.label(format!("proven_runtime_flow={} · proven_layout={}", report.proven_runtime_flow, report.proven_layout));
    ui.label("No runtime binding, ownership, layout, function boundary or source-method proof.");
    ui.label("Source slots are memory addresses; direct targets may be data. Inspect never decompiles automatically.");
    ui.label(format!(
        "{} rows at offset {}; matched {}{}; more={}; nextOffset={:?}",
        report.returned,
        report.offset,
        report.matched,
        if report.matched_is_lower_bound { " (lower bound)" } else { "" },
        report.more,
        report.next_offset
    ));
    ui.label(format!(
        "Complete={}; rows truncated={}; 2 MiB whole-JSON cap reached={}",
        report.complete, report.rows_truncated, report.byte_capped
    ));
    ui.label(format!(
        "Matching work: exhausted={}; used={}; limit={} (separate from loader work)",
        report.matching_work_exhausted, report.matching_work_used, report.matching_work_limit
    ));
    ui.collapsing("Full matching limitations", |ui| {
        for limitation in &report.limitations {
            ui.label(*limitation);
        }
    });
    ui.heading("Metadata coverage (including unavailable modules)");
    for coverage in &report.coverage {
        ui.push_id(&coverage.module_id, |ui| {
            ui.label(format!(
                "{}: {:?} · {:?} · origin {:?}",
                coverage.module_id, coverage.format, coverage.metadata_status, coverage.metadata_origin
            ));
            ui.label(format!(
                "Historical non-atomic source check={}; imports complete={}; exports complete={}",
                coverage.source_revalidated_non_atomic, coverage.import_table_complete, coverage.export_table_complete
            ));
            if let Some(identity) = &coverage.producer_identity {
                ui.label(format!("Producer identity: {}", raw_name(identity)));
            }
            for message in &coverage.omissions {
                ui.label(message);
            }
            ui.collapsing("Loader provenance, coverage and warnings", |ui| {
                ui.label(format!(
                    "Export directory present={:?}; known slots={}; examined imports={}; exports={}",
                    coverage.export_directory_present,
                    coverage.known_source_slots,
                    coverage.examined_imports,
                    coverage.examined_exports
                ));
                ui.label(format!(
                    "Loader={:?}; regular={:?}; delay={:?}; exports={:?}; work={}; limits={:?}",
                    coverage.loader_status,
                    coverage.regular_imports,
                    coverage.delay_imports,
                    coverage.exports,
                    coverage.metadata_lookup_work,
                    coverage.loader_limits
                ));
                for warning in &coverage.warnings {
                    ui.label(warning);
                }
            });
        });
    }
    ui.heading("All observed rows (not only successful declarations)");
    for (index, row) in report.rows.iter().enumerate() {
        ui.push_id(index, |ui| {
            ui.separator();
            ui.label(format!(
                "{} source slot {:#x}: {:?} · {}",
                row.source_module_id, row.source_slot, row.status, row.raw_kind
            ));
            ui.label(format!("Raw library: {}", raw_name(&row.import_library)));
            if let Some(name) = &row.import_name {
                ui.label(format!("Named import: {}", raw_name(name)));
            }
            if let Some(ordinal) = row.import_ordinal {
                ui.label(format!("Ordinal import: {ordinal} (unsupported)"));
            }
            ui.label(&row.reason);
            ui.label(format!(
                "Candidates={}; truncated={}; producer search complete={}",
                row.candidate_count, row.candidates_truncated, row.producer_search_complete
            ));
            if ui.add_enabled(enabled, egui::Button::new("Inspect source slot")).clicked() {
                *requested =
                    Some(QualifiedProjectAddress { module_id: row.source_module_id.clone(), address: row.source_slot });
            }
            for candidate in &row.candidates {
                ui.label(format!(
                    "Candidate {} · {} · address {} · identity only={} · executable backing={}",
                    candidate.module_id,
                    candidate.raw_kind,
                    candidate.address.map(|address| format!("{address:#x}")).unwrap_or_else(|| "unavailable".into()),
                    candidate.identity_only,
                    candidate.executable_backing
                ));
                if let Some(name) = &candidate.export_name {
                    ui.label(format!("Export name: {}", raw_name(name)));
                }
                if let Some(forwarder) = &candidate.forwarder {
                    ui.label(format!("Forwarder (never followed): {}", raw_name(forwarder)));
                }
                ui.label(&candidate.reason);
                if row.status == ModuleReferenceStatus::DeclaredLink
                    && candidate.forwarder.is_none()
                    && !candidate.identity_only
                    && let Some(address) = candidate.address
                    && ui.add_enabled(enabled, egui::Button::new("Inspect direct target")).clicked()
                {
                    *requested = Some(QualifiedProjectAddress { module_id: candidate.module_id.clone(), address });
                }
            }
        });
    }
}

#[cfg(test)]
mod tests;
