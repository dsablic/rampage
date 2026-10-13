use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use clap::Args;
use rampage_api::workflows::WorkflowOptions;
use rampage_api::{DecompilerWorkerConfig, ReportLimits};
use rampage_arch::Arch;
use rampage_loaders::ImageAt;
use serde::Serialize;
use serde_json::Value;

use crate::commands::{Options, open};
use crate::report::Workflow;

const MAX_TASKS: usize = 64;
const MAX_FUNCTIONS: usize = 16;
const MAX_TASK_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESULT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Args)]
pub struct AnalyzeArgs {
    pub file: PathBuf,
    /// Analyze every supported declared architecture slice; conflicts with the global --arch selector
    #[arg(long, conflicts_with = "arch")]
    pub all_architectures: bool,
    /// Workflow to run per architecture; repeatable (default triage-report)
    #[arg(long, default_value = "triage-report")]
    pub workflow: Vec<Workflow>,
    /// Explicit function address or name to decompile per architecture; repeatable, at most 16
    #[arg(long)]
    pub function: Vec<String>,
    /// Second image for a selected diff-builds workflow
    #[arg(long)]
    pub other: Option<PathBuf>,
    #[arg(long, value_parser = rampage_api::parse_file_offset, requires = "other")]
    pub other_image_offset: Option<u64>,
    #[arg(long, value_parser = rampage_api::parse_file_offset, requires = "other_image_offset")]
    pub other_image_length: Option<u64>,
    /// Findings per workflow section (default 25, capped at 200)
    #[arg(long)]
    pub limit: Option<usize>,
    /// Skip workflow decompilation previews; explicit --function selections still run
    #[arg(long)]
    pub no_decompile: bool,
    /// Supervised decompiler deadline, not a workflow wall-clock limit (1..600000 ms)
    #[arg(long, default_value_t = 30000, value_parser = clap::value_parser!(u64).range(1..=600000))]
    pub decompile_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Task {
    Workflow { name: String },
    Decompile { function: String },
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Completed,
    Failed,
    OutputLimit,
    NotRun,
}

#[derive(Debug, Serialize)]
struct TaskResult {
    arch: Arch,
    task: Task,
    status: Status,
    elapsed_ms: u64,
    result: Option<Value>,
    error: Option<String>,
}

#[derive(Serialize)]
struct Target {
    arch: Arch,
    image_sha256: Option<String>,
    source_sha256: Option<String>,
    capture_identity: Option<rampage_analysis::capture_identity::CaptureIdentity>,
    error: Option<String>,
}

#[derive(Serialize)]
struct Analysis {
    schema: &'static str,
    file: String,
    file_display_lossy: bool,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    image_offset: Option<u64>,
    image_length: Option<u64>,
    targets: Vec<Target>,
    tasks: Vec<TaskResult>,
    completed_tasks: usize,
    failed_tasks: usize,
    elapsed_ms: u64,
    decompile_timeout_ms: u64,
    max_task_bytes: usize,
    max_result_bytes: usize,
    limitations: Vec<&'static str>,
}

fn elapsed(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn retain<R: Serialize>(
    arch: Arch,
    task: Task,
    started: Instant,
    run: impl FnOnce() -> Result<R>,
    remaining: &mut usize,
) -> TaskResult {
    if *remaining == 0 {
        return TaskResult {
            arch,
            task,
            status: Status::NotRun,
            elapsed_ms: 0,
            result: None,
            error: Some("combined result budget exhausted; task not run".to_owned()),
        };
    }
    let outcome = run().and_then(|result| serde_json::to_value(result).map_err(Into::into));
    match outcome {
        Ok(result) => {
            let mut row = TaskResult {
                arch,
                task,
                status: Status::Completed,
                elapsed_ms: elapsed(started),
                result: Some(result),
                error: None,
            };
            let bytes = match serde_json::to_vec(&row) {
                Ok(bytes) => bytes,
                Err(error) => return failed(arch, row.task, started, error.into()),
            };
            if bytes.len() > MAX_TASK_BYTES || bytes.len() > *remaining {
                row.status = Status::OutputLimit;
                row.result = None;
                row.error = Some("task exceeded the serialized output budget; select fewer/smaller tasks".to_owned());
                row
            } else {
                *remaining -= bytes.len();
                row
            }
        }
        Err(error) => failed(arch, task, started, error),
    }
}

fn failed(arch: Arch, task: Task, started: Instant, error: anyhow::Error) -> TaskResult {
    let error: String = format!("{error:#}").chars().take(4096).collect();
    TaskResult { arch, task, status: Status::Failed, elapsed_ms: elapsed(started), result: None, error: Some(error) }
}

pub fn analyze(out: &mut impl Write, args: &AnalyzeArgs, options: &Options) -> Result<()> {
    if args.all_architectures && options.arch.is_some() {
        bail!("select either --all-architectures or --arch");
    }
    if args.function.len() > MAX_FUNCTIONS || args.function.iter().any(|name| name.is_empty() || name.len() > 4096) {
        bail!("select at most 16 nonempty function addresses/names, each at most 4096 bytes");
    }
    if args.workflow.len() > MAX_TASKS || args.workflow.is_empty() && args.function.is_empty() {
        bail!("select 1..64 workflows or function decompilations");
    }
    let compares = args.workflow.iter().any(|workflow| workflow.registered().compares());
    if compares != args.other.is_some() {
        bail!("--other is required exactly when diff-builds is selected");
    }
    let started = Instant::now();
    let arches = if args.all_architectures {
        rampage_loaders::Binary::architecture_slices(&args.file, options.image)?
    } else {
        vec![match options.arch {
            Some(arch) => arch,
            None => open(&args.file, options)?.binary.arch,
        }]
    };
    if arches.len().checked_mul(args.workflow.len() + args.function.len()).is_none_or(|count| count > MAX_TASKS) {
        bail!("analysis exceeds the 64-task limit; select fewer workflows, functions or architectures");
    }
    let mut analysis = Analysis {
        schema: "rampage-analysis-batch-v1",
        file: args.file.to_string_lossy().into_owned(),
        file_display_lossy: args.file.to_str().is_none(),
        image_offset: options.image.map(ImageAt::offset),
        image_length: options.image.and_then(ImageAt::length),
        targets: Vec::new(),
        tasks: Vec::new(),
        completed_tasks: 0,
        failed_tasks: 0,
        elapsed_ms: 0,
        decompile_timeout_ms: args.decompile_timeout_ms,
        max_task_bytes: MAX_TASK_BYTES,
        max_result_bytes: MAX_RESULT_BYTES,
        limitations: vec![
            "Completed tasks mean queries returned, not that discovered functions or decompilation are correct.",
            "Decompilation recovery_status and diagnostics remain in each result; warnings are not hidden.",
            "The deadline bounds supervised decompilation; workflows have their existing algorithmic/output budgets, not a wall-clock deadline.",
            "Input files must remain quiescent. Each slice has its own image/source identity; this is not an atomic multi-slice snapshot.",
            "All-architecture mode enumerates supported declared CPUs; unsupported architectures are not inferred or analyzed.",
            "No target binaries are executed, annotations applied or suggested next-step tool calls followed.",
        ],
    };
    let mut remaining = MAX_RESULT_BYTES - 2 * 1024 * 1024;
    for arch in arches {
        let slice_options = Options {
            json: true,
            arch: Some(arch),
            image: options.image,
            packs: std::sync::Arc::clone(&options.packs),
        };
        let project = open(&args.file, &slice_options);
        let project = match project {
            Ok(project) => project,
            Err(error) => {
                let message: String = format!("{error:#}").chars().take(4096).collect();
                analysis.targets.push(Target {
                    arch,
                    image_sha256: None,
                    source_sha256: None,
                    capture_identity: None,
                    error: Some(message.clone()),
                });
                let tasks = args
                    .workflow
                    .iter()
                    .map(|workflow| Task::Workflow { name: workflow.registered().name().to_owned() })
                    .chain(args.function.iter().map(|function| Task::Decompile { function: function.clone() }));
                analysis
                    .tasks
                    .extend(tasks.map(|task| failed(arch, task, Instant::now(), anyhow::anyhow!(message.clone()))));
                continue;
            }
        };
        project.set_decompiler_worker(Some(DecompilerWorkerConfig {
            timeout: Duration::from_millis(args.decompile_timeout_ms),
            max_stdout_bytes: MAX_TASK_BYTES,
            ..DecompilerWorkerConfig::default()
        }));
        let triage = project.triage();
        analysis.targets.push(Target {
            arch,
            image_sha256: Some(triage.image_hashes.sha256.clone()),
            source_sha256: Some(triage.file_hashes.as_ref().unwrap_or(&triage.image_hashes).sha256.clone()),
            capture_identity: triage.capture_identity.clone(),
            error: None,
        });
        for workflow in &args.workflow {
            let workflow = workflow.registered();
            let task = Task::Workflow { name: workflow.name().to_owned() };
            let started = Instant::now();
            let workflow_options = WorkflowOptions {
                limits: ReportLimits::new(args.limit),
                decompile: !args.no_decompile,
                other: workflow.compares().then(|| args.other.clone()).flatten(),
                other_image: workflow
                    .compares()
                    .then(|| args.other_image_offset.map(|offset| ImageAt::new(offset, args.other_image_length)))
                    .flatten(),
            };
            analysis.tasks.push(retain(
                arch,
                task,
                started,
                || workflow.run(&project, &workflow_options).map_err(Into::into),
                &mut remaining,
            ));
        }
        for function in &args.function {
            let task = Task::Decompile { function: function.clone() };
            let started = Instant::now();
            analysis.tasks.push(retain(
                arch,
                task,
                started,
                || project.resolve(function).and_then(|address| project.decompile(address)).map_err(Into::into),
                &mut remaining,
            ));
        }
    }
    analysis.elapsed_ms = elapsed(started);
    let encoded = encode(&mut analysis)?;
    if options.json {
        out.write_all(&encoded)?;
        out.write_all(b"\n")?;
    } else {
        render(out, &analysis)?;
    }
    if analysis.failed_tasks > 0 {
        out.flush()?;
        bail!("{} analysis tasks did not complete; details retained in the report", analysis.failed_tasks);
    }
    Ok(())
}

fn encode(analysis: &mut Analysis) -> Result<Vec<u8>> {
    loop {
        analysis.completed_tasks = analysis.tasks.iter().filter(|task| task.status == Status::Completed).count();
        analysis.failed_tasks = analysis.tasks.len() - analysis.completed_tasks;
        let bytes = serde_json::to_vec(analysis)?;
        if bytes.len() < MAX_RESULT_BYTES {
            return Ok(bytes);
        }
        let Some(task) = analysis.tasks.iter_mut().rev().find(|task| task.result.is_some()) else {
            bail!("analysis report metadata exceeds the serialized output budget");
        };
        task.result = None;
        task.status = Status::OutputLimit;
        task.error = Some("result omitted to keep the complete serialized report within its output budget".to_owned());
    }
}

fn render(out: &mut impl Write, analysis: &Analysis) -> Result<()> {
    writeln!(
        out,
        "{}: {} completed, {} failed tasks across {} slices",
        analysis.file,
        analysis.completed_tasks,
        analysis.failed_tasks,
        analysis.targets.len()
    )?;
    for target in &analysis.targets {
        writeln!(out, "{} image sha256 {}", target.arch, target.image_sha256.as_deref().unwrap_or("unavailable"))?;
    }
    for task in &analysis.tasks {
        let selector = match &task.task {
            Task::Workflow { name } => name,
            Task::Decompile { function } => function,
        };
        writeln!(out, "{} {selector}: {:?} ({} ms)", task.arch, task.status, task.elapsed_ms)?;
        if let Some(status) = task.result.as_ref().and_then(|result| result.get("recovery_status")) {
            writeln!(out, "  recovery_status: {status}")?;
        }
        if let Some(result) = &task.result {
            match &task.task {
                Task::Workflow { .. } => render_workflow(out, result)?,
                Task::Decompile { .. } => {
                    if let Some(code) = result.get("code").and_then(Value::as_str) {
                        writeln!(out, "{code}")?;
                    }
                }
            }
        }
        if let Some(error) = &task.error {
            writeln!(out, "  {error}")?;
        }
    }
    for limitation in &analysis.limitations {
        writeln!(out, "note: {limitation}")?;
    }
    Ok(())
}

fn lines(value: Option<&Value>) -> impl Iterator<Item = &str> {
    value.and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str)
}

fn render_workflow(out: &mut impl Write, report: &Value) -> Result<()> {
    for summary in lines(report.get("summary")) {
        writeln!(out, "  {summary}")?;
    }
    for section in report.get("sections").and_then(Value::as_array).into_iter().flatten() {
        writeln!(out, "  == {} ==", section.get("title").and_then(Value::as_str).unwrap_or("section"))?;
        for finding in section.get("findings").and_then(Value::as_array).into_iter().flatten() {
            writeln!(
                out,
                "    [{}] {}",
                finding.get("confidence").and_then(Value::as_str).unwrap_or("unknown"),
                finding.get("observation").and_then(Value::as_str).unwrap_or("unreadable finding")
            )?;
            for evidence in lines(finding.get("evidence")) {
                writeln!(out, "      {evidence}")?;
            }
        }
        if let Some(excerpt) = section.get("excerpt") {
            if let Some(text) = excerpt.get("text").and_then(Value::as_str) {
                writeln!(out, "{text}")?;
            }
            if excerpt.get("truncated").and_then(Value::as_bool) == Some(true) {
                writeln!(out, "  ... (cut)")?;
            }
        }
        if section.get("truncated").and_then(Value::as_bool) == Some(true) {
            writeln!(out, "    findings truncated; use --json for counts")?;
        }
    }
    for limitation in lines(report.get("limitations")) {
        writeln!(out, "  note: {limitation}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task() -> Task {
        Task::Decompile { function: "selected".to_owned() }
    }

    #[test]
    fn completed_queries_preserve_recovery_warnings() {
        let mut remaining = 1024;
        let result = retain(
            Arch::Aarch64,
            task(),
            Instant::now(),
            || {
                Ok(serde_json::json!({
                    "recovery_status": "incomplete", "code": "halt_baddata();", "diagnostics": {"bad_data": true},
                }))
            },
            &mut remaining,
        );
        assert_eq!(result.status, Status::Completed);
        assert_eq!(result.result.unwrap()["recovery_status"], "incomplete");
        assert!(remaining < 1024);
    }

    #[test]
    fn output_budget_rejects_whole_results_and_never_returns_partial_json() {
        let mut remaining = 5;
        let result = retain(
            Arch::Aarch64,
            task(),
            Instant::now(),
            || Ok(serde_json::json!({"message": "large"})),
            &mut remaining,
        );
        assert_eq!(result.status, Status::OutputLimit);
        assert!(result.result.is_none());
        assert_eq!(remaining, 5);
        let mut remaining = 0;
        let result =
            retain::<Value>(Arch::Aarch64, task(), Instant::now(), || panic!("exhausted task ran"), &mut remaining);
        assert_eq!(result.status, Status::NotRun);
    }

    #[test]
    fn task_errors_preserve_their_context_instead_of_failing_report_encoding() {
        let mut remaining = 1024;
        let result = retain::<Value>(
            Arch::Aarch64,
            task(),
            Instant::now(),
            || Err(anyhow::anyhow!("selected address is unavailable")),
            &mut remaining,
        );
        assert_eq!(result.status, Status::Failed);
        assert!(result.error.unwrap().contains("unavailable"));
        assert!(result.result.is_none());
    }

    #[test]
    fn task_envelopes_count_against_the_serialized_budget() {
        let mut remaining = usize::MAX;
        let value = Value::String("x".repeat(MAX_TASK_BYTES - 3));
        assert!(serde_json::to_vec(&value).unwrap().len() < MAX_TASK_BYTES);
        let row = retain(Arch::Aarch64, task(), Instant::now(), || Ok(value), &mut remaining);
        assert_eq!(row.status, Status::OutputLimit);
        assert!(row.result.is_none());
    }

    #[test]
    fn whole_report_encoding_bounds_wrappers_and_retains_omitted_task_outcomes() {
        let mut remaining = usize::MAX;
        let tasks = (0..8)
            .map(|_| {
                retain(
                    Arch::Aarch64,
                    task(),
                    Instant::now(),
                    || Ok(Value::String("x".repeat(2 * 1024 * 1024))),
                    &mut remaining,
                )
            })
            .collect();
        let mut report = Analysis {
            schema: "rampage-analysis-batch-v1",
            file: "fixture".to_owned(),
            file_display_lossy: false,
            image_offset: None,
            image_length: None,
            targets: vec![],
            tasks,
            completed_tasks: 0,
            failed_tasks: 0,
            elapsed_ms: 0,
            decompile_timeout_ms: 30_000,
            max_task_bytes: MAX_TASK_BYTES,
            max_result_bytes: MAX_RESULT_BYTES,
            limitations: vec![],
        };
        let bytes = encode(&mut report).unwrap();
        assert!(bytes.len() < MAX_RESULT_BYTES);
        assert_eq!(report.tasks.len(), 8);
        assert_eq!(report.completed_tasks, 7);
        assert_eq!(report.failed_tasks, 1);
        assert_eq!(report.tasks[7].status, Status::OutputLimit);
        let json: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json["tasks"][7]["result"].is_null());
    }

    #[test]
    fn text_previews_state_truncation_independently_of_finding_counts() {
        let report = serde_json::json!({"sections": [{"title": "preview", "findings": [], "truncated": false,
            "excerpt": {"text": "selected code", "truncated": true}}]});
        let mut out = Vec::new();
        render_workflow(&mut out, &report).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("selected code"));
        assert!(text.contains("... (cut)"));
    }
}
