use std::cell::RefCell;
use std::fs::{DirBuilder, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::{Duration, Instant};

use super::*;
use crate::annotations::{Annotations, Field};
use crate::{DebuggerCapturePublicationStatus, FunctionsQuery, ProjectWorkspaceProgress};

const DEADLINE: Duration = Duration::from_secs(10);
static NEXT: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static ANNOTATION_WAIT: RefCell<Option<(SyncSender<()>, Receiver<()>)>> = const { RefCell::new(None) };
}

pub(super) fn annotation_waiting() {
    let handshake = ANNOTATION_WAIT.with(|slot| slot.borrow_mut().take());
    if let Some((observed, resume)) = handshake {
        observed.send(()).unwrap();
        resume.recv_timeout(DEADLINE).unwrap();
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "inventory-contention-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Fixture {
    scratch: Scratch,
    source: PathBuf,
    cache: PathBuf,
    log: PathBuf,
    project: Arc<Project>,
    address: u64,
}

impl Fixture {
    fn new() -> Self {
        let scratch = Scratch::new();
        let source = scratch.0.join("owned.elf");
        let input = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/decode-x64.elf");
        std::fs::copy(input, &source).unwrap();
        let original = Arc::new(Project::new(rampage_loaders::Binary::open(&source).unwrap()));
        let functions = original.functions(&FunctionsQuery { limit: Some(1), ..Default::default() }).unwrap();
        let address = functions.items[0].address;
        original.rename(address, Some("inventory_name_a")).unwrap();
        let cache = scratch.0.join("cache.json");
        controlled(|control| {
            let prepared = capture_function_inventory(Arc::clone(&original), control).unwrap();
            publish_function_inventory(&prepared, &cache, control).unwrap();
        });
        let log = scratch.0.join("annotations.jsonl");
        let mut annotations = Annotations::open_checked(log.clone()).unwrap();
        annotations.set(Field::Name, address, Some("inventory_name_a".into())).unwrap();
        annotations.refresh().unwrap();
        let project = Arc::new(Project::with_annotations(rampage_loaders::Binary::open(&source).unwrap(), annotations));
        Self { scratch, source, cache, log, project, address }
    }

    fn block_comment_log(&self) -> File {
        let mut lock_path = self.log.as_os_str().to_owned();
        lock_path.push(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(PathBuf::from(lock_path))
            .unwrap();
        file.lock().unwrap();
        file
    }
}

fn controlled<T>(work: impl FnOnce(&mut ProjectWorkspaceTaskControl<'_>) -> T) -> T {
    let cancellation = AtomicBool::new(false);
    let mut observer = |_| {};
    work(&mut ProjectWorkspaceTaskControl::new(&cancellation, &mut observer))
}

fn wait_for_comment_writer(project: &Project) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        match project.annotations.try_read() {
            Err(std::sync::TryLockError::WouldBlock) => return,
            Err(std::sync::TryLockError::Poisoned(_)) => panic!("annotation lock poisoned"),
            Ok(guard) => drop(guard),
        }
        assert!(Instant::now() < deadline, "comment writer did not acquire the annotation lock");
        std::thread::yield_now();
    }
}

#[derive(Clone, Copy)]
enum Stage {
    InitialNames,
    KeyNames,
    FinalValidation,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Comment,
    Cancel,
    RenameAba,
    TruncateSource,
    RemoveSource,
}

fn contended_read(stage: Stage, action: Action) {
    let fixture = Fixture::new();
    let original_nonce = fixture.project.names_revision().unwrap();
    let cancellation = AtomicBool::new(false);
    let outcome = std::thread::scope(|scope| {
        let fixture = &fixture;
        let cancellation = &cancellation;
        let blocker = fixture.block_comment_log();
        let (start_writer, writer_start) = sync_channel(0);
        let writer = scope.spawn(move || {
            writer_start.recv_timeout(DEADLINE).unwrap();
            fixture.project.comment(fixture.address, Some("real comment writer held by its log lock")).unwrap();
        });
        let (waiting, waited) = sync_channel(0);
        let (resume, resumed) = sync_channel(0);
        let (done, result) = sync_channel(0);
        let reader = scope.spawn(move || {
            ANNOTATION_WAIT.with(|slot| *slot.borrow_mut() = Some((waiting, resumed)));
            let mut identity_phases = 0;
            let mut started = false;
            let mut observer = |progress: ProjectWorkspaceProgress| {
                if progress.phase == ProjectWorkspacePhase::ValidatingIdentity {
                    identity_phases += 1;
                }
                let at_stage = match stage {
                    Stage::InitialNames => {
                        progress.phase == ProjectWorkspacePhase::ValidatingIdentity && identity_phases == 1
                    }
                    Stage::KeyNames => {
                        progress.phase == ProjectWorkspacePhase::ValidatingIdentity && identity_phases == 2
                    }
                    Stage::FinalValidation => progress.phase == ProjectWorkspacePhase::ResultValidation,
                };
                if !started && at_stage {
                    started = true;
                    start_writer.send(()).unwrap();
                    wait_for_comment_writer(&fixture.project);
                }
            };
            let outcome = read_function_inventory(
                Arc::clone(&fixture.project),
                &fixture.cache,
                &mut ProjectWorkspaceTaskControl::new(cancellation, &mut observer),
            );
            assert!(done.send(outcome).is_ok());
        });
        waited.recv_timeout(DEADLINE).unwrap();
        assert!(matches!(fixture.project.names_revision(), Err(ApiError::Unavailable(_))));
        let outcome = if action == Action::Cancel {
            cancellation.store(true, Ordering::Relaxed);
            resume.send(()).unwrap();
            let outcome = result.recv_timeout(DEADLINE).unwrap();
            blocker.unlock().unwrap();
            writer.join().unwrap();
            outcome
        } else {
            blocker.unlock().unwrap();
            writer.join().unwrap();
            match action {
                Action::RenameAba => {
                    fixture.project.rename(fixture.address, Some("inventory_name_b")).unwrap();
                    fixture.project.rename(fixture.address, Some("inventory_name_a")).unwrap();
                }
                Action::TruncateSource => {
                    OpenOptions::new().write(true).open(&fixture.source).unwrap().set_len(0).unwrap();
                }
                Action::RemoveSource => std::fs::remove_file(&fixture.source).unwrap(),
                Action::Comment => {}
                Action::Cancel => unreachable!(),
            }
            resume.send(()).unwrap();
            result.recv_timeout(DEADLINE).unwrap()
        };
        reader.join().unwrap();
        outcome
    });
    assert_eq!(fixture.project.analysis_cache_status(), crate::AnalysisCacheStatus::default());
    match action {
        Action::Comment => match outcome.unwrap() {
            InventoryCacheReadOutcome::Hit(view) => {
                assert!(Arc::ptr_eq(&original_nonce, view.names_revision()));
                assert_eq!(view.rows()[0].name, "inventory_name_a");
                view.validate_current_metadata(&fixture.project).unwrap();
                assert_eq!(
                    fixture.project.comment_at(fixture.address).as_deref(),
                    Some("real comment writer held by its log lock")
                );
            }
            _ => panic!("temporary comment contention discarded the requested read"),
        },
        Action::Cancel => assert!(matches!(outcome, Err(ApiError::Unavailable(_)))),
        Action::RenameAba | Action::TruncateSource => {
            assert!(matches!(outcome.unwrap(), InventoryCacheReadOutcome::SourceChanged));
            if action == Action::RenameAba {
                assert!(!Arc::ptr_eq(&original_nonce, &fixture.project.names_revision().unwrap()));
                assert_eq!(fixture.project.function_name(fixture.address), "inventory_name_a");
            }
        }
        Action::RemoveSource => {
            assert!(matches!(outcome, Err(ApiError::Load { source: rampage_loaders::LoadError::Io { .. }, .. })));
        }
    }
}

#[test]
fn real_comment_writer_contention_resumes_early_names_key_and_final_read_validation() {
    for stage in [Stage::InitialNames, Stage::KeyNames, Stage::FinalValidation] {
        contended_read(stage, Action::Comment);
    }
}

#[test]
fn cancellation_during_annotation_wait_finishes_before_the_comment_writer_is_unblocked() {
    for stage in [Stage::InitialNames, Stage::KeyNames, Stage::FinalValidation] {
        contended_read(stage, Action::Cancel);
    }
}

#[test]
fn key_and_final_waits_retain_the_original_names_nonce_across_real_rename_aba() {
    for stage in [Stage::KeyNames, Stage::FinalValidation] {
        contended_read(stage, Action::RenameAba);
    }
}

#[test]
fn source_changes_after_annotation_wait_are_guarded_and_io_errors_are_not_source_changed() {
    for stage in [Stage::KeyNames, Stage::FinalValidation] {
        contended_read(stage, Action::TruncateSource);
        contended_read(stage, Action::RemoveSource);
    }
}

#[test]
fn post_link_annotation_wait_cancellation_preserves_the_committed_publication() {
    let fixture = Fixture::new();
    fixture.project.functions(&FunctionsQuery { limit: Some(0), ..Default::default() }).unwrap();
    let prepared = controlled(|control| capture_function_inventory(Arc::clone(&fixture.project), control)).unwrap();
    let output = fixture.scratch.0.join("post-link.json");
    let cancellation = AtomicBool::new(false);
    let publication = std::thread::scope(|scope| {
        let fixture = &fixture;
        let cancellation = &cancellation;
        let prepared = &prepared;
        let output = &output;
        let blocker = fixture.block_comment_log();
        let (start_writer, writer_start) = sync_channel(0);
        let writer = scope.spawn(move || {
            writer_start.recv_timeout(DEADLINE).unwrap();
            fixture.project.comment(fixture.address, Some("comment during post-link validation")).unwrap();
        });
        let (waiting, waited) = sync_channel(0);
        let (resume, resumed) = sync_channel(0);
        let (done, result) = sync_channel(0);
        let publisher = scope.spawn(move || {
            ANNOTATION_WAIT.with(|slot| *slot.borrow_mut() = Some((waiting, resumed)));
            let mut observer = |progress: ProjectWorkspaceProgress| {
                if progress.phase == ProjectWorkspacePhase::ValidatingCache {
                    start_writer.send(()).unwrap();
                    wait_for_comment_writer(&fixture.project);
                }
            };
            assert!(
                done.send(publish_function_inventory(
                    prepared,
                    output,
                    &mut ProjectWorkspaceTaskControl::new(cancellation, &mut observer),
                ))
                .is_ok()
            );
        });
        waited.recv_timeout(DEADLINE).unwrap();
        assert!(output.exists());
        cancellation.store(true, Ordering::Relaxed);
        resume.send(()).unwrap();
        let publication = result.recv_timeout(DEADLINE).unwrap().unwrap();
        blocker.unlock().unwrap();
        writer.join().unwrap();
        publisher.join().unwrap();
        publication
    });
    assert_eq!(publication.status, DebuggerCapturePublicationStatus::PublishedUncertain);
    assert!(output.exists());
    assert!(!publication.warnings.is_empty());
}
