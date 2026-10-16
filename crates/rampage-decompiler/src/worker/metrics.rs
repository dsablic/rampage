//! Opt-in host observations, outside the strict worker wire protocol.
//!
//! Milestones are monotonic offsets in microseconds from supervisor entry, not additive phase durations.
//! Pipe work overlaps execution. Exit timestamps describe host observation, not the kernel's exact exit time.

use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

use serde::Serialize;

use super::{ByteCleanup, WorkerError, WorkerOutput};

#[derive(Debug)]
pub struct SupervisedRun {
    pub result: Result<WorkerOutput, WorkerError>,
    pub metrics: SupervisedMetrics,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupervisedMetrics {
    pub total_elapsed_us: u64,
    pub request_preflight_complete_us: Option<u64>,
    pub request_serialization_started_us: Option<u64>,
    pub request_serialization_complete_us: Option<u64>,
    pub spawn_started_us: Option<u64>,
    pub spawn_complete_us: Option<u64>,
    pub pipe_setup_complete_us: Option<u64>,
    pub input: SupervisedInputMetrics,
    pub stdout: SupervisedStreamMetrics,
    pub stderr: SupervisedStreamMetrics,
    pub exit_observed_us: Option<u64>,
    pub root_reaped_us: Option<u64>,
    pub root_exit_status: Option<SupervisedExitStatus>,
    pub cleanup_started_us: Option<u64>,
    pub cleanup_finished_us: Option<u64>,
    pub cleanup_succeeded: Option<bool>,
    /// Secondary cleanup diagnostics, retained even when a primary exit/protocol/decompile error takes precedence.
    pub cleanup_error: Option<SupervisedCleanupError>,
    /// Private ABI v1 response-flushed completion, not a native initialization or operation-success milestone.
    pub control_completion_us: Option<u64>,
    /// Authenticated completion/full input and a successful live-root signal with actual SIGKILL exit.
    /// Output EOF is drained separately after group shutdown; this flag alone never means operation success.
    pub intentional_stop: bool,
    pub response_decode_started_us: Option<u64>,
    /// Strict response decoding completed; subsequent version/output checks may still fail.
    pub response_decoded_us: Option<u64>,
    pub ownership: SupervisedOwnership,
    pub rss: SupervisedRssMetrics,
}

impl SupervisedMetrics {
    fn new() -> Self {
        Self {
            total_elapsed_us: 0,
            request_preflight_complete_us: None,
            request_serialization_started_us: None,
            request_serialization_complete_us: None,
            spawn_started_us: None,
            spawn_complete_us: None,
            pipe_setup_complete_us: None,
            input: SupervisedInputMetrics::default(),
            stdout: SupervisedStreamMetrics::default(),
            stderr: SupervisedStreamMetrics::default(),
            exit_observed_us: None,
            root_reaped_us: None,
            root_exit_status: None,
            cleanup_started_us: None,
            cleanup_finished_us: None,
            cleanup_succeeded: None,
            cleanup_error: None,
            control_completion_us: None,
            intentional_stop: false,
            response_decode_started_us: None,
            response_decoded_us: None,
            ownership: SupervisedOwnership::NotSpawned,
            rss: SupervisedRssMetrics::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SupervisedInputMetrics {
    pub requested_bytes: Option<u64>,
    pub written_bytes: u64,
    pub started_us: Option<u64>,
    /// Host return from the first successful nonempty write, not proof of child consumption.
    pub first_write_us: Option<u64>,
    pub finished_us: Option<u64>,
    /// Full delivery means bytes written to the pipe, not proof of worker parsing or engine initialization.
    pub outcome: Option<SupervisedInputOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisedInputOutcome {
    FullyDelivered,
    BrokenPipe,
    Stopped,
    WriteError,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SupervisedStreamMetrics {
    /// Actual bytes read, including a chunk that may have triggered the output limit.
    pub read_bytes: u64,
    pub started_us: Option<u64>,
    pub first_byte_us: Option<u64>,
    pub eof_us: Option<u64>,
    pub finished_us: Option<u64>,
    pub outcome: Option<SupervisedStreamOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisedStreamOutcome {
    Eof,
    Stopped,
    OutputLimit,
    ReadError,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SupervisedExitStatus {
    pub success: bool,
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SupervisedCleanupError {
    GroupSignal { os_code: Option<i32>, root_failed: bool, root_os_code: Option<i32> },
    OwnedChild { os_code: Option<i32> },
    Other,
}

impl From<&WorkerError> for SupervisedCleanupError {
    fn from(error: &WorkerError) -> Self {
        match error {
            WorkerError::Cleanup { group, root } => {
                let root_os_code = match root.as_deref() {
                    Some(WorkerError::Io { source, .. }) => source.raw_os_error(),
                    _ => None,
                };
                Self::GroupSignal { os_code: group.raw_os_error(), root_failed: root.is_some(), root_os_code }
            }
            WorkerError::Io { source, .. } => Self::OwnedChild { os_code: source.raw_os_error() },
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisedOwnership {
    NotSpawned,
    Unreaped,
    Reaped,
    Unverified,
}

/// Direct-root resident bytes, shared-inclusive. Neither private memory nor a descendant/process-group sum.
/// A sampled maximum is not a guaranteed peak. No successful sample is represented by None, never zero.
/// An actual successful zero reading is retained as Some(0) and counted separately.
#[derive(Debug, Clone, Serialize)]
pub struct SupervisedRssMetrics {
    pub max_observed_child_rss_bytes: Option<u64>,
    pub attempts: u64,
    pub samples: u64,
    pub unavailable_samples: u64,
    pub zero_samples: u64,
    pub error_count: u64,
    pub last_error: Option<SupervisedRssError>,
    pub first_sample_us: Option<u64>,
    pub last_sample_us: Option<u64>,
    pub backend: SupervisedRssBackend,
    /// Supervisor receive-wait cap, not a guarantee of regular sampling or scheduler latency.
    pub nominal_poll_interval_us: Option<u64>,
}

impl SupervisedRssMetrics {
    fn new() -> Self {
        let backend = if cfg!(all(target_os = "macos", target_pointer_width = "64")) {
            SupervisedRssBackend::DarwinProcPidInfo
        } else if cfg!(all(target_os = "linux", target_pointer_width = "64")) {
            SupervisedRssBackend::LinuxProcStatus
        } else {
            SupervisedRssBackend::Unavailable
        };
        Self {
            max_observed_child_rss_bytes: None,
            attempts: 0,
            samples: 0,
            unavailable_samples: 0,
            zero_samples: 0,
            error_count: 0,
            last_error: None,
            first_sample_us: None,
            last_sample_us: None,
            backend,
            nominal_poll_interval_us: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisedRssBackend {
    DarwinProcPidInfo,
    LinuxProcStatus,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisedRssError {
    PermissionDenied,
    InvalidData,
    Interrupted,
    Other,
}

pub(super) struct Measurement {
    started: Instant,
    data: Option<Mutex<SupervisedMetrics>>,
    cleanup: AtomicU8,
}

impl Measurement {
    pub(super) fn new(started: Instant, enabled: bool) -> Self {
        Self {
            started,
            data: enabled.then(|| Mutex::new(SupervisedMetrics::new())),
            cleanup: AtomicU8::new(ByteCleanup::NotSpawned as u8),
        }
    }

    pub(super) fn cleanup_disposition(&self) -> ByteCleanup {
        match self.cleanup.load(Ordering::Acquire) {
            value if value == ByteCleanup::NotSpawned as u8 => ByteCleanup::NotSpawned,
            value if value == ByteCleanup::Confirmed as u8 => ByteCleanup::Confirmed,
            _ => ByteCleanup::Uncertain,
        }
    }

    pub(super) fn cleanup_uncertain(&self) {
        self.cleanup.store(ByteCleanup::Uncertain as u8, Ordering::Release);
    }

    pub(super) fn spawn_failed(&self) {
        self.cleanup.store(ByteCleanup::NotSpawned as u8, Ordering::Release);
    }

    pub(super) fn cleanup_confirmed(&self) {
        self.cleanup.store(ByteCleanup::Confirmed as u8, Ordering::Release);
    }

    pub(super) fn enabled(&self) -> bool {
        self.data.is_some()
    }

    pub(super) fn elapsed_us(&self) -> u64 {
        self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
    }

    pub(super) fn record(&self, update: impl FnOnce(&mut SupervisedMetrics, u64)) {
        if let Some(data) = &self.data {
            let elapsed = self.elapsed_us();
            let mut data = data.lock().unwrap_or_else(|poison| poison.into_inner());
            update(&mut data, elapsed);
        }
    }

    pub(super) fn rss(&self, sample: &io::Result<Option<u64>>) {
        self.record(|data, elapsed| {
            let rss = &mut data.rss;
            rss.attempts = rss.attempts.saturating_add(1);
            match sample {
                Ok(Some(bytes)) => {
                    rss.samples = rss.samples.saturating_add(1);
                    rss.zero_samples = rss.zero_samples.saturating_add(u64::from(*bytes == 0));
                    rss.max_observed_child_rss_bytes = Some(rss.max_observed_child_rss_bytes.unwrap_or(0).max(*bytes));
                    rss.first_sample_us.get_or_insert(elapsed);
                    rss.last_sample_us = Some(elapsed);
                }
                Ok(None) => rss.unavailable_samples = rss.unavailable_samples.saturating_add(1),
                Err(error) => {
                    rss.error_count = rss.error_count.saturating_add(1);
                    rss.last_error = Some(match error.kind() {
                        io::ErrorKind::PermissionDenied => SupervisedRssError::PermissionDenied,
                        io::ErrorKind::InvalidData => SupervisedRssError::InvalidData,
                        io::ErrorKind::Interrupted => SupervisedRssError::Interrupted,
                        _ => SupervisedRssError::Other,
                    });
                }
            }
        });
    }

    pub(super) fn finish(self) -> Option<SupervisedMetrics> {
        self.record(|data, elapsed| data.total_elapsed_us = elapsed);
        self.data.map(|data| data.into_inner().unwrap_or_else(|poison| poison.into_inner()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_and_error_samples_do_not_manufacture_a_zero_maximum() {
        let measurement = Measurement::new(Instant::now(), true);
        measurement.rss(&Ok(None));
        measurement.rss(&Err(io::ErrorKind::PermissionDenied.into()));
        let metrics = measurement.finish().unwrap();
        assert_eq!(metrics.rss.max_observed_child_rss_bytes, None);
        assert_eq!(metrics.rss.samples, 0);
        assert_eq!(metrics.rss.unavailable_samples, 1);
        assert_eq!(metrics.rss.error_count, 1);
        assert_eq!(metrics.rss.last_error, Some(SupervisedRssError::PermissionDenied));
    }

    #[test]
    fn sampled_maximum_and_zero_observations_are_distinct_from_missing_samples() {
        let measurement = Measurement::new(Instant::now(), true);
        for bytes in [0, 8192, 4096] {
            measurement.rss(&Ok(Some(bytes)));
        }
        let metrics = measurement.finish().unwrap();
        assert_eq!(metrics.rss.max_observed_child_rss_bytes, Some(8192));
        assert_eq!(metrics.rss.samples, 3);
        assert_eq!(metrics.rss.zero_samples, 1);
    }

    #[test]
    fn disabled_measurement_never_evaluates_updates_or_allocates_a_report() {
        let measurement = Measurement::new(Instant::now(), false);
        measurement.record(|_, _| panic!("disabled measurement invoked its update"));
        assert!(measurement.finish().is_none());
    }

    #[test]
    fn mandatory_cleanup_proof_does_not_enable_diagnostic_collection() {
        let measurement = Measurement::new(Instant::now(), false);
        assert_eq!(measurement.cleanup_disposition(), ByteCleanup::NotSpawned);
        measurement.cleanup_uncertain();
        assert_eq!(measurement.cleanup_disposition(), ByteCleanup::Uncertain);
        measurement.spawn_failed();
        assert_eq!(measurement.cleanup_disposition(), ByteCleanup::NotSpawned);
        measurement.cleanup_uncertain();
        measurement.cleanup_confirmed();
        assert_eq!(measurement.cleanup_disposition(), ByteCleanup::Confirmed);
        assert!(!measurement.enabled());
        measurement.record(|_, _| panic!("cleanup tracking enabled diagnostic collection"));
        assert!(measurement.finish().is_none());
    }
}
