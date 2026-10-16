use std::sync::atomic::{AtomicU8, Ordering};

use rampage_decompiler::worker::ByteCleanup;

use crate::PluginError;

const IDLE: u8 = 0;
const RUNNING: u8 = 1;
const QUARANTINED: u8 = 2;

static ADMISSION: Admission = Admission::new();

/// Parent-owned execution state. Quarantine has no in-process reset: inspect unresolved workers before restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginAdmission {
    Idle,
    Running,
    Quarantined,
}

pub fn admission_status() -> PluginAdmission {
    ADMISSION.status()
}

struct Admission {
    state: AtomicU8,
}

impl Admission {
    const fn new() -> Self {
        Self { state: AtomicU8::new(IDLE) }
    }

    fn status(&self) -> PluginAdmission {
        match self.state.load(Ordering::Acquire) {
            IDLE => PluginAdmission::Idle,
            RUNNING => PluginAdmission::Running,
            _ => PluginAdmission::Quarantined,
        }
    }

    fn acquire(&self) -> Result<Permit<'_>, PluginError> {
        match self.state.compare_exchange(IDLE, RUNNING, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(Permit { admission: self, state: LeaseState::NoWorker }),
            Err(RUNNING) => Err(PluginError::Busy),
            Err(_) => Err(PluginError::Quarantined),
        }
    }
}

enum LeaseState {
    NoWorker,
    AwaitingProof,
    Finished(ByteCleanup),
}

pub(crate) struct Permit<'a> {
    admission: &'a Admission,
    state: LeaseState,
}

impl Permit<'static> {
    pub(crate) fn acquire() -> Result<Self, PluginError> {
        ADMISSION.acquire()
    }
}

impl Permit<'_> {
    pub(crate) fn begin_supervision(&mut self) {
        self.state = LeaseState::AwaitingProof;
    }

    pub(crate) fn finish_supervision(&mut self, cleanup: ByteCleanup) {
        self.state = match self.state {
            LeaseState::AwaitingProof => LeaseState::Finished(cleanup),
            _ => LeaseState::Finished(ByteCleanup::Uncertain),
        };
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let state = match self.state {
            LeaseState::NoWorker | LeaseState::Finished(ByteCleanup::NotSpawned | ByteCleanup::Confirmed) => IDLE,
            LeaseState::AwaitingProof | LeaseState::Finished(ByteCleanup::Uncertain) => QUARANTINED,
        };
        self.admission.state.store(state, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unspawned_and_confirmed_cleanup_release_only_after_the_real_lease_drops() {
        for cleanup in [ByteCleanup::NotSpawned, ByteCleanup::Confirmed] {
            let admission = Admission::new();
            let mut permit = admission.acquire().unwrap();
            permit.begin_supervision();
            assert!(matches!(admission.acquire(), Err(PluginError::Busy)));
            permit.finish_supervision(cleanup);
            assert_eq!(admission.status(), PluginAdmission::Running);
            assert!(matches!(admission.acquire(), Err(PluginError::Busy)));
            drop(permit);
            assert_eq!(admission.status(), PluginAdmission::Idle);
            assert!(admission.acquire().is_ok());
        }
    }

    #[test]
    fn missing_uncertain_and_duplicate_cleanup_proofs_quarantine_instead_of_reopening() {
        for proof in [None, Some(ByteCleanup::Uncertain), Some(ByteCleanup::Confirmed)] {
            let admission = Admission::new();
            let mut permit = admission.acquire().unwrap();
            permit.begin_supervision();
            if let Some(proof) = proof {
                permit.finish_supervision(proof);
                if proof == ByteCleanup::Confirmed {
                    permit.finish_supervision(ByteCleanup::NotSpawned);
                }
            }
            drop(permit);
            assert_eq!(admission.status(), PluginAdmission::Quarantined);
            assert!(matches!(admission.acquire(), Err(PluginError::Quarantined)));
            assert!(matches!(admission.acquire(), Err(PluginError::Quarantined)));
        }
    }

    #[test]
    fn unwind_preserves_known_cleanup_and_quarantines_unfinished_supervision() {
        for proof in [None, Some(ByteCleanup::Confirmed), Some(ByteCleanup::Uncertain)] {
            let admission = Admission::new();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut permit = admission.acquire().unwrap();
                permit.begin_supervision();
                if let Some(proof) = proof {
                    permit.finish_supervision(proof);
                }
                panic!("intentional admission unwind");
            }));
            assert!(result.is_err());
            let expected = if proof == Some(ByteCleanup::Confirmed) {
                PluginAdmission::Idle
            } else {
                PluginAdmission::Quarantined
            };
            assert_eq!(admission.status(), expected);
        }
    }

    #[test]
    fn failures_before_supervision_neither_poison_nor_leave_a_running_lease() {
        let admission = Admission::new();
        drop(admission.acquire().unwrap());
        assert_eq!(admission.status(), PluginAdmission::Idle);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _permit = admission.acquire().unwrap();
            panic!("intentional pre-supervision unwind");
        }));
        assert!(result.is_err());
        assert_eq!(admission.status(), PluginAdmission::Idle);
    }
}
