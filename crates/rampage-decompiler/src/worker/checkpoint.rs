//! Opt-in cancellation-only control v2. Progress is never completion or PID/group authority.

use super::{SupervisedMetrics, WorkerError};

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ByteCheckpoint {
    Run = 1,
    Output = 2,
}

#[doc(hidden)]
#[derive(Debug)]
pub struct SupervisedBytesRun {
    pub result: Result<Vec<u8>, WorkerError>,
    pub metrics: SupervisedMetrics,
}

/// A lifecycle-created handle. Unselected/default-v1 checkpoints are no-ops. A selected park sends one
/// progress frame and blocks without a normal return; peer EOF or any command is an error, never resume.
#[doc(hidden)]
#[derive(Clone)]
pub struct BinaryCheckpoint {
    #[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
    inner: Option<std::sync::Arc<platform::ChildCheckpoint>>,
    _private: (),
}

impl BinaryCheckpoint {
    pub fn selected(&self) -> Option<ByteCheckpoint> {
        #[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
        {
            self.inner.as_ref().map(|inner| inner.selected)
        }
        #[cfg(not(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64")))]
        {
            None
        }
    }

    pub fn park(&self, checkpoint: ByteCheckpoint) -> Result<(), WorkerError> {
        #[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
        if let Some(inner) = &self.inner {
            return inner.park(checkpoint);
        }
        let _ = checkpoint;
        Ok(())
    }

    pub(super) fn disabled() -> Self {
        Self {
            #[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
            inner: None,
            _private: (),
        }
    }
}

pub(super) struct Observation<'a> {
    pub selected: ByteCheckpoint,
    pub observer: &'a mut dyn FnMut(ByteCheckpoint),
}

#[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
pub(super) mod platform {
    use std::io::{self, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::{Arc, Mutex};

    use super::{BinaryCheckpoint, ByteCheckpoint};
    use crate::worker::{WorkerError, io_error};

    pub(in crate::worker) const HELLO: &[u8] = b"RAMPAGE-CONTROL/2/HOST\0";
    const COMPLETE: [u8; 4] = [2, 0, 0, 0];

    fn protocol(message: &'static str) -> WorkerError {
        WorkerError::Protocol(message.to_owned())
    }

    pub(in crate::worker) fn selection(id: u8) -> Result<ByteCheckpoint, WorkerError> {
        match id {
            1 => Ok(ByteCheckpoint::Run),
            2 => Ok(ByteCheckpoint::Output),
            _ => Err(protocol("unknown binary checkpoint ID")),
        }
    }

    pub(in crate::worker) struct ChildCheckpoint {
        pub selected: ByteCheckpoint,
        socket: Mutex<UnixStream>,
        phase: AtomicU8,
    }

    impl ChildCheckpoint {
        pub(super) fn park(&self, point: ByteCheckpoint) -> Result<(), WorkerError> {
            if point != self.selected {
                return Ok(());
            }
            self.phase
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| protocol("duplicate or out-of-order binary checkpoint"))?;
            let mut socket = self.socket.lock().map_err(|_| protocol("binary checkpoint control lock poisoned"))?;
            socket.write_all(&[1, point as u8, 0, 0]).map_err(|error| io_error("write binary checkpoint", error))?;
            let mut byte = [0];
            loop {
                match socket.read(&mut byte) {
                    Ok(0) => return Err(protocol("parked binary checkpoint peer closed")),
                    Ok(_) => return Err(protocol("unexpected command for parked binary checkpoint")),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(io_error("wait at binary checkpoint", error)),
                }
            }
        }
    }

    pub(in crate::worker) fn handle(socket: UnixStream, selected: ByteCheckpoint) -> BinaryCheckpoint {
        BinaryCheckpoint {
            inner: Some(Arc::new(ChildCheckpoint { selected, socket: Mutex::new(socket), phase: AtomicU8::new(0) })),
            _private: (),
        }
    }

    pub(in crate::worker) fn complete(handle: &BinaryCheckpoint) -> Result<(), WorkerError> {
        let inner = handle.inner.as_ref().ok_or_else(|| protocol("missing binary checkpoint lifecycle"))?;
        inner
            .phase
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| protocol("binary handler returned after checkpoint parking"))?;
        let mut socket = inner.socket.lock().map_err(|_| protocol("binary checkpoint control lock poisoned"))?;
        socket.write_all(&COMPLETE).map_err(|error| io_error("write v2 completion", error))?;
        let mut byte = [0];
        loop {
            match socket.read(&mut byte) {
                Ok(0) => return Ok(()),
                Ok(_) => return Err(protocol("unexpected v2 completion command")),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(io_error("wait for v2 supervisor release", error)),
            }
        }
    }

    pub(in crate::worker) struct Host {
        pub socket: UnixStream,
        selected: ByteCheckpoint,
        frame: [u8; 4],
        received: usize,
        seen: bool,
        pending: Option<ByteCheckpoint>,
        invalid: bool,
    }

    impl Host {
        pub fn new(socket: UnixStream, selected: ByteCheckpoint) -> Self {
            Self { socket, selected, frame: [0; 4], received: 0, seen: false, pending: None, invalid: false }
        }

        pub fn take(&mut self) -> Option<ByteCheckpoint> {
            if self.invalid { None } else { self.pending.take() }
        }

        fn accept(&mut self) -> Result<(), WorkerError> {
            if self.seen {
                return Err(protocol("duplicate or out-of-order v2 frame"));
            }
            if self.frame[2] != 0 || self.frame[3] != 0 {
                return Err(protocol("nonzero reserved v2 frame bytes"));
            }
            match self.frame[0] {
                1 => {
                    let point = selection(self.frame[1])?;
                    if point != self.selected {
                        return Err(protocol("unexpected binary checkpoint selection"));
                    }
                    self.seen = true;
                    self.pending = Some(point);
                    Ok(())
                }
                2 if self.frame[1] == 0 => Err(protocol("binary worker completed without selected checkpoint")),
                _ => Err(protocol("unknown v2 control frame")),
            }
        }

        pub fn poll(&mut self) -> Result<(), WorkerError> {
            if self.invalid {
                return Err(protocol("v2 control already invalidated"));
            }
            let result = self.poll_inner();
            if result.is_err() {
                self.invalid = true;
                self.pending = None;
            }
            result
        }

        fn poll_inner(&mut self) -> Result<(), WorkerError> {
            if !self.seen {
                match self.socket.read(&mut self.frame[self.received..]) {
                    Ok(0) => return Err(protocol("missing or truncated v2 checkpoint frame")),
                    Ok(count) => {
                        self.received += count;
                        if self.received != 4 {
                            return Ok(());
                        }
                        self.accept()?;
                    }
                    Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {
                        return Ok(());
                    }
                    Err(error) => return Err(io_error("read v2 checkpoint", error)),
                }
            }
            let mut extra = [0];
            for _ in 0..8 {
                match self.socket.read(&mut extra) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Ok(0) => return Err(protocol("parked v2 peer closed before cancellation")),
                    Ok(_) => return Err(protocol("duplicate or out-of-order bytes after v2 checkpoint")),
                    Err(error) => return Err(io_error("inspect parked v2 peer", error)),
                }
            }
            Err(io_error("inspect parked v2 peer", io::ErrorKind::Interrupted.into()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn pair(selected: ByteCheckpoint) -> (Host, UnixStream) {
            let (host, child) = UnixStream::pair().unwrap();
            host.set_nonblocking(true).unwrap();
            (Host::new(host, selected), child)
        }

        #[test]
        fn partial_frame_yields_one_selected_event_and_no_completion() {
            let (mut host, mut child) = pair(ByteCheckpoint::Output);
            child.write_all(&[1, 2]).unwrap();
            host.poll().unwrap();
            assert!(host.take().is_none());
            child.write_all(&[0, 0]).unwrap();
            host.poll().unwrap();
            assert_eq!(host.take(), Some(ByteCheckpoint::Output));
            assert!(host.take().is_none());
            host.poll().unwrap();
            child.write_all(&COMPLETE).unwrap();
            assert!(matches!(host.poll(), Err(WorkerError::Protocol(_))));
            assert!(host.take().is_none());
        }

        #[test]
        fn unknown_reserved_duplicate_truncated_and_out_of_order_frames_fail_closed() {
            for frame in [[1, 3, 0, 0], [1, 2, 0, 0], [1, 1, 1, 0], [2, 0, 0, 0], [2, 1, 0, 0], [9, 0, 0, 0]] {
                let (mut host, mut child) = pair(ByteCheckpoint::Run);
                child.write_all(&frame).unwrap();
                assert!(matches!(host.poll(), Err(WorkerError::Protocol(_))));
                assert!(host.take().is_none());
            }
            for length in 0..4 {
                let (mut host, mut child) = pair(ByteCheckpoint::Run);
                child.write_all(&[1, 1, 0, 0][..length]).unwrap();
                drop(child);
                let mut rejected = false;
                for _ in 0..5 {
                    if host.poll().is_err() {
                        rejected = true;
                        break;
                    }
                }
                assert!(rejected, "truncated frame accepted");
                assert!(host.take().is_none());
            }
            let (mut host, mut child) = pair(ByteCheckpoint::Run);
            child.write_all(&[1, 1, 0, 0, 1, 1, 0, 0]).unwrap();
            assert!(matches!(host.poll(), Err(WorkerError::Protocol(_))));
            assert!(host.take().is_none());
        }

        #[test]
        fn peer_eof_invalidates_queued_progress_before_dispatch() {
            let (mut host, mut child) = pair(ByteCheckpoint::Run);
            child.write_all(&[1, 1, 0, 0]).unwrap();
            host.poll().unwrap();
            drop(child);
            assert!(matches!(host.poll(), Err(WorkerError::Protocol(_))));
            assert!(host.take().is_none());
        }

        #[test]
        fn selected_park_has_no_normal_resume_and_clones_cannot_duplicate_it() {
            for selected in [ByteCheckpoint::Run, ByteCheckpoint::Output] {
                let (mut host, child) = UnixStream::pair().unwrap();
                host.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                child.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                let checkpoint = handle(child, selected);
                let unselected =
                    if selected == ByteCheckpoint::Run { ByteCheckpoint::Output } else { ByteCheckpoint::Run };
                checkpoint.park(unselected).unwrap();
                let clone = checkpoint.clone();
                let parked = std::thread::spawn(move || clone.park(selected));
                let mut frame = [0; 4];
                let received = host.read_exact(&mut frame);
                let duplicate = received.as_ref().ok().map(|_| checkpoint.park(selected));
                let completed = received.as_ref().ok().map(|_| complete(&checkpoint));
                drop(host);
                let outcome = parked.join().unwrap();
                received.unwrap();
                assert_eq!(frame, [1, selected as u8, 0, 0]);
                assert!(matches!(duplicate.unwrap(), Err(WorkerError::Protocol(_))));
                assert!(matches!(completed.unwrap(), Err(WorkerError::Protocol(_))));
                assert!(matches!(outcome, Err(WorkerError::Protocol(_))));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_handle_is_send_sync_static_and_both_checkpoints_are_noops() {
        fn assert_callback_bounds<T: Send + Sync + 'static>() {}
        assert_callback_bounds::<BinaryCheckpoint>();
        let handle = BinaryCheckpoint::disabled();
        assert_eq!(handle.selected(), None);
        handle.park(ByteCheckpoint::Run).unwrap();
        handle.clone().park(ByteCheckpoint::Output).unwrap();
    }
}
