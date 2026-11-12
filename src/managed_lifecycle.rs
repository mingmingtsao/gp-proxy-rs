//! A bounded, credential-free history owned by the managed runtime namespace.
use crate::{control::StopReport, managed_protocol::ManagedIdentity, service::CleanupSummary};
use serde::{Deserialize, Serialize};

/// Issued only by this process's admitted runtime lease. No Deserialize exists:
/// fields being private alone would not prevent serde construction by callers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunStamp {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    runtime: [u64; 3],
    managed: ManagedIdentity,
    instance: [u8; 16],
    ordinal: u64,
}
impl RunStamp {
    pub fn managed(&self) -> ManagedIdentity {
        self.managed
    }
    pub fn instance(&self) -> [u8; 16] {
        self.instance
    }
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }
}

#[derive(Clone, Debug)]
pub enum IncarnationOutcome {
    Active,
    Finished(StopReport),
}
#[derive(Clone, Debug)]
pub struct Incarnation {
    pub stamp: RunStamp,
    pub outcome: IncarnationOutcome,
}
/// Independent saturated totals, never validated as one process's StopReport.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleHistory {
    pub finished_incarnations: u64,
    pub unfinished_incarnations: u64,
    pub unconfirmed_finished_incarnations: u64,
    pub completed: CleanupSummary,
    pub metadata_interrupted: bool,
    pub counter_saturated: bool,
}
impl LifecycleHistory {
    pub fn remote_uncertainty(&self) -> bool {
        self.unfinished_incarnations != 0
            || self.metadata_interrupted
            || self.counter_saturated
            || self.completed.logout_unconfirmed != 0
            || self.completed.remote_outcome_unknown != 0
    }
}
#[derive(Clone, Debug)]
pub struct RuntimeLifecycleView {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    runtime: [u64; 3],
    pub sequence: u64,
    pub installation: [u8; 16],
    pub ordinal_highwater: u64,
    pub current: Option<Incarnation>,
    pub history: LifecycleHistory,
    pub last_unfinished: Option<RunStamp>,
    last_finished: Option<(RunStamp, StopReport)>,
}
impl RuntimeLifecycleView {
    pub fn last_finished(&self) -> Option<&(RunStamp, StopReport)> {
        self.last_finished.as_ref()
    }
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    pub(crate) fn belongs_to_runtime(&self, identity: [u64; 3]) -> bool {
        self.runtime == identity
    }
    /// A disk completion is separate evidence from receipt of an IPC reply.
    /// Never matches by generation alone or substitutes a different instance.
    pub fn finished_for(
        &self,
        managed: &ManagedIdentity,
        instance: &[u8; 16],
    ) -> Option<&StopReport> {
        self.last_finished.as_ref().and_then(|(stamp, report)| {
            (stamp.managed == *managed && stamp.instance == *instance).then_some(report)
        })
    }
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod platform {
    use super::*;
    use crate::owned_snapshot::{OwnedSnapshot, SnapshotGuard, SnapshotKind};
    use std::{io, path::Path};
    pub(crate) const MAX_LIFECYCLE_BYTES: usize = 4096;
    const LOCK_BUDGET: std::time::Duration = std::time::Duration::from_millis(250);
    const LOCK_RECHECK: std::time::Duration = std::time::Duration::from_millis(2);

    fn lock_timeout() -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "managed lifecycle lock wait expired or clock became uncertain",
        )
    }
    /// Only lock acquisition may retry. Once a guard exists, the caller reads
    /// and writes exactly once. Filesystem syscalls remain non-cancellable.
    fn wait_for_lock<T>(
        lease: &crate::lease::Lease,
        mut acquire: impl FnMut() -> io::Result<T>,
        checkpoint: &mut dyn FnMut(&'static str) -> io::Result<()>,
    ) -> io::Result<T> {
        let deadline = lease
            .deadline_after(LOCK_BUDGET)
            .map_err(|_| lock_timeout())?;
        let mut notified = false;
        loop {
            if lease.until(Some(deadline)).map_err(|_| lock_timeout())? {
                return Err(lock_timeout());
            }
            match acquire() {
                Ok(guard) => {
                    if lease.until(Some(deadline)).map_err(|_| lock_timeout())? {
                        return Err(lock_timeout()); // drops even a just-acquired guard
                    }
                    return Ok(guard);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if !notified {
                        notified = true;
                        checkpoint("lifecycle_lock_would_block")?;
                    }
                    let remaining = lease.remaining(deadline).map_err(|_| lock_timeout())?;
                    if remaining.is_zero() {
                        return Err(lock_timeout());
                    }
                    std::thread::sleep(remaining.min(LOCK_RECHECK));
                }
                Err(error) => return Err(error),
            }
        }
    }
    impl LifecycleHistory {
        fn add(target: &mut u64, value: u64, saturated: &mut bool) {
            match target.checked_add(value) {
                Some(next) => *target = next,
                None => {
                    *target = u64::MAX;
                    *saturated = true;
                }
            }
        }
        fn finished(&mut self, report: &StopReport) {
            if report.cleanup.logout_unconfirmed != 0 || report.cleanup.remote_outcome_unknown != 0
            {
                Self::add(
                    &mut self.unconfirmed_finished_incarnations,
                    1,
                    &mut self.counter_saturated,
                );
            }
            Self::add(
                &mut self.finished_incarnations,
                1,
                &mut self.counter_saturated,
            );
            for (target, value) in [
                (
                    &mut self.completed.known_sessions,
                    report.cleanup.known_sessions,
                ),
                (
                    &mut self.completed.logout_confirmed,
                    report.cleanup.logout_confirmed,
                ),
                (
                    &mut self.completed.logout_unconfirmed,
                    report.cleanup.logout_unconfirmed,
                ),
                (
                    &mut self.completed.remote_outcome_unknown,
                    report.cleanup.remote_outcome_unknown,
                ),
            ] {
                Self::add(target, value, &mut self.counter_saturated);
            }
        }
        fn unfinished(&mut self) {
            Self::add(
                &mut self.unfinished_incarnations,
                1,
                &mut self.counter_saturated,
            );
        }
    }
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct StoredStamp {
        managed: ManagedIdentity,
        instance: [u8; 16],
        ordinal: u64,
    }
    impl StoredStamp {
        fn validate(&self, installation: [u8; 16], highwater: u64) -> io::Result<()> {
            self.managed.validate()?;
            if self.managed.installation != installation
                || self.instance == [0; 16]
                || self.ordinal == 0
                || self.ordinal > highwater
            {
                return Err(invalid());
            }
            Ok(())
        }
        fn token(&self, runtime: [u64; 3]) -> RunStamp {
            RunStamp {
                runtime,
                managed: self.managed,
                instance: self.instance,
                ordinal: self.ordinal,
            }
        }
        fn from_token(token: &RunStamp) -> Self {
            Self {
                managed: token.managed,
                instance: token.instance,
                ordinal: token.ordinal,
            }
        }
    }
    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
    enum StoredOutcome {
        Active,
        Finished { report: StopReport },
    }
    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct StoredIncarnation {
        stamp: StoredStamp,
        outcome: StoredOutcome,
    }
    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct StoredFinished {
        stamp: StoredStamp,
        report: StopReport,
    }
    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Data {
        version: u8,
        installation: [u8; 16],
        ordinal_highwater: u64,
        current: Option<StoredIncarnation>,
        history: LifecycleHistory,
        last_unfinished: Option<StoredStamp>,
        last_finished: Option<StoredFinished>,
    }
    fn valid_report(report: &StopReport) -> bool {
        report.local_cleanup_complete && report.valid()
    }
    fn same_report(a: &StopReport, b: &StopReport) -> bool {
        a == b
    }
    fn invalid() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid managed lifecycle history",
        )
    }
    impl Data {
        fn empty(installation: [u8; 16]) -> Self {
            Self {
                version: 1,
                installation,
                ordinal_highwater: 0,
                current: None,
                history: LifecycleHistory::default(),
                last_unfinished: None,
                last_finished: None,
            }
        }
        fn validate(&self, installation: [u8; 16]) -> io::Result<()> {
            if self.version != 1 || installation == [0; 16] || self.installation != installation {
                return Err(invalid());
            }
            if self.history.unconfirmed_finished_incarnations > self.history.finished_incarnations {
                return Err(invalid());
            }
            let mut finished = self
                .history
                .finished_incarnations
                .checked_add(self.history.unfinished_incarnations)
                .ok_or_else(invalid)?;
            if let Some(current) = &self.current {
                current
                    .stamp
                    .validate(installation, self.ordinal_highwater)?;
                if current.stamp.ordinal != self.ordinal_highwater {
                    return Err(invalid());
                }
                match &current.outcome {
                    StoredOutcome::Active => {
                        finished = finished.checked_add(1).ok_or_else(invalid)?
                    }
                    StoredOutcome::Finished { report } => {
                        if !valid_report(report) {
                            return Err(invalid());
                        }
                        if self.last_finished.as_ref().is_none_or(|last| {
                            last.stamp != current.stamp || !same_report(&last.report, report)
                        }) {
                            return Err(invalid());
                        }
                    }
                }
            }
            if finished != self.ordinal_highwater {
                return Err(invalid());
            }
            if let Some(last) = &self.last_unfinished {
                last.validate(installation, self.ordinal_highwater)?;
                if self.history.unfinished_incarnations == 0 {
                    return Err(invalid());
                }
            } else if self.history.unfinished_incarnations != 0 {
                return Err(invalid());
            }
            if let Some(last) = &self.last_finished {
                last.stamp.validate(installation, self.ordinal_highwater)?;
                if self.history.finished_incarnations == 0 || !valid_report(&last.report) {
                    return Err(invalid());
                }
            } else if self.history.finished_incarnations != 0 {
                return Err(invalid());
            }
            Ok(())
        }
        fn encode(&self) -> io::Result<Vec<u8>> {
            self.validate(self.installation)?;
            let mut bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
            bytes.push(b'\n');
            if bytes.len() > MAX_LIFECYCLE_BYTES {
                return Err(invalid());
            }
            Ok(bytes)
        }
        fn decode(bytes: &[u8], installation: [u8; 16]) -> io::Result<Self> {
            if bytes.len() > MAX_LIFECYCLE_BYTES {
                return Err(invalid());
            }
            let data: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
            data.validate(installation)?;
            Ok(data)
        }
        fn view(&self, sequence: u64, runtime: [u64; 3]) -> RuntimeLifecycleView {
            RuntimeLifecycleView {
                runtime,
                sequence,
                installation: self.installation,
                ordinal_highwater: self.ordinal_highwater,
                current: self.current.as_ref().map(|current| Incarnation {
                    stamp: current.stamp.token(runtime),
                    outcome: match &current.outcome {
                        StoredOutcome::Active => IncarnationOutcome::Active,
                        StoredOutcome::Finished { report } => {
                            IncarnationOutcome::Finished(report.clone())
                        }
                    },
                }),
                history: self.history.clone(),
                last_unfinished: self
                    .last_unfinished
                    .as_ref()
                    .map(|value| value.token(runtime)),
                last_finished: self
                    .last_finished
                    .as_ref()
                    .map(|value| (value.stamp.token(runtime), value.report.clone())),
            }
        }
        fn retire_active(&mut self) {
            if self
                .current
                .as_ref()
                .is_some_and(|value| matches!(value.outcome, StoredOutcome::Active))
            {
                let current = self.current.take().expect("active incarnation was checked");
                self.history.unfinished();
                self.last_unfinished = Some(current.stamp);
            }
        }
    }

    pub(crate) struct Journal {
        snapshot: OwnedSnapshot,
        installation: [u8; 16],
        runtime: [u64; 3],
    }
    impl Journal {
        pub(crate) fn initialize(path: &Path, installation: [u8; 16]) -> io::Result<()> {
            OwnedSnapshot::initialize(
                path,
                installation,
                SnapshotKind::RuntimeLifecycle,
                MAX_LIFECYCLE_BYTES,
                &Data::empty(installation).encode()?,
            )?;
            Ok(())
        }
        /// Caller validates this path's directory inode against its runtime Owner.
        pub(crate) fn open(
            path: &Path,
            installation: [u8; 16],
            runtime: [u64; 3],
        ) -> io::Result<Self> {
            Ok(Self {
                snapshot: OwnedSnapshot::open(
                    path,
                    installation,
                    SnapshotKind::RuntimeLifecycle,
                    MAX_LIFECYCLE_BYTES,
                )?,
                installation,
                runtime,
            })
        }
        pub(crate) fn read(&self) -> io::Result<RuntimeLifecycleView> {
            let guard = self.snapshot.lock()?;
            let value = guard.read()?;
            Ok(Data::decode(&value.payload, self.installation)?.view(value.sequence, self.runtime))
        }
        fn daemon_lock(
            &self,
            checkpoint: &mut dyn FnMut(&'static str) -> io::Result<()>,
        ) -> io::Result<SnapshotGuard<'_>> {
            wait_for_lock(
                &crate::lease::Lease::new(),
                || self.snapshot.lock(),
                checkpoint,
            )
        }
        /// Runtime admission tolerates a concurrent short inspection. Manager
        /// diagnostic read() deliberately retains its nonblocking contract.
        pub(crate) fn read_for_admission(&self) -> io::Result<RuntimeLifecycleView> {
            self.read_for_admission_with(&mut |_| Ok(()))
        }
        fn read_for_admission_with(
            &self,
            checkpoint: &mut dyn FnMut(&'static str) -> io::Result<()>,
        ) -> io::Result<RuntimeLifecycleView> {
            let guard = self.daemon_lock(checkpoint)?;
            let value = guard.read()?;
            Ok(Data::decode(&value.payload, self.installation)?.view(value.sequence, self.runtime))
        }

        /// The RuntimeLease wrapper enforces once-per-process admission. This lower
        /// layer requires the caller to hold the namespace's permanent runtime lock.
        pub(crate) fn begin(
            &self,
            managed: ManagedIdentity,
            instance: [u8; 16],
        ) -> io::Result<RunStamp> {
            self.begin_with(managed, instance, &mut |_| Ok(()))
        }
        fn begin_with(
            &self,
            managed: ManagedIdentity,
            instance: [u8; 16],
            checkpoint: &mut dyn FnMut(&'static str) -> io::Result<()>,
        ) -> io::Result<RunStamp> {
            managed.validate()?;
            if managed.installation != self.installation || instance == [0; 16] {
                return Err(invalid());
            }
            let mut guard = self.daemon_lock(checkpoint)?;
            let before = guard.read()?;
            let mut data = Data::decode(&before.payload, self.installation)?;
            let ordinal = data.ordinal_highwater.checked_add(1).ok_or_else(invalid)?;
            data.retire_active();
            let stamp = StoredStamp {
                managed,
                instance,
                ordinal,
            };
            data.ordinal_highwater = ordinal;
            data.current = Some(StoredIncarnation {
                stamp: stamp.clone(),
                outcome: StoredOutcome::Active,
            });
            guard.write(before.sequence, &data.encode()?)?;
            Ok(stamp.token(self.runtime))
        }
        pub(crate) fn finish(&self, stamp: &RunStamp, report: &StopReport) -> io::Result<()> {
            self.finish_with(stamp, report, &mut |_| Ok(()))
        }
        #[cfg(test)]
        pub(crate) fn finish_checkpoint(
            &self,
            stamp: &RunStamp,
            report: &StopReport,
            checkpoint: &mut dyn FnMut(&'static str) -> io::Result<()>,
        ) -> io::Result<()> {
            self.finish_with(stamp, report, checkpoint)
        }
        fn finish_with(
            &self,
            stamp: &RunStamp,
            report: &StopReport,
            checkpoint: &mut dyn FnMut(&'static str) -> io::Result<()>,
        ) -> io::Result<()> {
            if stamp.runtime != self.runtime || !valid_report(report) {
                return Err(invalid());
            }
            let mut guard = self.daemon_lock(checkpoint)?;
            let before = guard.read()?;
            let mut data = Data::decode(&before.payload, self.installation)?;
            let current = data.current.as_mut().ok_or_else(invalid)?;
            if current.stamp != StoredStamp::from_token(stamp) {
                return Err(invalid());
            }
            if let StoredOutcome::Finished { report: old } = &current.outcome {
                return if same_report(old, report) {
                    Ok(())
                } else {
                    Err(invalid())
                };
            }
            current.outcome = StoredOutcome::Finished {
                report: report.clone(),
            };
            data.last_finished = Some(StoredFinished {
                stamp: current.stamp.clone(),
                report: report.clone(),
            });
            data.history.finished(report);
            guard.write_with(before.sequence, &data.encode()?, checkpoint)?;
            Ok(())
        }
        /// The wrapper first verifies a matching RetiredRuntime and disabled gate.
        pub(crate) fn retire(&self, expected: &RunStamp) -> io::Result<RuntimeLifecycleView> {
            if expected.runtime != self.runtime {
                return Err(invalid());
            }
            let mut guard = self.snapshot.lock()?;
            let before = guard.read()?;
            let mut data = Data::decode(&before.payload, self.installation)?;
            if data
                .current
                .as_ref()
                .is_none_or(|value| value.stamp != StoredStamp::from_token(expected))
            {
                if data.current.is_none()
                    && data.last_unfinished.as_ref() == Some(&StoredStamp::from_token(expected))
                {
                    return Ok(data.view(before.sequence, self.runtime));
                }
                return Err(invalid());
            }
            if data
                .current
                .as_ref()
                .is_some_and(|value| matches!(value.outcome, StoredOutcome::Finished { .. }))
            {
                return Ok(data.view(before.sequence, self.runtime));
            }
            data.retire_active();
            let after = guard.write(before.sequence, &data.encode()?)?;
            Ok(data.view(after.sequence, self.runtime))
        }
        /// Explicit conservative recovery only. Never used by normal admission.
        /// The caller must own RetiredRuntime for this namespace and close Gate.
        pub(crate) fn repair(&self) -> io::Result<RuntimeLifecycleView> {
            let mut guard = self.snapshot.lock()?;
            if let Ok(value) = guard.read() {
                return Ok(Data::decode(&value.payload, self.installation)?
                    .view(value.sequence, self.runtime));
            }
            let observed = guard.inspect()?;
            let value = observed.highest_complete().ok_or_else(invalid)?;
            let mut data = Data::decode(&value.payload, self.installation)?;
            data.history.metadata_interrupted = true;
            data.retire_active();
            let after = guard.repair(&observed, &data.encode()?)?;
            Ok(data.view(after.sequence, self.runtime))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        struct LockFixture(std::path::PathBuf);
        impl LockFixture {
            fn new() -> Self {
                use std::os::unix::fs::DirBuilderExt;
                let root = std::path::PathBuf::from(format!(
                    "/tmp/gp-lifecycle-lock-{:016x}",
                    rand::random::<u64>()
                ));
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&root)
                    .unwrap();
                Journal::initialize(&root.join("journal"), [1; 16]).unwrap();
                Self(root)
            }
            fn journal(&self) -> Journal {
                Journal::open(&self.0.join("journal"), [1; 16], [7, 8, 9]).unwrap()
            }
            fn managed() -> ManagedIdentity {
                ManagedIdentity {
                    installation: [1; 16],
                    generation: 1,
                    release: [2; 32],
                }
            }
        }
        impl Drop for LockFixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        #[test]
        fn admission_and_begin_wait_for_confirmed_contention_but_manager_read_stays_nonblocking() {
            use std::{sync::mpsc, thread, time::Duration};
            for begin in [false, true] {
                let fixture = LockFixture::new();
                let journal = fixture.journal();
                let reader = journal.snapshot.lock().unwrap();
                let before = reader.read().unwrap();
                assert_eq!(
                    journal.read().unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                let other = fixture.journal();
                let (hit_tx, hit_rx) = mpsc::channel();
                let (release_tx, release_rx) = mpsc::channel();
                let (done_tx, done_rx) = mpsc::channel();
                let worker = thread::spawn(move || {
                    let mut notify = |at| {
                        if at == "lifecycle_lock_would_block" {
                            hit_tx.send(()).map_err(|_| io::ErrorKind::BrokenPipe)?;
                            release_rx
                                .recv_timeout(Duration::from_secs(2))
                                .map_err(|_| io::ErrorKind::TimedOut)?;
                        }
                        Ok(())
                    };
                    let result = if begin {
                        other
                            .begin_with(LockFixture::managed(), [4; 16], &mut notify)
                            .map(|stamp| stamp.ordinal())
                    } else {
                        other
                            .read_for_admission_with(&mut notify)
                            .map(|view| view.sequence)
                    };
                    let _ = done_tx.send(result);
                });
                let hit = hit_rx.recv_timeout(Duration::from_secs(2));
                drop(reader);
                let released = release_tx.send(());
                let result = done_rx.recv_timeout(Duration::from_secs(2));
                let joined = worker.join();
                assert!(hit.is_ok() && released.is_ok() && joined.is_ok());
                let value = result.unwrap().unwrap();
                let after = journal.read().unwrap();
                assert_eq!(after.sequence, before.sequence + u64::from(begin));
                assert_eq!(after.history.finished_incarnations, 0);
                assert_eq!(after.history.unfinished_incarnations, 0);
                if begin {
                    assert_eq!(value, 1);
                    assert_eq!(after.ordinal_highwater, 1);
                } else {
                    assert_eq!(value, before.sequence);
                    assert_eq!(after.ordinal_highwater, 0);
                }
            }
        }
        #[test]
        fn lock_wait_deadline_and_clock_regression_never_grant_a_late_operation() {
            use crate::lease::TestClock;
            use std::{cell::Cell, time::Duration};
            for mode in 0..3 {
                let fixture = LockFixture::new();
                let journal = fixture.journal();
                let reader = journal.snapshot.lock().unwrap();
                let before = reader.read().unwrap();
                let clock = TestClock::new();
                let lease = clock.lease(None);
                let attempts = Cell::new(0);
                let observed = Cell::new(0);
                let result = wait_for_lock(
                    &lease,
                    || {
                        attempts.set(attempts.get() + 1);
                        journal.snapshot.lock()
                    },
                    &mut |at| {
                        assert_eq!(at, "lifecycle_lock_would_block");
                        observed.set(observed.get() + 1);
                        match mode {
                            0 => clock
                                .advance(Duration::ZERO, LOCK_BUDGET + Duration::from_millis(1)),
                            1 => clock
                                .advance(LOCK_BUDGET + Duration::from_millis(1), Duration::ZERO),
                            _ => clock.rollback(Duration::from_millis(1)),
                        }
                        Ok(())
                    },
                );
                let kind = result.err().unwrap().kind();
                drop(reader);
                assert_eq!(kind, io::ErrorKind::TimedOut);
                assert_eq!(attempts.get(), 1);
                assert_eq!(observed.get(), 1);
                assert_eq!(journal.snapshot.lock().unwrap().read().unwrap(), before);
            }
        }
        #[test]
        fn a_guard_acquired_after_the_deadline_is_dropped_without_a_write() {
            use crate::lease::TestClock;
            use std::time::Duration;
            for regression in [false, true] {
                let fixture = LockFixture::new();
                let journal = fixture.journal();
                let before = journal.snapshot.lock().unwrap().read().unwrap();
                let clock = TestClock::new();
                let lease = clock.lease(None);
                let result = wait_for_lock(
                    &lease,
                    || {
                        let guard = journal.snapshot.lock()?;
                        if regression {
                            clock.rollback(Duration::from_millis(1));
                        } else {
                            clock.advance(Duration::ZERO, LOCK_BUDGET + Duration::from_millis(1));
                        }
                        Ok(guard)
                    },
                    &mut |_| panic!("uncontended acquisition must not notify contention"),
                );
                assert_eq!(result.err().unwrap().kind(), io::ErrorKind::TimedOut);
                // A new exclusive guard proves the rejected guard was dropped.
                assert_eq!(journal.snapshot.lock().unwrap().read().unwrap(), before);
            }
        }
        #[test]
        fn non_contention_errors_and_partial_write_are_not_retried() {
            use std::cell::Cell;
            let attempts = Cell::new(0);
            let result = wait_for_lock::<()>(
                &crate::lease::Lease::new(),
                || {
                    attempts.set(attempts.get() + 1);
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "synthetic denial",
                    ))
                },
                &mut |_| panic!("only WouldBlock may retry"),
            );
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(attempts.get(), 1);
            let fixture = LockFixture::new();
            let journal = fixture.journal();
            let stamp = journal.begin(LockFixture::managed(), [5; 16]).unwrap();
            let report = StopReport {
                local_cleanup_complete: true,
                cleanup: CleanupSummary {
                    known_sessions: 1,
                    logout_confirmed: 1,
                    logout_unconfirmed: 0,
                    remote_outcome_unknown: 0,
                },
            };
            let writes = Cell::new(0);
            let error = journal
                .finish_checkpoint(&stamp, &report, &mut |at| {
                    if at == "slot_partial_payload" {
                        writes.set(writes.get() + 1);
                        return Err(io::Error::other("synthetic incomplete write"));
                    }
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert_eq!(writes.get(), 1);
            assert_eq!(
                journal.read().unwrap_err().kind(),
                io::ErrorKind::Interrupted
            );
            let guard = journal.snapshot.lock().unwrap();
            let view = guard.inspect().unwrap();
            let complete = view.highest_complete().unwrap();
            let data = Data::decode(&complete.payload, [1; 16]).unwrap();
            assert!(matches!(
                data.current.unwrap().outcome,
                StoredOutcome::Active
            ));
            assert_eq!(data.history.finished_incarnations, 0);
        }
        #[test]
        fn finish_waits_for_inspection_lock_then_commits_once() {
            use std::{os::unix::fs::DirBuilderExt, sync::mpsc, thread, time::Duration};
            struct Temporary(std::path::PathBuf);
            impl Drop for Temporary {
                fn drop(&mut self) {
                    let _ = std::fs::remove_dir_all(&self.0);
                }
            }
            let parent = Temporary(std::path::PathBuf::from(format!(
                "/tmp/gp-lifecycle-contention-{:016x}",
                rand::random::<u64>()
            )));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&parent.0)
                .unwrap();
            let path = parent.0.join("journal");
            let managed = ManagedIdentity {
                installation: [1; 16],
                generation: 1,
                release: [2; 32],
            };
            Journal::initialize(&path, managed.installation).unwrap();
            let journal = Journal::open(&path, managed.installation, [7, 8, 9]).unwrap();
            let stamp = journal.begin(managed, [3; 16]).unwrap();
            // This is the exact production lock/dual-frame read used by
            // Journal::read. Hold it until the writer confirms WouldBlock.
            let reader = journal.snapshot.lock().unwrap();
            let before = reader.read().unwrap();
            let other = Journal::open(&path, managed.installation, [7, 8, 9]).unwrap();
            let (contended_tx, contended_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let (result_tx, result_rx) = mpsc::channel();
            let report = StopReport {
                local_cleanup_complete: true,
                cleanup: CleanupSummary {
                    known_sessions: 1,
                    logout_confirmed: 1,
                    logout_unconfirmed: 0,
                    remote_outcome_unknown: 0,
                },
            };
            let expected = report.clone();
            let worker = thread::spawn(move || {
                let result = other.finish_checkpoint(&stamp, &report, &mut |at| {
                    if at == "lifecycle_lock_would_block" {
                        contended_tx
                            .send(())
                            .map_err(|_| io::ErrorKind::BrokenPipe)?;
                        resume_rx
                            .recv_timeout(Duration::from_secs(2))
                            .map_err(|_| io::ErrorKind::TimedOut)?;
                    }
                    Ok(())
                });
                let _ = result_tx.send(result);
            });
            let contention = contended_rx.recv_timeout(Duration::from_secs(2));
            // Release and join before any assertion, including the old-code
            // red assertion; no failed test leaves a deliberately held lock.
            drop(reader);
            let released = resume_tx.send(());
            let result = result_rx.recv_timeout(Duration::from_secs(2));
            let joined = worker.join();
            assert!(contention.is_ok(), "writer never confirmed lock contention");
            assert!(released.is_ok());
            assert!(joined.is_ok());
            result
                .unwrap()
                .expect("short read-only inspection must not make a completed cleanup unknown");
            let after = journal.read().unwrap();
            assert_eq!(after.sequence, before.sequence + 1);
            assert_eq!(after.history.finished_incarnations, 1);
            assert_eq!(after.history.unfinished_incarnations, 0);
            assert_eq!(after.history.completed.logout_confirmed, 1);
            assert_eq!(after.finished_for(&managed, &[3; 16]), Some(&expected));
        }

        #[test]
        fn aggregate_saturation_is_sticky_and_never_treated_as_one_stop_report() {
            let mut history = LifecycleHistory {
                completed: CleanupSummary {
                    known_sessions: u64::MAX,
                    logout_confirmed: u64::MAX,
                    logout_unconfirmed: 0,
                    remote_outcome_unknown: 0,
                },
                ..LifecycleHistory::default()
            };
            let report = StopReport {
                local_cleanup_complete: true,
                cleanup: CleanupSummary {
                    known_sessions: 1,
                    logout_confirmed: 0,
                    logout_unconfirmed: 1,
                    remote_outcome_unknown: 3,
                },
            };
            assert!(valid_report(&report));
            history.finished(&report);
            assert_eq!(history.finished_incarnations, 1);
            assert_eq!(history.unconfirmed_finished_incarnations, 1);
            assert_eq!(history.completed.known_sessions, u64::MAX);
            assert_eq!(history.completed.logout_confirmed, u64::MAX);
            assert_eq!(history.completed.logout_unconfirmed, 1);
            assert!(history.counter_saturated && history.remote_uncertainty());
            // Independent totals cannot satisfy a per-process checked sum.
            assert!(!valid_report(&StopReport {
                local_cleanup_complete: true,
                cleanup: history.completed
            }));
        }
        #[test]
        fn malformed_durable_identity_and_outcome_never_create_a_clean_history() {
            let valid = Data::empty([1; 16]).encode().unwrap();
            for key in ["version", "installation", "ordinal_highwater", "current"] {
                let mut value: serde_json::Value = serde_json::from_slice(&valid).unwrap();
                value[key] = serde_json::json!("malformed");
                assert!(Data::decode(&serde_json::to_vec(&value).unwrap(), [1; 16]).is_err());
            }
            let mut value: serde_json::Value = serde_json::from_slice(&valid).unwrap();
            value["foreign"] = true.into();
            assert!(Data::decode(&serde_json::to_vec(&value).unwrap(), [1; 16]).is_err());
            assert!(Data::decode(&valid, [2; 16]).is_err());
            assert!(Data::decode(&vec![b' '; MAX_LIFECYCLE_BYTES + 1], [1; 16]).is_err());
            let duplicate = b"{\"version\":1,\"version\":1}";
            assert!(Data::decode(duplicate, [1; 16]).is_err());
        }
        #[test]
        fn ordinal_exhaustion_does_not_wrap_or_forget_previous_fact() {
            let mut data = Data::empty([1; 16]);
            data.ordinal_highwater = u64::MAX;
            data.history.unfinished_incarnations = u64::MAX;
            data.last_unfinished = Some(StoredStamp {
                managed: ManagedIdentity {
                    installation: [1; 16],
                    generation: 1,
                    release: [2; 32],
                },
                instance: [3; 16],
                ordinal: u64::MAX,
            });
            assert!(data.validate([1; 16]).is_ok());
            // Exercise the real bounded filesystem transaction, not merely
            // checked_add: refusal must leave both committed slots unchanged.
            use std::os::unix::fs::DirBuilderExt;
            struct Temporary(std::path::PathBuf);
            impl Drop for Temporary {
                fn drop(&mut self) {
                    let _ = std::fs::remove_dir_all(&self.0);
                }
            }
            let parent = Temporary(std::path::PathBuf::from(format!(
                "/tmp/gp-lifecycle-overflow-{:016x}",
                rand::random::<u64>()
            )));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&parent.0)
                .unwrap();
            let path = parent.0.join("journal");
            OwnedSnapshot::initialize(
                &path,
                [1; 16],
                SnapshotKind::RuntimeLifecycle,
                MAX_LIFECYCLE_BYTES,
                &data.encode().unwrap(),
            )
            .unwrap();
            let journal = Journal::open(&path, [1; 16], [1, 2, 3]).unwrap();
            let before = journal.snapshot.lock().unwrap().read().unwrap();
            let result = journal.begin(
                ManagedIdentity {
                    installation: [1; 16],
                    generation: 1,
                    release: [2; 32],
                },
                [4; 16],
            );
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert_eq!(journal.snapshot.lock().unwrap().read().unwrap(), before);
            assert!(journal.read().unwrap().history.remote_uncertainty());
        }
    }
}
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
pub(crate) use platform::Journal;
