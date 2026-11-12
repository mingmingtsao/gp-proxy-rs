//! Explicit user-level deployment operations. Ordinary proxy startup never calls this module.
use crate::managed_runtime::Gate;
#[cfg(target_os = "macos")]
use crate::{config::Config, managed_protocol::ManagedIdentity, managed_release};
use serde::Serialize;
#[cfg(target_os = "macos")]
use std::path::Component;
use std::{
    io,
    path::{Path, PathBuf},
};

/// Typed integration point for an embedding service manager. The command-line
/// application always uses the fixed native launchctl adapter. A successful
/// backend command never substitutes for the managed IPC and runtime proofs.
pub mod backend {
    pub use crate::launchd::{Action, Executor};
    pub use crate::managed_child::{Outcome, UnknownReason};
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManageAction {
    Start,
    Stop,
    Upgrade,
    Uninstall,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CleanupProvenance {
    Ipc,
    RuntimeTerminal { ordinal: u64, sequence: u64 },
}

#[derive(Debug, Serialize)]
pub struct DeploymentReport {
    pub schema: u8,
    pub installation: String,
    pub installed: bool,
    pub release: Option<String>,
    pub generation: u64,
    pub admission_open: bool,
    pub pending_operation: Option<String>,
    pub pending_phase: Option<String>,
    pub pending_outcome: Option<String>,
    pub cleanup_unconfirmed_episodes: u64,
    pub logout_unconfirmed: u64,
    pub remote_outcome_unknown: bool,
    /// Runtime journal totals are counted once, independently of manager receipts.
    pub runtime_finished_incarnations: u64,
    pub runtime_unfinished_incarnations: u64,
    pub cleanup_totals: crate::service::CleanupSummary,
    pub lifecycle_metadata_interrupted: bool,
    pub lifecycle_counter_saturated: bool,
    /// A read-only observation of Active after taking the vacant runtime lock.
    /// It is not added to the durable history until explicit recovery.
    pub current_incarnation_unfinished: bool,
    pub maintenance_unconfirmed_episodes: u64,
    pub maintenance_outcome_unknown: bool,
    pub maintenance_metadata_interrupted: bool,
    pub retired_jobs: usize,
    /// Diagnostic only: backend success is neither readiness nor exit proof.
    pub backend_observation: Option<String>,
    pub matched_instance: Option<String>,
    /// The exact old instance's report, when this operation stopped one. Remote
    /// uncertainty remains visible even if local replacement was safe.
    pub cleanup: Option<crate::control::StopReport>,
    /// A durable runtime terminal record is not an observed IPC response.
    pub cleanup_evidence_source: Option<CleanupProvenance>,
}

pub async fn install(plan: Plan, start: bool) -> io::Result<DeploymentReport> {
    install_with_backend(plan, start, &crate::launchd::Native).await
}

pub async fn change(root: &Path, action: ManageAction) -> io::Result<DeploymentReport> {
    let source = (action == ManageAction::Upgrade)
        .then(std::env::current_exe)
        .transpose()?;
    change_with_backend(root, action, source.as_deref(), &crate::launchd::Native).await
}

/// An optional caller-held expectation for refusing a stale recovery plan.
#[derive(Clone, Debug, Serialize)]
pub struct RecoveryExpectation {
    pub installation: [u8; 16],
    pub revision: [u8; 32],
}

pub async fn recover(root: &Path) -> io::Result<DeploymentReport> {
    recover_with_backend(root, None, &crate::launchd::Native).await
}

pub async fn inspect(root: &Path) -> io::Result<DeploymentReport> {
    inspect_with_backend(root, &crate::launchd::Native).await
}

#[cfg(target_os = "macos")]
pub use coordinator::{
    change_with_backend, inspect_with_backend, install_with_backend, recover_with_backend,
    recovery_plan,
};

#[cfg(not(target_os = "macos"))]
pub async fn install_with_backend(
    _plan: Plan,
    _start: bool,
    _backend: &impl backend::Executor,
) -> io::Result<DeploymentReport> {
    Err(unsupported())
}
#[cfg(not(target_os = "macos"))]
pub async fn change_with_backend(
    _root: &Path,
    _action: ManageAction,
    _source: Option<&Path>,
    _backend: &impl backend::Executor,
) -> io::Result<DeploymentReport> {
    Err(unsupported())
}
#[cfg(not(target_os = "macos"))]
pub async fn inspect_with_backend(
    _root: &Path,
    _backend: &impl backend::Executor,
) -> io::Result<DeploymentReport> {
    Err(unsupported())
}

#[cfg(not(target_os = "macos"))]
pub fn recovery_plan(_root: &Path) -> io::Result<RecoveryExpectation> {
    Err(unsupported())
}
#[cfg(not(target_os = "macos"))]
pub async fn recover_with_backend(
    _root: &Path,
    _expected: Option<&RecoveryExpectation>,
    _backend: &impl backend::Executor,
) -> io::Result<DeploymentReport> {
    Err(unsupported())
}

#[derive(Clone, Debug, Serialize)]
pub struct Plan {
    pub schema: u8,
    pub uid: u32,
    pub state_directory: PathBuf,
    pub launch_agents_directory: PathBuf,
    pub source_binary: PathBuf,
    pub release_bytes: u64,
    pub gate: Gate,
    pub label: String,
    pub plist: PathBuf,
}

#[cfg(target_os = "macos")]
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid user service deployment paths or state",
    )
}
#[cfg(not(target_os = "macos"))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "user service deployment currently requires macOS",
    )
}

pub fn default_state_directory() -> io::Result<PathBuf> {
    Ok(user_home()?.join("Library/Application Support/gp-proxy"))
}

fn user_home() -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = rustix::process::geteuid().as_raw();
        if uid == 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let selected = std::env::var_os("HOME").ok_or_else(invalid)?;
        let path = std::fs::canonicalize(selected)
            .map_err(|error| io::Error::new(error.kind(), "cannot resolve user home"))?;
        let meta = std::fs::symlink_metadata(&path)?;
        if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o022 != 0 {
            return Err(invalid());
        }
        Ok(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(unsupported())
    }
}

/// Resolve the selected parent, preserving a config symlink's own directory for
/// relative CA and PAC references. No directory is created by a plan.
#[cfg(target_os = "macos")]
fn selected_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let Some(Component::Normal(name)) = absolute.components().next_back() else {
        return Err(invalid());
    };
    let parent =
        std::fs::canonicalize(absolute.parent().ok_or_else(invalid)?).map_err(|error| {
            io::Error::new(error.kind(), "cannot resolve selected deployment parent")
        })?;
    let selected = parent.join(name);
    if selected
        .to_str()
        .is_none_or(|value| value.len() > 1024 || value.chars().any(char::is_control))
    {
        return Err(invalid());
    }
    Ok(selected)
}

pub fn plan(state_directory: Option<&Path>, configuration: &Path) -> io::Result<Plan> {
    let home = user_home()?;
    #[cfg(target_os = "macos")]
    {
        let source = std::env::current_exe()?;
        plan_with(
            state_directory.unwrap_or(&home.join("Library/Application Support/gp-proxy")),
            configuration,
            &source,
            &home,
            rustix::process::geteuid().as_raw(),
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (state_directory, configuration, home);
        Err(unsupported())
    }
}

#[cfg(target_os = "macos")]
fn plan_with(
    state: &Path,
    configuration: &Path,
    source: &Path,
    home: &Path,
    uid: u32,
) -> io::Result<Plan> {
    if uid == 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let state_directory = selected_path(state)?;
    let config = selected_path(configuration)?;
    let source_binary = selected_path(source)?;
    let settings = Config::read(&config)?;
    crate::tls::client_config(settings.ca_file.as_deref())?;
    if settings.portal.is_some() {
        crate::tls::client_config(settings.portal_ca_file.as_deref())?;
    }
    crate::policy::Policy::new(settings.domains.clone(), settings.networks.clone())?;
    crate::pac_history::PacHistory::read(
        settings.pac_history_file.as_deref().ok_or_else(invalid)?,
    )?;
    let source = managed_release::Source::open(&source_binary)?;
    let mut installation = [0; 16];
    getrandom::fill(&mut installation)
        .map_err(|_| io::Error::other("cannot create installation identity"))?;
    let identity = ManagedIdentity {
        installation,
        generation: 1,
        release: source.digest(),
    };
    let gate = Gate {
        version: 2,
        identity,
        enabled: false,
        binary: state_directory
            .join("versions")
            .join(managed_release::hexadecimal(&identity.release))
            .join("gp-proxy"),
        config,
        control: state_directory.join("data/control"),
        logs: state_directory.join("data/logs"),
    };
    gate.validate()?;
    let label = crate::launchd::label_for(&identity)?;
    let launch_agents_directory = home.join("Library/LaunchAgents");
    let plist = launch_agents_directory.join(format!("{label}.plist"));
    if plist
        .to_str()
        .is_none_or(|value| value.len() > 1024 || value.chars().any(char::is_control))
    {
        return Err(invalid());
    }
    Ok(Plan {
        schema: 2,
        uid,
        state_directory,
        launch_agents_directory,
        source_binary,
        release_bytes: source.len(),
        gate,
        label,
        plist,
    })
}

#[cfg(target_os = "macos")]
mod coordinator {
    use super::{backend::*, *};
    use crate::{
        control,
        deployment_store::{
            CleanupEvidenceSource, CleanupTarget, Operation, Phase, Record, RetiredJob,
            StopEvidence, Store, UnknownCleanup, UnknownReason,
        },
        lease::Lease,
        managed_runtime::{
            self, IncarnationOutcome, Maintenance, RetiredRuntime, RuntimeLifecycleView,
        },
    };
    use std::{future::Future, os::unix::fs::DirBuilderExt, time::Duration};

    fn uid() -> io::Result<u32> {
        let uid = rustix::process::geteuid().as_raw();
        if uid == 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(uid)
    }

    fn pending() -> io::Error {
        io::Error::other(
            "deployment has an unfinished transaction; inspect retained state before recovery",
        )
    }

    fn validate_plan(plan: &Plan) -> io::Result<managed_release::Source> {
        plan.gate.validate()?;
        let id = plan.gate.identity;
        let label = crate::launchd::label_for(&id)?;
        if plan.schema != 2
            || plan.uid != uid()?
            || plan.state_directory != selected_path(&plan.state_directory)?
            || plan.source_binary != selected_path(&plan.source_binary)?
            || plan.gate.config != selected_path(&plan.gate.config)?
            || plan.launch_agents_directory != selected_path(&plan.launch_agents_directory)?
            || plan.label != label
            || plan.plist != plan.launch_agents_directory.join(format!("{label}.plist"))
            || plan.gate.enabled
            || id.generation != 1
            || plan.gate.binary
                != plan
                    .state_directory
                    .join("versions")
                    .join(managed_release::hexadecimal(&id.release))
                    .join("gp-proxy")
            || plan.gate.control != plan.state_directory.join("data/control")
            || plan.gate.logs != plan.state_directory.join("data/logs")
        {
            return Err(invalid());
        }
        let source = managed_release::Source::open(&plan.source_binary)?;
        if source.digest() != id.release || source.len() != plan.release_bytes {
            return Err(invalid());
        }
        Ok(source)
    }

    fn report(
        store: &Store,
        gate: &Gate,
        maintenance: &Maintenance,
    ) -> io::Result<DeploymentReport> {
        let mut lifecycle = maintenance.lifecycle()?;
        let mut current_unfinished = false;
        if lifecycle
            .current
            .as_ref()
            .is_some_and(|current| matches!(current.outcome, IncarnationOutcome::Active))
        {
            match maintenance.try_runtime() {
                Ok(retired) => {
                    // Re-read under retirement: a process could have finished
                    // between the first read and release of its runtime lock.
                    lifecycle = maintenance.lifecycle()?;
                    current_unfinished = lifecycle.current.as_ref().is_some_and(|current| {
                        matches!(current.outcome, IncarnationOutcome::Active)
                    });
                    drop(retired);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        let history = &lifecycle.history;
        let unfinished = history
            .unfinished_incarnations
            .saturating_add(u64::from(current_unfinished));
        Ok(DeploymentReport {
            schema: 3,
            installation: managed_release::hexadecimal(&gate.identity.installation),
            installed: store.record().current.is_some(),
            release: store
                .record()
                .current
                .as_ref()
                .map(|r| managed_release::hexadecimal(&r.digest())),
            generation: gate.identity.generation,
            admission_open: gate.enabled,
            pending_operation: store.pending().map(|tx| format!("{:?}", tx.operation)),
            pending_phase: store.pending().map(|tx| format!("{:?}", tx.phase)),
            pending_outcome: store
                .pending()
                .and_then(|tx| tx.outcome.as_ref())
                .map(|value| format!("{:?}", value.reason)),
            cleanup_unconfirmed_episodes: unfinished
                .saturating_add(history.unconfirmed_finished_incarnations),
            logout_unconfirmed: history.completed.logout_unconfirmed,
            remote_outcome_unknown: history.remote_uncertainty()
                || current_unfinished
                || store.ledger().remote_outcome_unknown,
            runtime_finished_incarnations: history.finished_incarnations,
            runtime_unfinished_incarnations: unfinished,
            cleanup_totals: history.completed,
            lifecycle_metadata_interrupted: history.metadata_interrupted,
            lifecycle_counter_saturated: history.counter_saturated,
            current_incarnation_unfinished: current_unfinished,
            maintenance_unconfirmed_episodes: store.ledger().unconfirmed_episodes,
            maintenance_outcome_unknown: store.ledger().remote_outcome_unknown,
            maintenance_metadata_interrupted: store.ledger().metadata_interrupted,
            retired_jobs: store.ledger().retired_jobs.len(),
            backend_observation: None,
            matched_instance: None,
            cleanup: None,
            cleanup_evidence_source: None,
        })
    }

    fn attach_cleanup(result: &mut DeploymentReport, proof: Option<&StopEvidence>) {
        if let Some(proof) = proof {
            result.cleanup = Some(proof.report.clone());
            result.cleanup_evidence_source = Some(match &proof.source {
                CleanupEvidenceSource::Ipc => CleanupProvenance::Ipc,
                CleanupEvidenceSource::RuntimeTerminal { ordinal, sequence } => {
                    CleanupProvenance::RuntimeTerminal {
                        ordinal: *ordinal,
                        sequence: *sequence,
                    }
                }
            });
        }
    }

    fn record_finished(
        store: &mut Store,
        view: &RuntimeLifecycleView,
        target: CleanupTarget,
        managed: ManagedIdentity,
        instance: [u8; 16],
    ) -> io::Result<bool> {
        if view.finished_for(&managed, &instance).is_none() {
            return Ok(false);
        }
        store.record_durable_cleanup(target, view, managed, instance)?;
        Ok(true)
    }

    /// Admission is already closed, and the runtime lease is held. Only an
    /// explicit recover may repair an interrupted journal. All snapshot guards
    /// are internal to these synchronous calls and released before any await.
    fn settle_lifecycle(
        maintenance: &Maintenance,
        retired: &RetiredRuntime,
        repair: bool,
    ) -> io::Result<RuntimeLifecycleView> {
        let view = match maintenance.lifecycle() {
            Ok(view) => view,
            Err(error) if repair && error.kind() == io::ErrorKind::Interrupted => {
                maintenance.repair_lifecycle_closed(retired)?
            }
            Err(error) => return Err(error),
        };
        if let Some(current) = view.current.as_ref() {
            if matches!(current.outcome, IncarnationOutcome::Active) {
                return maintenance.retire_unfinished(retired, &current.stamp);
            }
        }
        Ok(view)
    }

    /// Dirty lifecycle metadata must not prevent closing admission or stopping
    /// the running process. It is repaired only after retirement below.
    fn recovery_lifecycle(maintenance: &Maintenance) -> io::Result<Option<RuntimeLifecycleView>> {
        match maintenance.lifecycle() {
            Ok(view) => Ok(Some(view)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn journal_instance(
        view: &RuntimeLifecycleView,
        managed: ManagedIdentity,
        exclude: Option<[u8; 16]>,
    ) -> Option<[u8; 16]> {
        [
            view.current.as_ref().map(|current| &current.stamp),
            view.last_finished().map(|(stamp, _)| stamp),
            view.last_unfinished.as_ref(),
        ]
        .into_iter()
        .flatten()
        .filter(|stamp| stamp.managed() == managed && Some(stamp.instance()) != exclude)
        .max_by_key(|stamp| stamp.ordinal())
        .map(|stamp| stamp.instance())
    }

    async fn bounded<T>(
        duration: Duration,
        work: impl Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        let lease = Lease::new();
        let deadline = lease
            .deadline_after(duration)
            .map_err(|_| io::ErrorKind::TimedOut)?;
        lease
            .run_until(Some(deadline), work)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }

    async fn ready(gate: &Gate) -> io::Result<control::ControlIdentity> {
        bounded(Duration::from_secs(45), async {
            loop {
                match control::inspect(&gate.control).await {
                    Ok(identity) => {
                        if identity.managed != Some(gate.identity) || !identity.supports_stop {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "managed service identity mismatch",
                            ));
                        }
                        if identity.phase == crate::service::ServicePhase::Stopped {
                            return Err(io::Error::new(
                                io::ErrorKind::NotConnected,
                                "managed service has already stopped",
                            ));
                        }
                        return Ok(identity);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::NotFound
                                | io::ErrorKind::ConnectionRefused
                                | io::ErrorKind::WouldBlock
                        ) => {}
                    Err(error) => return Err(error),
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
    }

    async fn retire(maintenance: &Maintenance) -> io::Result<RetiredRuntime> {
        bounded(Duration::from_secs(10), async {
            loop {
                match maintenance.try_runtime() {
                    Ok(retired) => return Ok(retired),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
    }

    async fn command(backend: &impl Executor, action: Action) -> io::Result<()> {
        // Native itself owns bounded output and child wait. A custom backend is
        // trusted embedding code and must honour the Executor contract.
        match backend.execute(action).await? {
            Outcome::Exited {
                success: true,
                code: Some(0),
            } => Ok(()),
            Outcome::Exited { .. } => Err(io::Error::other(
                "service manager command failed; deployment outcome requires inspection",
            )),
            Outcome::Unknown { .. } => Err(io::Error::other(
                "service manager outcome unknown; no automatic retry or rollback",
            )),
        }
    }

    async fn command_load(
        store: &mut Store,
        backend: &impl Executor,
        action: Action,
    ) -> io::Result<()> {
        let result = backend.execute(action).await;
        if matches!(
            &result,
            Ok(Outcome::Exited { .. }
                | Outcome::Unknown {
                    child_reaped: true,
                    ..
                })
        ) {
            store.mark_load_child(false)?;
        }
        match result? {
            Outcome::Exited {
                success: true,
                code: Some(0),
            } => Ok(()),
            _ => Err(io::Error::other(
                "service load outcome requires explicit recovery",
            )),
        }
    }

    fn close(maintenance: &mut Maintenance) -> io::Result<()> {
        let mut gate = maintenance.read_gate()?;
        if gate.enabled {
            gate.enabled = false;
            maintenance.set_gate(&gate)?;
        }
        Ok(())
    }

    /// Reopen after any persistence error: cached records may predate a rename
    /// which succeeded before sync failed. No cached state is used to recover.
    fn contain_failure(root: &Path, original: io::Error) -> io::Error {
        let Ok(mut store) = Store::open(root) else {
            return io::Error::new(
                original.kind(),
                "deployment failed; persisted state and admission closure require inspection",
            );
        };
        if store.pending().is_none() {
            return original;
        }
        let closed = managed_runtime::open_maintenance(&store.runtime_path())
            .and_then(|mut maintenance| close(&mut maintenance))
            .is_ok();
        let recorded = store.note_unknown(UnknownReason::OperationFailed).is_ok();
        io::Error::new(original.kind(), match (closed, recorded) {
            (true, true) => "deployment failed; new admission closed, transaction outcome unknown; an existing instance may still require cleanup",
            (true, false) => "deployment failed; new admission closed, transaction persistence requires inspection",
            _ => "deployment failed; admission closure and transaction outcome require inspection",
        })
    }

    pub async fn install_with_backend(
        plan: Plan,
        start: bool,
        backend: &impl Executor,
    ) -> io::Result<DeploymentReport> {
        let mut source = validate_plan(&plan)?;
        // Run the selected trusted executable before creating installation state.
        crate::managed_candidate::validate(&plan.source_binary, source.digest(), &plan.gate.config)
            .await?;
        source.verify()?;
        let root = plan.state_directory.clone();
        let existing = match std::fs::symlink_metadata(&root) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        let mut store = if existing {
            Store::open(&root)?
        } else {
            Store::initialize(&root, &plan.gate)?
        };
        let mut maintenance = managed_runtime::open_maintenance(&store.runtime_path())?;
        let result = (|| {
            if store.pending().is_some()
                || store.record().current.is_some()
                || store.record().previous.is_some()
                || store.record().plist.is_some()
                || maintenance.read_gate()? != store.record().gate
                || store.record().gate.enabled
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "installation is not an idle, fully uninstalled owned store",
                ));
            }
            let retired = maintenance.try_runtime()?;
            settle_lifecycle(&maintenance, &retired, false)?;
            let release = store.prepare_release(&mut source)?;
            let mut next = store.record().clone();
            next.current = Some(release.clone());
            if existing {
                next.gate.identity.generation = store.reserve_generation()?;
                next.gate.identity.release = release.digest();
                next.gate.binary = store.version_path(&release);
                next.gate.config = plan.gate.config.clone();
                next.label = crate::launchd::label_for(&next.gate.identity)?;
            }
            next.plist_path = Some(
                plan.launch_agents_directory
                    .join(format!("{}.plist", next.label)),
            );
            store.begin(Operation::Install, next.clone())?;
            maintenance.set_gate(&next.gate)?;
            store.advance(Phase::Configured, None)?;
            store.commit()?;
            drop(retired);
            report(&store, &next.gate, &maintenance)
        })();
        drop(maintenance);
        drop(store);
        let installed = result.map_err(|error| contain_failure(&root, error))?;
        if start {
            change_with_backend(&root, ManageAction::Start, None, backend).await
        } else {
            Ok(installed)
        }
    }

    pub async fn change_with_backend(
        root: &Path,
        action: ManageAction,
        source: Option<&Path>,
        backend: &impl Executor,
    ) -> io::Result<DeploymentReport> {
        let uid = uid()?;
        if source.is_some() != (action == ManageAction::Upgrade) {
            return Err(invalid());
        }
        let mut store = Store::open(root)?;
        if store.pending().is_some() {
            return Err(pending());
        }
        let mut maintenance = managed_runtime::open_maintenance(&store.runtime_path())?;
        let old = store.record().clone();
        if maintenance.read_gate()? != old.gate {
            return Err(io::Error::other(
                "deployment record and admission gate disagree; recovery required",
            ));
        }
        if old.current.is_none() {
            if action == ManageAction::Uninstall {
                return report(&store, &old.gate, &maintenance);
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no installed release",
            ));
        }
        if old.plist.is_some() {
            store.verify_current_plist()?;
        }
        if action == ManageAction::Start && old.gate.enabled {
            let result = resume(&mut store, &maintenance, &old, uid, backend).await;
            drop(maintenance);
            drop(store);
            return result.map_err(|error| contain_failure(root, error));
        }
        if action == ManageAction::Stop && !old.gate.enabled && old.plist.is_none() {
            return report(&store, &old.gate, &maintenance);
        }
        let mut next = old.clone();
        if let Some(source) = source {
            let mut candidate = managed_release::Source::open(source)?;
            if candidate.digest() == old.gate.identity.release {
                return report(&store, &old.gate, &maintenance);
            }
            let release = store.prepare_release(&mut candidate)?;
            if let Err(error) = crate::managed_candidate::validate(
                &store.version_path(&release),
                release.digest(),
                &old.gate.config,
            )
            .await
            {
                // No service transaction has started: the old instance remains
                // admitted. Remove only this exact unreferenced owned candidate.
                if old.previous.as_ref() != Some(&release) {
                    store.discard_candidate(&release)?;
                }
                return Err(error);
            }
            next.previous = old.current.clone();
            next.current = Some(release.clone());
            next.gate.identity.release = release.digest();
            next.gate.binary = store.version_path(&release);
        } else if action == ManageAction::Start {
            crate::managed_candidate::validate(
                &old.gate.binary,
                old.gate.identity.release,
                &old.gate.config,
            )
            .await?;
        }
        next.gate.enabled = match action {
            ManageAction::Start => true,
            ManageAction::Upgrade => old.gate.enabled,
            ManageAction::Stop | ManageAction::Uninstall => false,
        };
        if next.gate.enabled || action == ManageAction::Upgrade {
            next.gate.identity.generation = store.reserve_generation()?;
            next.label = crate::launchd::label_for(&next.gate.identity)?;
            next.plist_path = Some(
                old.plist_path
                    .as_ref()
                    .and_then(|path| path.parent())
                    .ok_or_else(invalid)?
                    .join(format!("{}.plist", next.label)),
            );
            next.plist = None;
        }
        if !next.gate.enabled {
            next.plist = None;
        }
        if action == ManageAction::Uninstall {
            next.current = None;
            next.previous = None;
        }
        let operation = match action {
            ManageAction::Start => Operation::Start,
            ManageAction::Stop => Operation::Stop,
            ManageAction::Upgrade => Operation::Upgrade,
            ManageAction::Uninstall => Operation::Uninstall,
        };
        let result = apply(
            &mut store,
            &mut maintenance,
            old,
            next,
            operation,
            uid,
            backend,
        )
        .await;
        drop(maintenance);
        drop(store);
        result.map_err(|error| contain_failure(root, error))
    }

    async fn resume(
        store: &mut Store,
        maintenance: &Maintenance,
        old: &Record,
        uid: u32,
        backend: &impl Executor,
    ) -> io::Result<DeploymentReport> {
        crate::managed_candidate::validate(
            &old.gate.binary,
            old.gate.identity.release,
            &old.gate.config,
        )
        .await?;
        if old.plist.is_none() {
            return Err(invalid());
        }
        let mut predecessor_unobserved = false;
        let mut previous_instance = None;
        match control::inspect(&old.gate.control).await {
            Ok(identity) => {
                if identity.managed != Some(old.gate.identity) || !identity.supports_stop {
                    return Err(invalid());
                }
                previous_instance = Some(identity.instance);
                if identity.phase == crate::service::ServicePhase::Stopped {
                    drop(retire(maintenance).await?);
                    predecessor_unobserved = true;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                drop(retire(maintenance).await?);
                predecessor_unobserved = true;
            }
            Err(error) => return Err(error),
        }
        let before = maintenance.lifecycle()?;
        if previous_instance.is_none() && predecessor_unobserved {
            previous_instance = before
                .current
                .as_ref()
                .filter(|current| current.stamp.managed() == old.gate.identity)
                .map(|current| current.stamp.instance());
        }
        // Same admitted generation, same files. This never replaces a running
        // process and does not claim a cleanup receipt for its predecessor.
        store.begin(Operation::Resume, old.clone())?;
        if let Some(instance) = previous_instance {
            store.observe_previous_instance(instance)?;
        }
        let terminal = if let Some(instance) = previous_instance {
            record_finished(
                store,
                &before,
                CleanupTarget::Previous,
                old.gate.identity,
                instance,
            )?
        } else {
            false
        };
        if predecessor_unobserved && !terminal {
            store.record_cleanup_unknown(
                CleanupTarget::Previous,
                UnknownCleanup {
                    managed: old.gate.identity,
                    instance: previous_instance,
                    reason: UnknownReason::RuntimeRetiredWithoutReceipt,
                },
            )?;
        }
        store.advance(Phase::NewJobLoadRequested, None)?;
        command(
            backend,
            Action::Enable {
                uid,
                label: old.label.clone(),
            },
        )
        .await?;
        command(
            backend,
            Action::Kickstart {
                uid,
                label: old.label.clone(),
            },
        )
        .await?;
        store.advance(Phase::NewJobLoaded, None)?;
        let identity = ready(&old.gate).await?;
        if let Some(previous) = previous_instance {
            if previous != identity.instance {
                let after = maintenance.lifecycle()?;
                if !terminal
                    && !record_finished(
                        store,
                        &after,
                        CleanupTarget::Previous,
                        old.gate.identity,
                        previous,
                    )?
                {
                    store.record_cleanup_unknown(
                        CleanupTarget::Previous,
                        UnknownCleanup {
                            managed: old.gate.identity,
                            instance: Some(previous),
                            reason: UnknownReason::UnobservedIncarnation,
                        },
                    )?;
                }
            }
        }
        let cleanup = store.pending().and_then(|tx| tx.stop.clone());
        store.advance(Phase::Ready, None)?;
        store.commit()?;
        let mut result = report(store, &old.gate, maintenance)?;
        result.matched_instance = Some(managed_release::hexadecimal(&identity.instance));
        attach_cleanup(&mut result, cleanup.as_ref());
        Ok(result)
    }

    async fn apply(
        store: &mut Store,
        maintenance: &mut Maintenance,
        old: Record,
        next: Record,
        operation: Operation,
        uid: u32,
        backend: &impl Executor,
    ) -> io::Result<DeploymentReport> {
        store.begin(operation, next.clone())?;
        close(maintenance)?;
        store.advance(Phase::Maintenance, None)?;
        if old.gate.enabled {
            // Closing admission prevents replacements; it does not stop an
            // already admitted instance. Exact durable terminal evidence can
            // replace a lost reply, but is explicitly reported as disk evidence.
            let view = maintenance.lifecycle()?;
            let finished = view.current.as_ref().filter(|current| {
                current.stamp.managed() == old.gate.identity
                    && matches!(current.outcome, IncarnationOutcome::Finished(_))
            });
            if let Some(current) = finished {
                store.observe_previous_instance(current.stamp.instance())?;
                store.advance(Phase::StopRequested, None)?;
                if !record_finished(
                    store,
                    &view,
                    CleanupTarget::Previous,
                    old.gate.identity,
                    current.stamp.instance(),
                )? {
                    return Err(invalid());
                }
                store.advance(Phase::Stopped, None)?;
            } else {
                let identity = ready(&old.gate).await?;
                // Persist the exact incarnation before the manager can lose
                // its IPC response; a later instance cannot substitute for it.
                store.observe_previous_instance(identity.instance)?;
                store.advance(Phase::StopRequested, None)?;
                let completion = control::stop(
                    &old.gate.control,
                    &identity.binding,
                    Some(identity.instance),
                )
                .await?;
                store.advance(
                    Phase::Stopped,
                    Some(StopEvidence::ipc(
                        identity.instance,
                        old.gate.identity,
                        completion,
                    )),
                )?;
            }
        }
        let retired = retire(maintenance).await?;
        settle_lifecycle(maintenance, &retired, false)?;
        store.advance(Phase::RuntimeRetired, None)?;
        let cleanup = store.pending().and_then(|tx| tx.stop.clone());
        if old.plist.is_some() {
            store.advance(Phase::OldJobRemovalRequested, None)?;
            command(
                backend,
                Action::Bootout {
                    uid,
                    label: old.label.clone(),
                },
            )
            .await?;
            store.advance(Phase::OldJobRemoved, None)?;
        }
        if !next.gate.enabled {
            if let Some(plist) = old.plist.as_ref() {
                store.remove_plist(plist)?;
            }
            maintenance.set_gate(&next.gate)?;
            store.advance(Phase::Configured, None)?;
            store.commit()?;
            let mut result = report(store, &next.gate, maintenance)?;
            attach_cleanup(&mut result, cleanup.as_ref());
            return Ok(result);
        }
        if let Some(plist) = old.plist.as_ref() {
            store.remove_plist(plist)?;
        }
        let path = next.plist_path.as_ref().ok_or_else(invalid)?;
        let parent = path.parent().ok_or_else(invalid)?;
        // Create at most the selected leaf; do not recursively adopt parents.
        match std::fs::DirBuilder::new().mode(0o700).create(parent) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let bytes = crate::launchd::render_plist(
            uid,
            &next.label,
            &next.gate.binary,
            &store.runtime_path(),
            &next.gate.identity,
        )?;
        store.publish_plist(path, &bytes, old.plist.as_ref())?;
        store.advance(Phase::PlistPublished, None)?;
        // This label belongs to a fresh generation and has never been loaded
        // by this installation. Bootstrap uses its existing OS policy. Do not
        // create a persistent enable override for every new label: bootout is
        // not documented to remove those overrides. Explicit same-label Resume
        // retains its separate enable operation.
        // Record the possible side effect before opening admission. Old launchd
        // arguments carry an older generation and cannot acquire this lease.
        store.advance(Phase::NewJobLoadRequested, None)?;
        store.mark_load_child(true)?;
        maintenance.set_gate(&next.gate)?;
        drop(retired);
        command_load(
            store,
            backend,
            Action::Bootstrap {
                uid,
                plist: path.clone(),
            },
        )
        .await?;
        store.advance(Phase::NewJobLoaded, None)?;
        let identity = ready(&next.gate).await?;
        store.advance(Phase::Ready, None)?;
        store.commit()?;
        let mut result = report(store, &next.gate, maintenance)?;
        result.matched_instance = Some(managed_release::hexadecimal(&identity.instance));
        attach_cleanup(&mut result, cleanup.as_ref());
        Ok(result)
    }

    async fn observe_for_recovery(
        gate: &Gate,
        maintenance: &Maintenance,
    ) -> io::Result<Option<control::ControlIdentity>> {
        bounded(Duration::from_secs(45), async {
            loop {
                match control::inspect(&gate.control).await {
                    Ok(identity) => return Ok(Some(identity)),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                        ) =>
                    {
                        match maintenance.try_runtime() {
                            Ok(retired) => {
                                drop(retired);
                                return Ok(None);
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                            Err(error) => return Err(error),
                        }
                    }
                    Err(error) => return Err(error),
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
    }

    pub fn recovery_plan(root: &Path) -> io::Result<RecoveryExpectation> {
        let store = Store::open_recovery(root)?;
        Ok(RecoveryExpectation {
            installation: store.record().installation,
            revision: store.recovery_token()?,
        })
    }

    fn attempted_may_have_run(tx: &crate::deployment_store::Transaction) -> bool {
        tx.operation == Operation::Resume
            || (tx.next.gate.enabled
                && matches!(
                    tx.phase,
                    Phase::NewJobLoadRequested
                        | Phase::NewJobLoaded
                        | Phase::AdmissionOpened
                        | Phase::Ready
                ))
            || tx.next_stop.is_some()
            || tx.next_unknown.is_some()
    }

    fn old_job_removed(tx: &crate::deployment_store::Transaction) -> bool {
        tx.operation != Operation::Resume
            && matches!(
                tx.phase,
                Phase::OldJobRemoved
                    | Phase::PlistPublished
                    | Phase::NewJobLoadRequested
                    | Phase::NewJobLoaded
                    | Phase::AdmissionOpened
                    | Phase::Ready
                    | Phase::Configured
            )
    }

    async fn clear_retired_jobs(
        store: &mut Store,
        uid: u32,
        backend: &impl Executor,
    ) -> io::Result<()> {
        // Each explicit recovery makes one bounded attempt per retained label.
        // A nonzero exit never proves absence and therefore retains the job.
        for mut job in store.ledger().retired_jobs.clone() {
            if job.removal_unknown {
                let confirmed = matches!(
                    backend
                        .execute(Action::Bootout {
                            uid,
                            label: job.label.clone(),
                        })
                        .await,
                    Ok(Outcome::Exited {
                        success: true,
                        code: Some(0)
                    })
                );
                if !confirmed {
                    continue;
                }
                job = store.confirm_retired_job_removal(&job)?;
            }
            store.remove_retired_plist(&job)?;
            store.forget_retired_job(&job)?;
        }
        Ok(())
    }

    pub async fn recover_with_backend(
        root: &Path,
        expected: Option<&RecoveryExpectation>,
        backend: &impl Executor,
    ) -> io::Result<DeploymentReport> {
        let uid = uid()?;
        let mut store = Store::open_recovery(root)?;
        if let Some(expected) = expected {
            if expected.installation != store.record().installation
                || expected.revision != store.recovery_token()?
            {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "recovery plan is stale; no external action submitted",
                ));
            }
        }
        store.repair_metadata()?;
        let mut maintenance = managed_runtime::open_maintenance(&store.runtime_path())?;
        let result = recover_locked(&mut store, &mut maintenance, uid, backend).await;
        drop(maintenance);
        drop(store);
        result.map_err(|error| contain_failure(root, error))
    }

    async fn recover_locked(
        store: &mut Store,
        maintenance: &mut Maintenance,
        uid: u32,
        backend: &impl Executor,
    ) -> io::Result<DeploymentReport> {
        let committed = store.record().clone();
        // A reservation is durable before any gate or external side effect.
        let generation = store.reserve_generation()?;
        let mut target = committed.clone();
        target.gate.enabled = false;
        target.gate.identity.generation = generation;
        target.label = crate::launchd::label_for(&target.gate.identity)?;
        target.plist_path = committed
            .plist_path
            .as_ref()
            .map(|path| {
                path.parent()
                    .ok_or_else(invalid)
                    .map(|parent| parent.join(format!("{}.plist", target.label)))
            })
            .transpose()?;
        target.plist = None;
        // New generation fencing also works if the old gate's inactive slot is
        // half-written. The expected CLOSED value is independently derived from
        // the durable deployment record/reservation, never from damaged bytes.
        match maintenance.read_gate() {
            Ok(_) => maintenance.set_gate(&target.gate)?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                maintenance.recover_next(&target.gate)?
            }
            Err(error) => return Err(error),
        }
        if store.has_garbage() {
            let retired = retire(maintenance).await?;
            store.drain_garbage(&retired)?;
        }
        if store.pending().is_none() {
            store.begin(Operation::Recover, target.clone())?;
        }
        let mut tx = store.pending().cloned().ok_or_else(invalid)?;
        let attempted = attempted_may_have_run(&tx);
        // Preserve the predecessor's exact terminal proof before stopping a
        // replacement can update last_finished. No snapshot guard spans await.
        if let Some(view) = recovery_lifecycle(maintenance)? {
            if tx.previous_instance.is_none() {
                if let Some(instance) = journal_instance(&view, tx.previous.gate.identity, None) {
                    store.observe_previous_instance(instance)?;
                    tx = store.pending().cloned().ok_or_else(invalid)?;
                }
            }
            if let Some(instance) = tx.previous_instance {
                record_finished(
                    store,
                    &view,
                    CleanupTarget::Previous,
                    tx.previous.gate.identity,
                    instance,
                )?;
            }
            if attempted {
                let exclude = (tx.previous.gate.identity == tx.next.gate.identity)
                    .then_some(tx.previous_instance)
                    .flatten();
                if let Some(instance) = journal_instance(&view, tx.next.gate.identity, exclude) {
                    record_finished(
                        store,
                        &view,
                        CleanupTarget::Attempted,
                        tx.next.gate.identity,
                        instance,
                    )?;
                }
            }
        }
        let mut observed = None;
        let mut extra_cleanup = None;
        if let Some(identity) = observe_for_recovery(&target.gate, maintenance).await? {
            let managed = identity.managed.ok_or_else(invalid)?;
            let role = if attempted
                && managed == tx.next.gate.identity
                && !(managed == tx.previous.gate.identity
                    && tx.previous_instance == Some(identity.instance))
            {
                CleanupTarget::Attempted
            } else if managed == tx.previous.gate.identity {
                CleanupTarget::Previous
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "recovery found an unrelated service instance",
                ));
            };
            if !identity.supports_stop {
                return Err(invalid());
            }
            if role == CleanupTarget::Previous && tx.previous_instance.is_none() {
                store.observe_previous_instance(identity.instance)?;
                tx = store.pending().cloned().ok_or_else(invalid)?;
            }
            // B can share A's managed generation after an automatic restart.
            // Stop B, but never overwrite the transaction's exact A slot. B's
            // durable lifecycle terminal remains the sole cumulative source.
            let matches_slot =
                role != CleanupTarget::Previous || tx.previous_instance == Some(identity.instance);
            observed = Some((role, managed, identity.instance, matches_slot));
            if matches_slot {
                store.record_cleanup_unknown(
                    role,
                    UnknownCleanup {
                        managed,
                        instance: Some(identity.instance),
                        reason: UnknownReason::StopUnobserved,
                    },
                )?;
            }
            match control::stop(
                &target.gate.control,
                &identity.binding,
                Some(identity.instance),
            )
            .await
            {
                Ok(report) => {
                    let proof = StopEvidence::ipc(identity.instance, managed, report);
                    if matches_slot {
                        store.record_cleanup(role, proof)?;
                    } else {
                        extra_cleanup = Some(proof);
                    }
                }
                Err(_) => { /* Retirement and the exact journal are checked below. */ }
            }
        }
        let retired = retire(maintenance).await?;
        let view = settle_lifecycle(maintenance, &retired, true)?;
        if let Some(instance) = tx.previous_instance {
            record_finished(
                store,
                &view,
                CleanupTarget::Previous,
                tx.previous.gate.identity,
                instance,
            )?;
        }
        if attempted {
            let exclude = (tx.previous.gate.identity == tx.next.gate.identity)
                .then_some(tx.previous_instance)
                .flatten();
            if let Some(instance) = journal_instance(&view, tx.next.gate.identity, exclude) {
                record_finished(
                    store,
                    &view,
                    CleanupTarget::Attempted,
                    tx.next.gate.identity,
                    instance,
                )?;
            }
        }
        // A missing IPC reply is not missing cleanup if the same incarnation
        // durably finished. Conversely, B's proof must never clear A's gap.
        let current = store.pending().cloned().ok_or_else(invalid)?;
        if tx.previous.gate.enabled && current.stop.is_none() {
            store.record_cleanup_unknown(
                CleanupTarget::Previous,
                UnknownCleanup {
                    managed: tx.previous.gate.identity,
                    instance: tx.previous_instance,
                    reason: UnknownReason::RuntimeRetiredWithoutReceipt,
                },
            )?;
        }
        if attempted && current.next_stop.is_none() {
            let exclude = (tx.previous.gate.identity == tx.next.gate.identity)
                .then_some(tx.previous_instance)
                .flatten();
            let instance = journal_instance(&view, tx.next.gate.identity, exclude).or_else(|| {
                observed.and_then(|(role, _, instance, _)| {
                    (role == CleanupTarget::Attempted).then_some(instance)
                })
            });
            store.record_cleanup_unknown(
                CleanupTarget::Attempted,
                UnknownCleanup {
                    managed: tx.next.gate.identity,
                    instance,
                    reason: UnknownReason::RuntimeRetiredWithoutReceipt,
                },
            )?;
        }
        let cleanup = store
            .pending()
            .and_then(|current| current.stop.clone().or_else(|| current.next_stop.clone()))
            .or(extra_cleanup);
        // Persist every possibly loaded definition before requesting removal.
        // The independent labels make delayed removal unable to target a later
        // generation. Keep plist and release references until removal confirms.
        if let (Some(plist), Some(release)) = (&tx.previous.plist, &tx.previous.current) {
            store.retain_retired_job(RetiredJob {
                managed: tx.previous.gate.identity,
                label: tx.previous.label.clone(),
                plist: plist.clone(),
                release: release.clone(),
                removal_unknown: !old_job_removed(&tx),
                anchor_pinned: false,
            })?;
        }
        if let (Some(plist), Some(release)) = (&tx.next.plist, &tx.next.current) {
            if tx.previous.plist.as_ref() != Some(plist) {
                if attempted {
                    store.retain_retired_job(RetiredJob {
                        managed: tx.next.gate.identity,
                        label: tx.next.label.clone(),
                        plist: plist.clone(),
                        release: release.clone(),
                        removal_unknown: true,
                        anchor_pinned: tx.load_child_may_live,
                    })?;
                } else {
                    store.remove_unstarted_plist(plist, &retired)?;
                }
            }
        }
        clear_retired_jobs(store, uid, backend).await?;
        store.finish_recovery(target.clone(), &retired)?;
        let mut result = report(store, &target.gate, maintenance)?;
        attach_cleanup(&mut result, cleanup.as_ref());
        drop(retired);
        Ok(result)
    }

    pub async fn inspect_with_backend(
        root: &Path,
        backend: &impl Executor,
    ) -> io::Result<DeploymentReport> {
        let uid = uid()?;
        let store = Store::open(root)?;
        let maintenance = managed_runtime::open_maintenance(&store.runtime_path())?;
        let gate = maintenance.read_gate()?;
        let mut result = report(&store, &gate, &maintenance)?;
        result.backend_observation = Some(
            match backend
                .execute(Action::ProbeService {
                    uid,
                    label: store.record().label.clone(),
                })
                .await
            {
                Ok(Outcome::Exited {
                    success: true,
                    code: Some(0),
                }) => "definition_reported",
                Ok(Outcome::Exited { .. }) => "probe_failed",
                Ok(Outcome::Unknown { .. }) | Err(_) => "probe_outcome_unknown",
            }
            .to_owned(),
        );
        if let Ok(identity) = control::inspect(&gate.control).await {
            if identity.managed == Some(gate.identity) {
                result.matched_instance = Some(managed_release::hexadecimal(&identity.instance));
            }
        }
        Ok(result)
    }
}
