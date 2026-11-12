//! Synthetic typed service backend, not launchd. At most three generation-bound
//! definitions (two retired and one current) and their owned child handles exist.
//! Delayed actions retain their original label and parsed definition. No task is
//! spawned to deliver them: the test must explicitly complete the delayed work.
use gp_proxy::{
    control,
    deployment::backend::{Action, Executor, Outcome, UnknownReason},
    managed_protocol::ManagedIdentity,
    managed_release::{hexadecimal, parse_release},
    managed_runtime::{self, Gate},
};
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{Mutex, Semaphore},
    time::{sleep, timeout},
};

const MAX_JOBS: usize = 3;
const MAX_ACTIONS: usize = 128;
const MAX_CONTROLS: usize = 8;
const STEP: Duration = Duration::from_secs(5);
const CONTROL_WAIT: Duration = Duration::from_secs(45);
const LABEL_PREFIX: &str = "io.gp-proxy.";
pub const CHILD_MODE: &str = "GP_DEPLOYMENT_OWNED_SESSION";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    BootstrapBefore,
    BootstrapAfter,
    BootoutBefore,
    BootoutAfter,
    KickstartBefore,
    KickstartAfter,
    EnableBefore,
    EnableAfter,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionKind {
    Bootstrap,
    Bootout,
    Kickstart,
    Enable,
}
impl ActionKind {
    fn of(action: &Action) -> Option<Self> {
        match action {
            Action::Bootstrap { .. } => Some(Self::Bootstrap),
            Action::Bootout { .. } => Some(Self::Bootout),
            Action::Kickstart { .. } => Some(Self::Kickstart),
            Action::Enable { .. } => Some(Self::Enable),
            _ => None,
        }
    }
    fn points(self) -> (Fault, Fault) {
        match self {
            Self::Bootstrap => (Fault::BootstrapBefore, Fault::BootstrapAfter),
            Self::Bootout => (Fault::BootoutBefore, Fault::BootoutAfter),
            Self::Kickstart => (Fault::KickstartBefore, Fault::KickstartAfter),
            Self::Enable => (Fault::EnableBefore, Fault::EnableAfter),
        }
    }
}

#[derive(Clone)]
pub struct Pause {
    entered: Arc<Semaphore>,
    released: Arc<Semaphore>,
}
impl Pause {
    pub async fn wait_entered(&self) {
        timeout(CONTROL_WAIT, self.entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
    }
    pub fn release(&self) {
        self.released.add_permits(1);
    }
    async fn arrive(&self) -> io::Result<()> {
        self.entered.add_permits(1);
        timeout(CONTROL_WAIT, self.released.acquire())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "owned backend pause deadline"))?
            .map_err(|_| io::ErrorKind::BrokenPipe)?
            .forget();
        Ok(())
    }
}
enum Response {
    Unknown,
    Pause(Pause),
}
struct Rule {
    point: Fault,
    response: Response,
}

#[derive(Clone, Debug)]
pub struct Observation {
    pub action: Action,
    pub gate_enabled: Option<bool>,
    pub generation: Option<u64>,
    /// False records the initial request; true records explicit delayed delivery.
    pub delayed_delivery: bool,
}

#[derive(Clone)]
struct Program {
    label: String,
    identity: ManagedIdentity,
    arguments: Vec<String>,
}
#[derive(Clone)]
struct Prepared {
    action: Action,
    program: Option<Program>,
}
impl Prepared {
    fn label(&self) -> Option<&str> {
        match &self.action {
            Action::Bootstrap { .. } => Some(&self.program.as_ref().unwrap().label),
            Action::ProbeService { label, .. }
            | Action::Bootout { label, .. }
            | Action::Enable { label, .. }
            | Action::Kickstart { label, .. } => Some(label),
            Action::ProbeDomain { .. } => None,
        }
    }
}
struct Job {
    program: Program,
    child: Option<Child>,
}
impl Job {
    fn spawn(&mut self, cwd: &Path) -> io::Result<bool> {
        if let Some(child) = &mut self.child {
            if child.try_wait()?.is_none() {
                return Ok(false);
            }
            child.wait()?;
        }
        self.child = Some(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "backend_owned_session",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env_clear()
                .env(CHILD_MODE, "exec")
                .env(
                    "GP_DEPLOYMENT_ARGUMENTS",
                    serde_json::to_string(&self.program.arguments).unwrap(),
                )
                .current_dir(cwd)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        Ok(true)
    }
    fn alive(&mut self) -> io::Result<bool> {
        match &mut self.child {
            Some(child) => Ok(child.try_wait()?.is_none()),
            None => Ok(false),
        }
    }
    async fn retire(&mut self) -> io::Result<()> {
        if let Some(child) = &mut self.child {
            timeout(STEP, async {
                loop {
                    if child.try_wait()?.is_some() {
                        child.wait()?;
                        return Ok::<(), io::Error>(());
                    }
                    sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fake backend will not kill an active service to rescue manager cleanup",
                )
            })??;
        }
        self.child = None;
        Ok(())
    }
    fn crash(&mut self) -> io::Result<ExitStatus> {
        let child = self.child.as_mut().ok_or(io::ErrorKind::NotFound)?;
        if child.try_wait()?.is_none() {
            child.kill()?;
        }
        let status = child.wait()?;
        self.child = None;
        Ok(status)
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

struct State {
    jobs: BTreeMap<String, Job>,
    actions: Vec<Observation>,
    rules: VecDeque<Rule>,
    delay_next: VecDeque<ActionKind>,
    delayed: VecDeque<Prepared>,
    spawned: usize,
}
pub struct Backend {
    pub root: PathBuf,
    installation: [u8; 16],
    plist_directory: PathBuf,
    cwd: PathBuf,
    uid: u32,
    state: Mutex<State>,
    delivery: Mutex<()>,
}
impl Backend {
    /// The initial label can be an installation prefix or a generation label;
    /// all actual requests must use the strict per-generation spelling.
    pub fn new(root: PathBuf, label: String, plist: PathBuf, cwd: PathBuf) -> Self {
        let text = label
            .strip_prefix(LABEL_PREFIX)
            .unwrap()
            .split(".g")
            .next()
            .unwrap();
        assert_eq!(text.len(), 32);
        let installation = decode_installation(text).unwrap();
        Self {
            root,
            installation,
            plist_directory: plist.parent().unwrap().to_owned(),
            cwd,
            uid: rustix::process::geteuid().as_raw(),
            delivery: Mutex::new(()),
            state: Mutex::new(State {
                jobs: BTreeMap::new(),
                actions: Vec::with_capacity(MAX_ACTIONS),
                rules: VecDeque::new(),
                delay_next: VecDeque::new(),
                delayed: VecDeque::new(),
                spawned: 0,
            }),
        }
    }
    pub async fn fail_once(&self, point: Fault) {
        let mut state = self.state.lock().await;
        assert!(state.rules.len() < MAX_CONTROLS);
        state.rules.push_back(Rule {
            point,
            response: Response::Unknown,
        });
    }
    pub async fn pause_once(&self, point: Fault) -> Pause {
        let pause = Pause {
            entered: Arc::new(Semaphore::new(0)),
            released: Arc::new(Semaphore::new(0)),
        };
        let mut state = self.state.lock().await;
        assert!(state.rules.len() < MAX_CONTROLS);
        state.rules.push_back(Rule {
            point,
            response: Response::Pause(pause.clone()),
        });
        pause
    }
    /// Return Unknown now, but preserve a bounded, label-bound action which a
    /// test may deliver after recovery has installed a different generation.
    pub async fn delay_once(&self, kind: ActionKind) {
        let mut state = self.state.lock().await;
        assert!(state.delay_next.len() + state.delayed.len() < MAX_CONTROLS);
        state.delay_next.push_back(kind);
    }
    pub async fn delayed_count(&self) -> usize {
        self.state.lock().await.delayed.len()
    }
    pub async fn complete_delayed(&self) -> io::Result<Outcome> {
        let _delivery = self.delivery.lock().await;
        let prepared = self
            .state
            .lock()
            .await
            .delayed
            .front()
            .cloned()
            .ok_or(io::ErrorKind::NotFound)?;
        self.observe(&prepared.action, true).await?;
        let result = self.apply(&prepared).await?;
        // Cancellation before completion leaves the original queued action.
        self.state.lock().await.delayed.pop_front();
        Ok(result)
    }
    pub async fn observations(&self) -> Vec<Observation> {
        self.state.lock().await.actions.clone()
    }
    pub async fn loaded(&self) -> bool {
        !self.state.lock().await.jobs.is_empty()
    }
    pub async fn loaded_labels(&self) -> Vec<String> {
        self.state.lock().await.jobs.keys().cloned().collect()
    }
    pub async fn alive_labels(&self) -> Vec<String> {
        self.state
            .lock()
            .await
            .jobs
            .iter_mut()
            .filter_map(|(label, job)| job.alive().unwrap().then(|| label.clone()))
            .collect()
    }
    pub async fn spawned(&self) -> usize {
        self.state.lock().await.spawned
    }
    pub async fn reap_stopped(&self) {
        let mut state = self.state.lock().await;
        for job in state.jobs.values_mut() {
            job.retire().await.unwrap();
        }
    }
    pub async fn reap_label(&self, label: &str) {
        self.validate_label(label).unwrap();
        self.state
            .lock()
            .await
            .jobs
            .get_mut(label)
            .unwrap()
            .retire()
            .await
            .unwrap();
    }
    pub async fn crash_label(&self, label: &str) -> ExitStatus {
        self.validate_label(label).unwrap();
        self.state
            .lock()
            .await
            .jobs
            .get_mut(label)
            .unwrap()
            .crash()
            .unwrap()
    }
    fn gate(&self) -> io::Result<Option<Gate>> {
        match managed_runtime::read_gate(&self.root.join("runtime")) {
            Ok(gate) => Ok(Some(gate)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn validate_label(&self, label: &str) -> io::Result<u64> {
        let prefix = format!("{LABEL_PREFIX}{}.g", hexadecimal(&self.installation));
        let suffix = label
            .strip_prefix(&prefix)
            .ok_or(io::ErrorKind::InvalidInput)?;
        if suffix.len() != 16
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let generation =
            u64::from_str_radix(suffix, 16).map_err(|_| io::ErrorKind::InvalidInput)?;
        if generation == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(generation)
    }
    fn program(&self, path: &Path) -> io::Result<Program> {
        if path.parent() != Some(self.plist_directory.as_path()) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(16 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        assert!(bytes.len() <= 16 * 1024);
        let text = std::str::from_utf8(&bytes).unwrap();
        let document = roxmltree::Document::parse_with_options(
            text,
            roxmltree::ParsingOptions {
                allow_dtd: true,
                ..Default::default()
            },
        )
        .unwrap();
        let dict = document.root_element().first_element_child().unwrap();
        let children: Vec<_> = dict.children().filter(|n| n.is_element()).collect();
        let mut arguments = None;
        let mut label = None;
        let mut run_at_load = false;
        assert!(children.len().is_multiple_of(2));
        for pair in children.chunks_exact(2) {
            assert!(pair[0].has_tag_name("key"));
            match pair[0].text().unwrap() {
                "Label" => {
                    assert!(label.is_none());
                    label = pair[1].text();
                }
                "ProgramArguments" => {
                    assert!(arguments.is_none() && pair[1].has_tag_name("array"));
                    arguments = Some(
                        pair[1]
                            .children()
                            .filter(|n| n.is_element())
                            .map(|node| {
                                assert!(node.has_tag_name("string"));
                                node.text().unwrap_or("").to_string()
                            })
                            .collect::<Vec<_>>(),
                    );
                }
                "RunAtLoad" => {
                    assert!(pair[1].has_tag_name("true"));
                    run_at_load = true;
                }
                _ => {}
            }
        }
        let label = label.unwrap().to_owned();
        let generation = self.validate_label(&label)?;
        assert_eq!(path.file_name().unwrap(), format!("{label}.plist").as_str());
        assert!(run_at_load, "do not fabricate absent RunAtLoad semantics");
        let arguments = arguments.unwrap();
        assert_eq!(arguments.len(), 10);
        assert_eq!(
            &arguments[1..4],
            [
                "managed-run",
                "--runtime-dir",
                self.root.join("runtime").to_str().unwrap()
            ]
        );
        assert_eq!(arguments[4], "--installation");
        assert_eq!(arguments[5], hexadecimal(&self.installation));
        assert_eq!(arguments[6], "--generation");
        assert_eq!(arguments[7], generation.to_string());
        assert_eq!(arguments[8], "--release");
        let release = parse_release(&arguments[9])?;
        assert_eq!(
            Path::new(&arguments[0]),
            self.root
                .join("versions")
                .join(&arguments[9])
                .join("gp-proxy")
        );
        let identity = ManagedIdentity {
            installation: self.installation,
            generation,
            release,
        };
        identity.validate()?;
        Ok(Program {
            label,
            identity,
            arguments,
        })
    }
    fn prepare(&self, action: Action) -> io::Result<Prepared> {
        let program = match &action {
            Action::Bootstrap { uid, plist } => {
                assert_eq!(*uid, self.uid);
                Some(self.program(plist)?)
            }
            Action::ProbeDomain { uid } => {
                assert_eq!(*uid, self.uid);
                None
            }
            Action::ProbeService { uid, label }
            | Action::Enable { uid, label }
            | Action::Kickstart { uid, label }
            | Action::Bootout { uid, label } => {
                assert_eq!(*uid, self.uid);
                self.validate_label(label)?;
                None
            }
        };
        Ok(Prepared { action, program })
    }
    async fn observe(&self, action: &Action, delayed_delivery: bool) -> io::Result<()> {
        let gate = self.gate()?;
        let mut state = self.state.lock().await;
        assert!(state.actions.len() < MAX_ACTIONS);
        state.actions.push(Observation {
            action: action.clone(),
            gate_enabled: gate.as_ref().map(|g| g.enabled),
            generation: gate.as_ref().map(|g| g.identity.generation),
            delayed_delivery,
        });
        Ok(())
    }
    async fn take_rule(&self, point: Fault) -> Option<Response> {
        let mut state = self.state.lock().await;
        if state.rules.front().is_some_and(|rule| rule.point == point) {
            state.rules.pop_front().map(|rule| rule.response)
        } else {
            None
        }
    }
    async fn apply(&self, prepared: &Prepared) -> io::Result<Outcome> {
        let gate = self.gate()?;
        let mut state = self.state.lock().await;
        match &prepared.action {
            Action::ProbeDomain { .. } | Action::Enable { .. } => Ok(success()),
            Action::ProbeService { label, .. } => Ok(if state.jobs.contains_key(label) {
                success()
            } else {
                absent()
            }),
            Action::Bootstrap { .. } => {
                let program = prepared.program.as_ref().unwrap();
                if state.jobs.contains_key(&program.label) {
                    return Ok(already_loaded());
                }
                if state.jobs.len() == MAX_JOBS {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "three-definition fake backend capacity",
                    ));
                }
                let mut job = Job {
                    program: program.clone(),
                    child: None,
                };
                if job.spawn(&self.cwd)? {
                    state.spawned += 1;
                }
                state.jobs.insert(program.label.clone(), job);
                Ok(success())
            }
            Action::Kickstart { label, .. } => {
                let Some(job) = state.jobs.get_mut(label) else {
                    return Ok(absent());
                };
                if job.spawn(&self.cwd)? {
                    state.spawned += 1;
                }
                Ok(success())
            }
            Action::Bootout { label, .. } => {
                let gate = gate.as_ref().ok_or(io::ErrorKind::NotFound)?;
                // A delayed old-label removal is harmless to a newly admitted
                // generation. The current generation still requires closure.
                if gate.enabled && label == &label_for(&gate.identity) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "current generation admission must close before removal",
                    ));
                }
                let Some(job) = state.jobs.get_mut(label) else {
                    return Ok(absent());
                };
                job.retire().await?;
                state.jobs.remove(label);
                Ok(success())
            }
        }
    }
    async fn wait_admitted(&self, label: &str) -> io::Result<()> {
        let control = self.gate()?.ok_or(io::ErrorKind::NotFound)?.control;
        let identity = {
            let state = self.state.lock().await;
            let job = state.jobs.get(label).ok_or(io::ErrorKind::NotFound)?;
            job.program.identity
        };
        timeout(CONTROL_WAIT, async {
            loop {
                if let Ok(observed) = control::inspect(&control).await {
                    assert_eq!(observed.managed, Some(identity));
                    assert!(observed.supports_stop);
                    return Ok::<(), io::Error>(());
                }
                let alive = self
                    .state
                    .lock()
                    .await
                    .jobs
                    .get_mut(label)
                    .ok_or(io::ErrorKind::NotFound)?
                    .alive()?;
                if !alive {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "real daemon exited before post-effect fault",
                    ));
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
    }
}
fn decode_installation(value: &str) -> io::Result<[u8; 16]> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut result = [0; 16];
    for (slot, text) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(text).unwrap(), 16)
            .map_err(|_| io::ErrorKind::InvalidInput)?;
    }
    if result == [0; 16] {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(result)
}
fn label_for(identity: &ManagedIdentity) -> String {
    format!(
        "{LABEL_PREFIX}{}.g{:016x}",
        hexadecimal(&identity.installation),
        identity.generation
    )
}
fn success() -> Outcome {
    Outcome::Exited {
        success: true,
        code: Some(0),
    }
}
fn absent() -> Outcome {
    Outcome::Exited {
        success: false,
        code: Some(3),
    }
}
fn already_loaded() -> Outcome {
    Outcome::Exited {
        success: false,
        code: Some(37),
    }
}
fn unknown() -> Outcome {
    Outcome::Unknown {
        reason: UnknownReason::Transport,
        child_reaped: true,
    }
}
async fn respond(response: Option<Response>) -> io::Result<bool> {
    match response {
        Some(Response::Unknown) => Ok(true),
        Some(Response::Pause(pause)) => {
            pause.arrive().await?;
            Ok(false)
        }
        None => Ok(false),
    }
}
impl Executor for Backend {
    async fn execute(&self, action: Action) -> io::Result<Outcome> {
        let prepared = self.prepare(action)?;
        self.observe(&prepared.action, false).await?;
        let kind = ActionKind::of(&prepared.action);
        {
            let mut state = self.state.lock().await;
            if kind.is_some() && state.delay_next.front().copied() == kind {
                assert!(state.delayed.len() < MAX_CONTROLS);
                state.delay_next.pop_front();
                state.delayed.push_back(prepared);
                return Ok(unknown());
            }
        }
        let points = kind.map(ActionKind::points);
        if let Some((before, _)) = points {
            if respond(self.take_rule(before).await).await? {
                return Ok(unknown());
            }
        }
        let result = self.apply(&prepared).await?;
        if result != success() {
            return Ok(result);
        }
        if let Some((_, after)) = points {
            let response = self.take_rule(after).await;
            if response.is_some()
                && matches!(kind, Some(ActionKind::Bootstrap | ActionKind::Kickstart))
            {
                self.wait_admitted(prepared.label().unwrap()).await?;
            }
            if respond(response).await? {
                return Ok(unknown());
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
#[path = "managed_backend_tests.rs"]
mod tests;
