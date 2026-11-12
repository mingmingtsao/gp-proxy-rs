//! One explicit operation per private, identity-checked local connection.
//! This protocol is separate from the unauthenticated HTTP proxy. It never
//! accepts configuration changes, paths to read, or queued authentication work.
use crate::{
    auth::AuthBinding,
    control_local::{self, LocalListener, LocalStream},
    service::{
        AuthEvent, AuthFailure, AuthInput, CleanupSummary, ServiceHandle, ServicePhase, StartError,
    },
};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
use std::{future::Future, io, path::Path, pin::Pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[cfg(all(
    test,
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
#[path = "../tests/support/control_managed.rs"]
mod managed_tests;

pub const PROTOCOL_VERSION: u8 = 5;
const VERSION: u8 = PROTOCOL_VERSION;
const MAX_FRAME: usize = 64 * 1024;
const HANDSHAKE: Duration = Duration::from_secs(3);
const OPERATION_WAIT: Duration = Duration::from_secs(100);
const INTERACTIVE_WAIT: Duration = Duration::from_secs(310);
const STOP_WAIT: Duration = Duration::from_secs(60);
const MAX_CLIENTS: usize = 4;

// Secret-bearing types intentionally do not implement Debug or Clone.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authentication {
    Password {
        #[serde(deserialize_with = "secret", serialize_with = "write_secret")]
        user: Zeroizing<String>,
        #[serde(deserialize_with = "secret", serialize_with = "write_secret")]
        password: Zeroizing<String>,
        computer: String,
    },
    PortalPassword {
        portal: String,
        #[serde(deserialize_with = "secret", serialize_with = "write_secret")]
        user: Zeroizing<String>,
        #[serde(deserialize_with = "secret", serialize_with = "write_secret")]
        password: Zeroizing<String>,
        computer: String,
    },
    Session {
        #[serde(deserialize_with = "secret", serialize_with = "write_secret")]
        source: Zeroizing<String>,
    },
}

fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}

fn write_secret<S: Serializer>(s: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(s)
}

impl Authentication {
    fn matches_binding(&self, binding: &AuthBinding) -> bool {
        if binding.validate().is_err() {
            return false;
        }
        match self {
            Self::Password { .. } | Self::Session { .. } => binding.portal_origin().is_none(),
            Self::PortalPassword { portal, .. } => {
                AuthBinding::via_portal(portal, binding.gateway())
                    .is_ok_and(|supplied| supplied.matches(binding))
            }
        }
    }

    fn into_input(self, binding: &AuthBinding) -> io::Result<AuthInput> {
        if !self.matches_binding(binding) {
            return Err(invalid());
        }
        let validate = |user: &str, password: &str, computer: &str| {
            computer.len() <= 255
                && [user, password, computer].iter().all(|value| {
                    !value.is_empty() && value.len() <= 8192 && !value.chars().any(char::is_control)
                })
        };
        match self {
            Self::Password {
                user,
                password,
                computer,
            } => {
                if !validate(&user, &password, &computer) {
                    return Err(invalid());
                }
                Ok(AuthInput::Password {
                    user: user.to_string(),
                    password,
                    computer,
                })
            }
            Self::PortalPassword {
                portal,
                user,
                password,
                computer,
            } => {
                if !validate(&user, &password, &computer) {
                    return Err(invalid());
                }
                Ok(AuthInput::PortalPassword {
                    portal,
                    user: user.to_string(),
                    password,
                    computer,
                })
            }
            Self::Session { source } => crate::session_file::parse(&source, binding.gateway())
                .map(AuthInput::Session)
                .map_err(|_| invalid()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    version: u8,
    instance: [u8; 16],
    challenge: [u8; 16],
    binding: AuthBinding,
    phase: ServicePhase,
    supports_stop: bool,
    #[serde(deserialize_with = "managed_identity")]
    managed: Option<crate::managed_protocol::ManagedIdentity>,
}

fn managed_identity<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<crate::managed_protocol::ManagedIdentity>, D::Error> {
    let identity = Option::<crate::managed_protocol::ManagedIdentity>::deserialize(deserializer)?;
    if let Some(identity) = &identity {
        identity.validate().map_err(serde::de::Error::custom)?;
    }
    Ok(identity)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Authenticate,
    Stop,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Submit {
    op: Operation,
    version: u8,
    instance: [u8; 16],
    challenge: [u8; 16],
    binding: AuthBinding,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    authentication: Option<Authentication>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    interactive: Option<bool>,
}

// Unlike Option's ordinary deserializer, an explicitly present null is not
// silently treated as an absent field. Stop must not carry authentication data.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StopReport {
    pub local_cleanup_complete: bool,
    pub cleanup: CleanupSummary,
}

impl StopReport {
    pub(crate) fn valid(&self) -> bool {
        let Some(known_cleaned) = self
            .cleanup
            .logout_confirmed
            .checked_add(self.cleanup.logout_unconfirmed)
        else {
            return false;
        };
        known_cleaned <= self.cleanup.known_sessions
            && (!self.local_cleanup_complete || known_cleaned == self.cleanup.known_sessions)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum StopReply {
    Stopped {
        version: u8,
        instance: [u8; 16],
        challenge: [u8; 16],
        binding: AuthBinding,
        report: StopReport,
    },
}

/// Transferred to the lifecycle coordinator before its control worker returns.
/// This owns no session and dropping it never rolls back an admitted stop.
pub struct StopResponder {
    stream: LocalStream,
    instance: [u8; 16],
    challenge: [u8; 16],
    binding: AuthBinding,
}

impl StopResponder {
    /// Call only after local work has joined and the endpoint lease is released.
    /// The separate deadline must not select the already-cancelled work token.
    pub async fn complete(mut self, report: StopReport) -> io::Result<()> {
        if !report.valid() {
            return Err(invalid());
        }
        let reply = StopReply::Stopped {
            version: VERSION,
            instance: self.instance,
            challenge: self.challenge,
            binding: self.binding,
            report,
        };
        timed(HANDSHAKE, write_frame(&mut self.stream, &reply)).await
    }
}

pub type StopSender = mpsc::Sender<StopResponder>;
pub type StopReceiver = mpsc::Receiver<StopResponder>;

pub fn stop_channel() -> (StopSender, StopReceiver) {
    mpsc::channel(1)
}

/// Public nonsecret identity for explicit maintenance of a busy service.
#[derive(Clone, Debug)]
pub struct ControlIdentity {
    pub instance: [u8; 16],
    pub binding: AuthBinding,
    pub phase: ServicePhase,
    pub supports_stop: bool,
    /// Present only after this process acquired and retained managed runtime admission.
    pub managed: Option<crate::managed_protocol::ManagedIdentity>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Respond {
    version: u8,
    instance: [u8; 16],
    challenge: [u8; 16],
    round: u8,
    round_nonce: [u8; 16],
    #[serde(deserialize_with = "secret", serialize_with = "write_secret")]
    answer: Zeroizing<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum Reply {
    Accepted {},
    Rejected {
        reason: StartError,
    },
    Failed {
        reason: AuthFailure,
    },
    Challenge {
        prompt: String,
        round: u8,
        round_nonce: [u8; 16],
        remaining_ms: u32,
    },
}

/// Sanitized display text for the current round, never a gateway continuation.
pub struct ChallengePrompt {
    prompt: String,
    round: u8,
}

impl ChallengePrompt {
    pub fn prompt(&self) -> &str {
        &self.prompt
    }
    pub fn round(&self) -> u8 {
        self.round
    }
}

/// A UI future must be cancellation-safe; input threads cannot be cancelled by
/// dropping their join handle. The control client enforces all time budgets.
pub trait ChallengeHandler {
    fn respond(
        &mut self,
        prompt: ChallengePrompt,
    ) -> Pin<Box<dyn Future<Output = io::Result<Zeroizing<String>>> + Send + '_>>;
}

/// Nonsecret preflight identity, retained while the short-lived CLI prompts.
/// The connection itself is closed so a slow user does not occupy a server slot.
pub struct Preflight {
    instance: [u8; 16],
    binding: AuthBinding,
}

impl Preflight {
    pub fn gateway(&self) -> &str {
        self.binding.gateway()
    }
    pub fn binding(&self) -> &AuthBinding {
        &self.binding
    }
    pub fn matches_binding(&self, binding: &AuthBinding) -> bool {
        self.binding.matches(binding)
    }
    /// Compatibility helper for direct mode only; portal identity cannot be reduced to a gateway.
    pub fn matches_gateway(&self, gateway: &str) -> bool {
        AuthBinding::direct(gateway).is_ok_and(|binding| self.matches_binding(&binding))
    }
}

#[cfg(test)]
fn same_gateway(a: &str, b: &str) -> bool {
    match (AuthBinding::direct(a), AuthBinding::direct(b)) {
        (Ok(a), Ok(b)) => a.matches(&b),
        _ => false,
    }
}

pub async fn preflight(directory: &Path) -> io::Result<Preflight> {
    timed(HANDSHAKE, async {
        let mut connection = control_local::connect(directory).await?;
        let hello: Hello = read_frame(&mut connection.stream).await?;
        validate_hello(&hello, connection.instance_id)?;
        Ok(Preflight {
            instance: hello.instance,
            binding: hello.binding,
        })
    })
    .await
}

fn validate_identity(hello: &Hello, instance: [u8; 16]) -> io::Result<()> {
    if hello.version != VERSION
        || hello.instance != instance
        || hello.binding.validate().is_err()
        || hello
            .managed
            .as_ref()
            .is_some_and(|identity| identity.validate().is_err())
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_hello(hello: &Hello, instance: [u8; 16]) -> io::Result<()> {
    validate_identity(hello, instance)?;
    match hello.phase {
        ServicePhase::Waiting => Ok(()),
        ServicePhase::Stopped => Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "local service is stopping",
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "local service is busy; no credentials submitted",
        )),
    }
}

pub async fn inspect(directory: &Path) -> io::Result<ControlIdentity> {
    timed(HANDSHAKE, async {
        let mut connection = control_local::connect(directory).await?;
        let hello: Hello = read_frame(&mut connection.stream).await?;
        validate_identity(&hello, connection.instance_id)?;
        Ok(ControlIdentity {
            instance: hello.instance,
            binding: hello.binding,
            phase: hello.phase,
            supports_stop: hello.supports_stop,
            managed: hello.managed,
        })
    })
    .await
}

fn stop_unobserved() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "local stop completion was not observed",
    )
}

/// Submit one stop on one verified connection. An error after submission does
/// not cancel stopping and must not be replaced with a signal or inferred success.
pub async fn stop(
    directory: &Path,
    binding: &AuthBinding,
    expected_instance: Option<[u8; 16]>,
) -> io::Result<StopReport> {
    stop_with_connection(
        control_local::connect(directory),
        binding,
        expected_instance,
    )
    .await
}

async fn stop_with_connection(
    connection: impl Future<Output = io::Result<control_local::LocalConnection>>,
    binding: &AuthBinding,
    expected_instance: Option<[u8; 16]>,
) -> io::Result<StopReport> {
    binding.validate()?;
    let lease = crate::lease::Lease::new();
    let deadline = lease
        .deadline_after(STOP_WAIT)
        .map_err(|_| stop_unobserved())?;
    lease
        .run_until(Some(deadline), async {
            let (mut stream, instance, challenge) = timed(HANDSHAKE, async {
                let mut connection = connection.await?;
                let hello: Hello = read_frame(&mut connection.stream).await?;
                validate_identity(&hello, connection.instance_id)?;
                if !binding.matches(&hello.binding)
                    || expected_instance.is_some_and(|expected| expected != hello.instance)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "local service identity differs; stop not submitted",
                    ));
                }
                if !hello.supports_stop {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "local service does not support stopping",
                    ));
                }
                let submit = Submit {
                    op: Operation::Stop,
                    version: VERSION,
                    instance: hello.instance,
                    challenge: hello.challenge,
                    binding: binding.clone(),
                    authentication: None,
                    interactive: None,
                };
                write_frame(&mut connection.stream, &submit)
                    .await
                    .map_err(|_| stop_unobserved())?;
                Ok((connection.stream, hello.instance, hello.challenge))
            })
            .await
            .map_err(|error| {
                if error.kind() == io::ErrorKind::TimedOut {
                    stop_unobserved()
                } else {
                    error
                }
            })?;
            let StopReply::Stopped {
                version,
                instance: observed_instance,
                challenge: observed_challenge,
                binding: observed_binding,
                report,
            } = read_delimited_frame(&mut stream)
                .await
                .map_err(|_| stop_unobserved())?;
            if version != VERSION
                || instance != observed_instance
                || challenge != observed_challenge
                || !binding.matches(&observed_binding)
                || !report.valid()
            {
                return Err(stop_unobserved());
            }
            Ok(report)
        })
        .await
        .map_err(|_| stop_unobserved())?
}

/// Submit once. An error after sending means the outcome may be unknown; callers
/// must inspect status and must never replay automatically.
pub async fn authenticate(
    directory: &Path,
    preflight: Preflight,
    authentication: Authentication,
) -> io::Result<()> {
    authenticate_inner(directory, preflight, authentication, None).await
}

pub async fn authenticate_interactive(
    directory: &Path,
    preflight: Preflight,
    authentication: Authentication,
    handler: &mut (dyn ChallengeHandler + Send),
) -> io::Result<()> {
    authenticate_inner(directory, preflight, authentication, Some(handler)).await
}

async fn authenticate_inner(
    directory: &Path,
    preflight: Preflight,
    authentication: Authentication,
    mut handler: Option<&mut (dyn ChallengeHandler + Send)>,
) -> io::Result<()> {
    if !authentication.matches_binding(&preflight.binding) {
        return Err(invalid());
    }
    let interactive = handler.is_some();
    let lease = crate::lease::Lease::new();
    let elapsed = || {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "authentication conversation timed out",
        )
    };
    let total = lease
        .deadline_after(if interactive {
            INTERACTIVE_WAIT
        } else {
            OPERATION_WAIT
        })
        .map_err(|_| elapsed())?;
    let (stream, identity) = timed(HANDSHAKE, async {
        let mut connection = control_local::connect(directory).await?;
        let hello: Hello = read_frame(&mut connection.stream).await?;
        validate_hello(&hello, connection.instance_id)?;
        if hello.instance != preflight.instance || !preflight.matches_binding(&hello.binding) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local service changed; credentials not submitted",
            ));
        }
        let identity = (hello.instance, hello.challenge);
        let submit = Submit {
            op: Operation::Authenticate,
            version: VERSION,
            instance: hello.instance,
            challenge: hello.challenge,
            binding: preflight.binding,
            authentication: Some(authentication),
            interactive: Some(interactive),
        };
        write_frame(&mut connection.stream, &submit).await?;
        Ok((connection.stream, identity))
    })
    .await?;
    let (mut read, mut write) = tokio::io::split(stream);
    let mut nonces = Vec::with_capacity(4);
    loop {
        let reply: Reply = lease
            .run_until(Some(total), read_delimited_frame(&mut read))
            .await
            .map_err(|_| elapsed())??;
        match reply {
            Reply::Accepted {} => return Ok(()),
            Reply::Rejected { reason } => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("authentication not started ({reason:?})"),
                ))
            }
            Reply::Failed { reason } => {
                return Err(io::Error::other(format!(
                    "authentication failed ({reason:?})"
                )))
            }
            Reply::Challenge {
                prompt,
                round,
                round_nonce,
                remaining_ms,
            } => {
                if handler.is_none()
                    || !valid_prompt(&prompt)
                    || !(1..=4).contains(&round)
                    || usize::from(round) != nonces.len() + 1
                    || nonces.contains(&round_nonce)
                    || !(1..=90_000).contains(&remaining_ms)
                {
                    return Err(invalid());
                }
                nonces.push(round_nonce);
                let deadline = lease
                    .deadline_after(Duration::from_millis(u64::from(remaining_ms)))
                    .map_err(|_| elapsed())?
                    .earliest(total);
                let mut extra = [0; 1];
                let answer = tokio::select! {
                    biased;
                    _ = read.read(&mut extra) => return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "authentication conversation ended during user input",
                    )),
                    result = lease.run_until(Some(deadline), handler.as_deref_mut().unwrap().respond(ChallengePrompt { prompt, round })) => result.map_err(|_| elapsed())??,
                };
                if answer.is_empty() || answer.len() > 8192 || answer.chars().any(char::is_control)
                {
                    return Err(invalid());
                }
                let response = Respond {
                    version: VERSION,
                    instance: identity.0,
                    challenge: identity.1,
                    round,
                    round_nonce,
                    answer,
                };
                let write_end = lease
                    .deadline_after(HANDSHAKE)
                    .map_err(|_| elapsed())?
                    .earliest(deadline);
                tokio::select! {
                    biased;
                    _ = read.read(&mut extra) => return Err(invalid()),
                    result = lease.run_until(Some(write_end), write_frame(&mut write, &response)) => result.map_err(|_| elapsed())??,
                }
            }
        }
    }
}

fn valid_prompt(prompt: &str) -> bool {
    !prompt.is_empty() && prompt.len() <= 2048 && !prompt.chars().any(|c| {
        c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    })
}

/// Bounded accept/task ownership. No background task survives this future.
pub async fn serve(
    listener: LocalListener,
    gateway: String,
    service: ServiceHandle,
    shutdown: CancellationToken,
) -> io::Result<()> {
    serve_inner(listener, gateway, service, shutdown, None).await
}

pub async fn serve_managed(
    listener: LocalListener,
    gateway: String,
    service: ServiceHandle,
    shutdown: CancellationToken,
    stop: StopSender,
) -> io::Result<()> {
    serve_inner(listener, gateway, service, shutdown, Some(stop)).await
}

async fn serve_inner(
    listener: LocalListener,
    gateway: String,
    service: ServiceHandle,
    shutdown: CancellationToken,
    stop: Option<StopSender>,
) -> io::Result<()> {
    let binding = service.binding();
    binding.validate()?;
    if AuthBinding::direct(&gateway)?.gateway() != binding.gateway() {
        return Err(invalid());
    }
    let mut tasks = JoinSet::new();
    let mut failure = None;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            result = tasks.join_next(), if !tasks.is_empty() => {
                if result.is_some_and(|r| r.is_err()) {
                    failure = Some(io::Error::other("local control task failed"));
                    break;
                }
            },
            stream = listener.accept() => match stream {
                Ok(stream) if tasks.len() < MAX_CLIENTS => {
                    let hello = Hello {
                        version: VERSION, instance: listener.instance_id(),
                        challenge: rand::random(), binding: binding.clone(), phase: service.phase(),
                        supports_stop: stop.is_some(),
                        managed: crate::managed_runtime::current_identity(),
                    };
                    let service = service.clone();
                    let shutdown = shutdown.clone();
                    let stop = stop.clone();
                    tasks.spawn(async move { let _ = handle(stream, hello, service, shutdown, stop).await; });
                },
                Ok(_) => {}, // Drop immediately; no task, queue, or credential read.
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {},
                    }
                },
                Err(_) => { failure = Some(io::Error::other("local control listener failed")); break; }
            }
        }
    }
    shutdown.cancel();
    // Workers observe cancellation, drop their operation handle, and let the
    // service finish bounded login/logout. They never abort an in-flight login.
    while let Some(result) = tasks.join_next().await {
        if result.is_err() {
            failure = Some(io::Error::other("local control task failed"));
        }
    }
    failure.map_or(Ok(()), Err)
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut stream: S,
    hello: Hello,
    service: ServiceHandle,
    shutdown: CancellationToken,
    stop: Option<StopSender>,
) -> io::Result<()> {
    let submit: Submit = tokio::select! {
        biased;
        _ = shutdown.cancelled() => return Ok(()),
        result = timed(HANDSHAKE, async {
            write_frame(&mut stream, &hello).await?;
            read_frame(&mut stream).await
        }) => result?,
    };
    if submit.version != VERSION
        || submit.instance != hello.instance
        || submit.challenge != hello.challenge
        || !submit.binding.matches(&hello.binding)
    {
        return Err(invalid());
    }
    match submit.op {
        Operation::Stop => {
            if !hello.supports_stop
                || submit.authentication.is_some()
                || submit.interactive.is_some()
            {
                return Err(invalid());
            }
            // Extra buffered bytes and EOF are rejected before the irrevocable
            // admission point. Later disconnects only lose the final receipt.
            reject_buffered(&mut stream).await?;
            let permit = stop.ok_or_else(invalid)?.try_reserve_owned().map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "stop request not admitted")
            })?;
            if !service.request_stop() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "local service is already stopping",
                ));
            }
            // There is deliberately no await between closing admission and
            // handing off the responder. Main can join this worker first.
            permit.send(StopResponder {
                stream: Box::new(stream),
                instance: hello.instance,
                challenge: hello.challenge,
                binding: hello.binding,
            });
            return Ok(());
        }
        Operation::Authenticate => {}
    }
    let interactive = submit.interactive.ok_or_else(invalid)?;
    let input = submit
        .authentication
        .ok_or_else(invalid)?
        .into_input(&hello.binding)?;
    let cancelled = CancellationToken::new();
    let admission =
        service.try_authenticate_bound(input, &hello.binding, cancelled.clone(), interactive);
    let mut operation = match admission {
        Ok(operation) => operation,
        Err(reason) => {
            return timed(
                HANDSHAKE,
                write_frame(&mut stream, &Reply::Rejected { reason }),
            )
            .await
        }
    };
    let (mut read, mut write) = tokio::io::split(stream);
    let mut extra = [0u8; 1];
    loop {
        let event = tokio::select! {
            biased;
            _ = shutdown.cancelled() => { cancelled.cancel(); return Ok(()); },
            _ = read.read(&mut extra) => { cancelled.cancel(); return Err(invalid()); },
            result = operation.next_event() => result,
        };
        match event {
            Err(reason) => {
                let reply = Reply::Failed { reason };
                return tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => Ok(()),
                    result = timed(HANDSHAKE, write_frame(&mut write, &reply)) => result,
                };
            }
            Ok(AuthEvent::Prepared) => break,
            Ok(AuthEvent::Challenge(request)) => {
                if !interactive || !valid_prompt(request.prompt()) {
                    return Err(invalid());
                }
                let remaining = request.remaining().map_err(|_| expired_prompt())?;
                let remaining_ms = u32::try_from(remaining.as_millis()).map_err(|_| invalid())?;
                if !(1..=90_000).contains(&remaining_ms) {
                    return Err(expired_prompt());
                }
                let round = request.round();
                let round_nonce = request.nonce();
                let reply = Reply::Challenge {
                    prompt: request.prompt().to_owned(),
                    round,
                    round_nonce,
                    remaining_ms,
                };
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => return Ok(()),
                    _ = read.read(&mut extra) => return Err(invalid()),
                    result = timed(HANDSHAKE.min(remaining), write_frame(&mut write, &reply)) => result?,
                }
                let remaining = request.remaining().map_err(|_| expired_prompt())?;
                let response: Respond = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => return Ok(()),
                    result = timed(remaining, read_delimited_frame(&mut read)) => result?,
                };
                if response.version != VERSION
                    || response.instance != hello.instance
                    || response.challenge != hello.challenge
                    || response.round != round
                    || response.round_nonce != round_nonce
                {
                    return Err(invalid());
                }
                // Reject already-buffered pipelined bytes before handing the
                // answer to the actor. Later arrivals cancel the in-flight round
                // through the next loop's monitor, with late-cookie cleanup.
                reject_buffered(&mut read).await?;
                request.respond(response.answer).map_err(|_| invalid())?;
            }
        }
    }
    // This is a server-side commit point, not a claim of client receipt or of
    // tunnel availability. The CLI must query status before using the tunnel.
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => { cancelled.cancel(); return Ok(()); },
        _ = read.read(&mut extra) => { cancelled.cancel(); return Err(invalid()); },
        result = timed(HANDSHAKE, write_frame(&mut write, &Reply::Accepted {})) => result?,
    }
    operation
        .commit()
        .map_err(|_| io::Error::other("authentication commit did not complete"))
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid local control message")
}

fn expired_prompt() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "authentication prompt expired")
}

async fn reject_buffered<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<()> {
    let mut byte = [0; 1];
    std::future::poll_fn(|cx| {
        let mut buffer = tokio::io::ReadBuf::new(&mut byte);
        use std::task::Poll;
        match Pin::new(&mut *stream).poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Ready(Ok(())),
            // Both EOF and extra protocol bytes terminate this operation.
            Poll::Ready(Ok(())) => Poll::Ready(Err(invalid())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    })
    .await
}

async fn timed<T>(
    duration: Duration,
    work: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let lease = crate::lease::Lease::new();
    let elapsed = || io::Error::new(io::ErrorKind::TimedOut, "local control operation timed out");
    let deadline = lease.deadline_after(duration).map_err(|_| elapsed())?;
    lease
        .run_until(Some(deadline), work)
        .await
        .map_err(|_| elapsed())?
}

async fn read_frame<T: DeserializeOwned, S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<T> {
    let first = stream.read_u8().await?;
    read_frame_after_first(stream, first).await
}

/// Thinking/network latency is bounded by the caller's overall deadline, but
/// the first byte starts a separate three-second complete-frame budget.
async fn read_delimited_frame<T: DeserializeOwned, S: AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<T> {
    let first = stream.read_u8().await?;
    timed(HANDSHAKE, read_frame_after_first(stream, first)).await
}

async fn read_frame_after_first<T: DeserializeOwned, S: AsyncRead + Unpin>(
    stream: &mut S,
    first: u8,
) -> io::Result<T> {
    let mut header = [first, 0, 0, 0];
    stream.read_exact(&mut header[1..]).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

#[cfg(all(
    test,
    any(target_os = "macos", target_os = "linux"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "../tests/support/control_pool.rs"]
mod control_pool_tests;

async fn write_frame<T: Serialize, S: AsyncWrite + Unpin>(
    stream: &mut S,
    value: &T,
) -> io::Result<()> {
    // Reserve the hard ceiling once: growing a secret-bearing Vec could free
    // old allocations before its final Zeroizing owner has a chance to wipe them.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_FRAME));
    struct Bounded<'a>(&'a mut Vec<u8>);
    impl io::Write for Bounded<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > MAX_FRAME.saturating_sub(self.0.len()) {
                return Err(invalid());
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Bounded(&mut bytes), value).map_err(|_| invalid())?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(invalid());
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

#[cfg(test)]
#[path = "../tests/support/control_stop.rs"]
mod stop_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    pub(super) fn fixture() -> (ServiceHandle, crate::service::Service, Hello) {
        let config = crate::config::Config {
            gateway: "https://vpn.example.test".into(),
            domains: vec!["corp.example.test".into()],
            ..Default::default()
        };
        let client = crate::gp::GatewayClient::new(
            url::Url::parse(&config.gateway).unwrap(),
            crate::tls::client_config(None).unwrap(),
            crate::gp::ResumptionPolicy::Memory {
                tls12: rustls::client::Tls12Resumption::SessionIdOrTickets,
            },
        )
        .unwrap();
        let policy = crate::policy::Policy::new(config.domains.clone(), vec![]).unwrap();
        let (pac, _) = tokio::sync::watch::channel(std::sync::Arc::new(policy));
        let (handle, service) = crate::service::new(
            config,
            client,
            std::sync::Arc::new(crate::session::TunnelConnector::default()),
            pac,
            CancellationToken::new(),
        )
        .unwrap();
        let hello = Hello {
            version: VERSION,
            instance: [1; 16],
            challenge: [2; 16],
            binding: AuthBinding::direct("https://vpn.example.test").unwrap(),
            phase: ServicePhase::Waiting,
            supports_stop: false,
            managed: None,
        };
        (handle, service, hello)
    }

    pub(super) fn input() -> Authentication {
        Authentication::Password {
            user: Zeroizing::new("synthetic-user".into()),
            password: Zeroizing::new("synthetic-password".into()),
            computer: "test".into(),
        }
    }

    #[test]
    fn authentication_roles_cannot_be_reduced_to_the_same_gateway() {
        let direct = AuthBinding::direct("https://vpn.example.test").unwrap();
        let portal =
            AuthBinding::via_portal("https://portal.example.test:7443", direct.gateway()).unwrap();
        assert!(input().into_input(&portal).is_err());
        assert!(Authentication::Session {
            source: Zeroizing::new("not-read-as-a-session".into())
        }
        .into_input(&portal)
        .is_err());
        let portal_input = |origin: &str| Authentication::PortalPassword {
            portal: origin.into(),
            user: Zeroizing::new("user".into()),
            password: Zeroizing::new("synthetic-secret".into()),
            computer: "test".into(),
        };
        assert!(portal_input("https://portal.example.test:7443")
            .into_input(&direct)
            .is_err());
        assert!(portal_input("https://portal.example.test:7444")
            .into_input(&portal)
            .is_err());
        assert!(matches!(
            portal_input("https://portal.example.test:7443").into_input(&portal),
            Ok(AuthInput::PortalPassword { .. })
        ));
        let preflight = Preflight {
            instance: [1; 16],
            binding: portal,
        };
        assert!(!preflight.matches_gateway(direct.gateway()));
        assert!(preflight.matches_binding(preflight.binding()));
    }

    #[tokio::test]
    async fn invalid_submit_never_enters_service_admission() {
        for field in 0..9 {
            let (service, _actor, hello) = fixture();
            let (mut client, server) = tokio::io::duplex(128 * 1024);
            let worker = tokio::spawn(handle(
                server,
                hello,
                service.clone(),
                CancellationToken::new(),
                None,
            ));
            let hello: Hello = read_frame(&mut client).await.unwrap();
            let mut submit = Submit {
                op: Operation::Authenticate,
                version: VERSION,
                instance: hello.instance,
                challenge: hello.challenge,
                binding: hello.binding,
                authentication: Some(input()),
                interactive: Some(false),
            };
            match field {
                0 => submit.version += 1,
                1 => submit.instance = [9; 16],
                2 => submit.challenge = [9; 16],
                3 => submit.binding = AuthBinding::direct("https://other.example.test").unwrap(),
                4 => {
                    submit.binding = AuthBinding::Direct {
                        gateway: "https://user:synthetic-secret@vpn.example.test".into(),
                    }
                }
                5 => {
                    submit.authentication = Some(Authentication::Session {
                        source: Zeroizing::new("{\"authcookie\":\"synthetic-secret\"}".into()),
                    })
                }
                7 => {
                    submit.binding = AuthBinding::via_portal(
                        "https://portal.example.test",
                        submit.binding.gateway(),
                    )
                    .unwrap()
                }
                8 => {
                    submit.authentication = Some(Authentication::PortalPassword {
                        portal: "https://portal.example.test".into(),
                        user: Zeroizing::new("user".into()),
                        password: Zeroizing::new("synthetic-secret".into()),
                        computer: "test".into(),
                    })
                }
                _ => {
                    submit.authentication = Some(Authentication::Password {
                        user: Zeroizing::new("user".into()),
                        password: Zeroizing::new("\nsynthetic-secret".into()),
                        computer: "test".into(),
                    })
                }
            }
            write_frame(&mut client, &submit).await.unwrap();
            let error = timeout(Duration::from_secs(1), worker)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert!(!error.to_string().contains("synthetic-secret"));
            assert_eq!(service.phase(), ServicePhase::Waiting);
        }
    }

    #[tokio::test]
    async fn stale_ready_hello_cannot_queue_a_second_authentication() {
        let (service, _actor, hello) = fixture();
        let held = service
            .try_authenticate(
                input().into_input(&hello.binding).unwrap(),
                hello.binding.gateway(),
                CancellationToken::new(),
            )
            .unwrap();
        let (mut client, server) = tokio::io::duplex(128 * 1024);
        let worker = tokio::spawn(handle(
            server,
            hello,
            service.clone(),
            CancellationToken::new(),
            None,
        ));
        let hello: Hello = read_frame(&mut client).await.unwrap();
        write_frame(
            &mut client,
            &Submit {
                op: Operation::Authenticate,
                version: VERSION,
                instance: hello.instance,
                challenge: hello.challenge,
                binding: hello.binding,
                authentication: Some(input()),
                interactive: Some(false),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_frame::<Reply, _>(&mut client).await.unwrap(),
            Reply::Rejected {
                reason: StartError::Busy
            }
        ));
        worker.await.unwrap().unwrap();
        assert_eq!(service.phase(), ServicePhase::Authenticating);
        drop(held);
    }

    #[tokio::test(start_paused = true)]
    async fn partial_submit_deadline_does_not_admit_an_operation() {
        let (service, _actor, hello) = fixture();
        let (mut client, server) = tokio::io::duplex(1024);
        let worker = tokio::spawn(handle(
            server,
            hello,
            service.clone(),
            CancellationToken::new(),
            None,
        ));
        let _: Hello = read_frame(&mut client).await.unwrap();
        client.write_u32(100).await.unwrap();
        client.write_all(b"{").await.unwrap();
        assert_eq!(
            worker.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(service.phase(), ServicePhase::Waiting);
    }

    #[tokio::test]
    async fn serialization_limit_sends_no_partial_secret_frame() {
        let source = Authentication::Session {
            source: Zeroizing::new("\"".repeat(MAX_FRAME)),
        };
        let mut output = Vec::new();
        assert!(write_frame(&mut output, &source).await.is_err());
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn framing_rejects_oversize_partial_duplicate_unknown_and_trailing_json() {
        for body in [
            br#"{"result":"accepted","result":"accepted"}"#.as_slice(),
            br#"{"result":"accepted","unknown":"synthetic-secret"}"#,
            br#"{"result":"accepted"}{}"#,
            b"not-json-synthetic-secret",
        ] {
            let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
            bytes.extend_from_slice(body);
            let error = read_frame::<Reply, _>(&mut bytes.as_slice())
                .await
                .err()
                .unwrap();
            assert!(!error.to_string().contains("synthetic-secret"));
        }
        for length in [0, MAX_FRAME + 1, u32::MAX as usize] {
            let header = (length as u32).to_be_bytes();
            assert!(read_frame::<Reply, _>(&mut header.as_slice())
                .await
                .is_err());
        }
        let partial = [0, 0, 0, 9, b'{'];
        assert!(read_frame::<Reply, _>(&mut partial.as_slice())
            .await
            .is_err());
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &Reply::Accepted {}).await.unwrap();
        assert!(matches!(
            read_frame::<Reply, _>(&mut bytes.as_slice()).await.unwrap(),
            Reply::Accepted {}
        ));
    }

    #[test]
    fn origin_and_input_validation_precede_authentication() {
        assert!(same_gateway(
            "https://vpn.example:443",
            "https://vpn.example/"
        ));
        for value in [
            "http://vpn.example",
            "https://vpn.example/path",
            "https://u:p@vpn.example",
            "https://vpn.example?secret",
            "https://vpn.example:0",
            "https://other.example",
        ] {
            assert!(!same_gateway("https://vpn.example", value));
        }
        for password in [String::new(), "x\nsecret".into(), "x".repeat(8193)] {
            assert!(Authentication::Password {
                user: Zeroizing::new("user".into()),
                password: Zeroizing::new(password),
                computer: "test".into()
            }
            .into_input(&AuthBinding::direct("https://vpn.example").unwrap())
            .is_err());
        }
    }
}
