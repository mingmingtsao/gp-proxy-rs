//! A stable local service owns one explicit authentication lifecycle at a time.
//! Passwords are one-operation inputs. Only cookie transport recovery is automatic.
use crate::{
    auth::AuthBinding,
    config::Config,
    gp::{
        GatewayClient, GpError, LoginChallenge, LoginProgress, PortalChallenge, PortalClient,
        PortalCookies, PortalProgress, Session, TunnelConfig,
    },
    lease::{Deadline, Failure as LeaseFailure, Lease},
    policy::Policy,
    proxy::Connector,
    session::{self, TunnelConnector},
    status::Reason,
};
use serde::{Deserialize, Serialize};
use std::{
    future::poll_fn,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::Poll,
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

const AUTH_TIMEOUT: Duration = Duration::from_secs(90);
const CONVERSATION_TIMEOUT: Duration = Duration::from_secs(300);
const ANSWER_TIMEOUT: Duration = Duration::from_secs(90);
const COMMIT_TIMEOUT: Duration = Duration::from_secs(3);
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServicePhase {
    Waiting,
    Authenticating,
    Active,
    Cleaning,
    Stopped,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum StartError {
    #[error("another authentication lifecycle is active")]
    Busy,
    #[error("the local service has stopped")]
    Stopped,
    #[error("authentication destinations or mode do not match the local service")]
    GatewayMismatch,
    #[error("invalid authentication input")]
    InvalidInput,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum AuthFailure {
    #[error("authentication was rejected")]
    AuthenticationRequired,
    #[error("authentication method is unsupported")]
    UnsupportedAuthentication,
    #[error("authentication requires an explicitly enabled interactive responder")]
    InteractiveRequired,
    #[error("gateway configuration was rejected")]
    ConfigurationRejected,
    #[error("gateway protocol validation failed")]
    ProtocolError,
    #[error("gateway transport is unavailable")]
    TransportUnavailable,
    #[error("authentication operation timed out")]
    TimedOut,
    #[error("authentication operation was cancelled")]
    Cancelled,
    #[error("the local service stopped")]
    Stopped,
}

impl AuthFailure {
    fn reason(self) -> Reason {
        match self {
            Self::AuthenticationRequired | Self::Cancelled => Reason::AuthenticationRequired,
            Self::UnsupportedAuthentication | Self::InteractiveRequired => {
                Reason::UnsupportedAuthentication
            }
            Self::ConfigurationRejected => Reason::ConfigurationRejected,
            Self::ProtocolError => Reason::ProtocolError,
            Self::TransportUnavailable | Self::TimedOut => Reason::TransportUnavailable,
            Self::Stopped => Reason::Stopped,
        }
    }
}

// Deliberately no Debug or Serialize: neither secrets nor input paths belong in
// diagnostics. IPC parsing is responsible for its own bounded, zeroizing frame.
pub enum AuthInput {
    Password {
        user: String,
        password: Zeroizing<String>,
        computer: String,
    },
    PortalPassword {
        portal: String,
        user: String,
        password: Zeroizing<String>,
        computer: String,
    },
    Session(Session),
}

impl AuthInput {
    fn valid(&self) -> bool {
        let field = |value: &str, max| value.len() <= max && !value.chars().any(char::is_control);
        match self {
            Self::Password {
                user,
                password,
                computer,
            }
            | Self::PortalPassword {
                user,
                password,
                computer,
                ..
            } => {
                !user.is_empty()
                    && !computer.is_empty()
                    && !password.is_empty()
                    && field(user, 8192)
                    && field(computer, 255)
                    && field(password, 8192)
            }
            Self::Session(session) => {
                !session.user.is_empty()
                    && !session.computer.is_empty()
                    && [
                        &session.user,
                        &session.portal,
                        &session.domain,
                        &session.computer,
                    ]
                    .into_iter()
                    .all(|value| field(value, 8192))
            }
        }
    }

    fn matches_binding(&self, binding: &AuthBinding) -> bool {
        match (self, binding) {
            (Self::Password { .. } | Self::Session(_), AuthBinding::Direct { .. }) => true,
            (Self::PortalPassword { portal, .. }, AuthBinding::Portal { gateway, .. }) => {
                AuthBinding::via_portal(portal, gateway)
                    .is_ok_and(|supplied| supplied.matches(binding))
            }
            _ => false,
        }
    }
}

// Share one conversation engine without erasing the protocol continuation's
// endpoint kind. A portal capability cannot be passed to gateway answer_login.
enum PasswordClient<'a> {
    Gateway(&'a GatewayClient),
    Portal(&'a PortalClient),
}

enum PasswordProgress {
    Session(Session),
    Cookies(PortalCookies),
    Challenge(PasswordChallenge),
}

enum PasswordChallenge {
    Gateway(LoginChallenge),
    Portal(PortalChallenge),
}

impl PasswordChallenge {
    fn prompt(&self) -> &str {
        match self {
            Self::Gateway(challenge) => challenge.prompt(),
            Self::Portal(challenge) => challenge.prompt(),
        }
    }
    fn round(&self) -> u8 {
        match self {
            Self::Gateway(challenge) => challenge.round(),
            Self::Portal(challenge) => challenge.round(),
        }
    }
}

impl From<LoginProgress> for PasswordProgress {
    fn from(progress: LoginProgress) -> Self {
        match progress {
            LoginProgress::Session(session) => Self::Session(session),
            LoginProgress::Challenge(challenge) => {
                Self::Challenge(PasswordChallenge::Gateway(challenge))
            }
        }
    }
}

impl From<PortalProgress> for PasswordProgress {
    fn from(progress: PortalProgress) -> Self {
        match progress {
            PortalProgress::Cookies(cookies) => Self::Cookies(cookies),
            PortalProgress::Challenge(challenge) => {
                Self::Challenge(PasswordChallenge::Portal(challenge))
            }
        }
    }
}

impl PasswordClient<'_> {
    async fn prelogin(&self) -> Result<(), GpError> {
        match self {
            Self::Gateway(client) => client.prelogin().await,
            Self::Portal(client) => client.prelogin().await,
        }
    }

    async fn begin(
        &self,
        user: &str,
        password: &str,
        computer: &str,
        before_write: impl FnOnce() -> Result<(), GpError> + Send,
    ) -> Result<PasswordProgress, GpError> {
        match self {
            Self::Gateway(client) => client
                .begin_login_guarded(user, password, computer, before_write)
                .await
                .map(Into::into),
            Self::Portal(client) => client
                .begin_login_guarded(user, password, computer, before_write)
                .await
                .map(Into::into),
        }
    }

    async fn answer(
        &self,
        challenge: PasswordChallenge,
        answer: Zeroizing<String>,
        before_write: impl FnOnce() -> Result<(), GpError> + Send,
    ) -> Result<PasswordProgress, GpError> {
        match (self, challenge) {
            (Self::Gateway(client), PasswordChallenge::Gateway(challenge)) => client
                .answer_challenge_guarded(challenge, answer, before_write)
                .await
                .map(Into::into),
            (Self::Portal(client), PasswordChallenge::Portal(challenge)) => client
                .answer_challenge_guarded(challenge, answer, before_write)
                .await
                .map(Into::into),
            _ => Err(GpError::Protocol("authentication endpoint kind mismatch")),
        }
    }
}

/// Process-lifetime totals for locally owned gateway sessions. These are not
/// proof that a gateway never issued an unseen cookie or revoked every cookie.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupSummary {
    pub known_sessions: u64,
    pub logout_confirmed: u64,
    pub logout_unconfirmed: u64,
    pub remote_outcome_unknown: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogoutOutcome {
    Confirmed,
    Unconfirmed,
}

impl CleanupSummary {
    fn logout(&mut self, outcome: LogoutOutcome) {
        let count = match outcome {
            LogoutOutcome::Confirmed => &mut self.logout_confirmed,
            LogoutOutcome::Unconfirmed => &mut self.logout_unconfirmed,
        };
        *count = count.saturating_add(1);
    }
}

struct Admission {
    phase: ServicePhase,
    stopping: bool,
    finished: Option<CleanupSummary>,
}

struct Shared {
    admission: Mutex<Admission>,
    binding: AuthBinding,
    connector: Arc<TunnelConnector>,
    shutdown: CancellationToken,
}

impl Shared {
    fn stop(&self) -> bool {
        let first = {
            let mut state = self.admission.lock().unwrap();
            let first = !state.stopping;
            state.stopping = true;
            state.phase = ServicePhase::Stopped;
            first
        };
        self.connector.disconnect();
        self.shutdown.cancel();
        first
    }
}

struct Command {
    input: AuthInput,
    lease: Lease,
    budget: Deadline,
    conversation_end: Deadline,
    interactive: bool,
    challenges: mpsc::Sender<ChallengeRequest>,
    client_cancel: CancellationToken,
    operation_cancel: CancellationToken,
    prepared: oneshot::Sender<Result<(), AuthFailure>>,
    commit: oneshot::Receiver<()>,
}

#[derive(Clone)]
pub struct ServiceHandle {
    shared: Arc<Shared>,
    commands: mpsc::Sender<Command>,
}

impl ServiceHandle {
    pub fn binding(&self) -> AuthBinding {
        self.shared.binding.clone()
    }

    pub fn phase(&self) -> ServicePhase {
        self.shared.admission.lock().unwrap().phase
    }

    /// Permanently closes admission under the same lock as authentication.
    /// The first caller returns true. Completion still requires all task joins.
    pub fn request_stop(&self) -> bool {
        self.shared.stop()
    }

    /// Published only at the normal end of the service actor's cleanup. A
    /// panic/abort never fabricates this result; the owner must also join its
    /// proxy/control/initial tasks before reporting whole-service completion.
    pub fn completion(&self) -> Option<CleanupSummary> {
        self.shared.admission.lock().unwrap().finished
    }

    /// Atomic, zero-queue admission. A successful Hello is only a hint: state
    /// and the fixed destinations and input role are checked again on submit.
    pub fn try_authenticate(
        &self,
        input: AuthInput,
        expected_gateway: &str,
        client_cancel: CancellationToken,
    ) -> Result<AuthOperation, StartError> {
        let binding =
            AuthBinding::direct(expected_gateway).map_err(|_| StartError::GatewayMismatch)?;
        self.try_authenticate_bound(input, &binding, client_cancel, false)
    }

    /// Allow this operation's caller to answer bounded, single-use challenges.
    pub fn try_authenticate_interactive(
        &self,
        input: AuthInput,
        expected_gateway: &str,
        client_cancel: CancellationToken,
    ) -> Result<AuthOperation, StartError> {
        let binding =
            AuthBinding::direct(expected_gateway).map_err(|_| StartError::GatewayMismatch)?;
        self.try_authenticate_bound(input, &binding, client_cancel, true)
    }

    pub fn try_authenticate_bound(
        &self,
        input: AuthInput,
        expected_binding: &AuthBinding,
        client_cancel: CancellationToken,
        interactive: bool,
    ) -> Result<AuthOperation, StartError> {
        if !expected_binding.matches(&self.shared.binding)
            || !input.matches_binding(&self.shared.binding)
        {
            return Err(StartError::GatewayMismatch);
        }
        if !input.valid() {
            return Err(StartError::InvalidInput);
        }
        let mut state = self.shared.admission.lock().unwrap();
        if state.stopping || self.shared.shutdown.is_cancelled() {
            return Err(StartError::Stopped);
        }
        match state.phase {
            ServicePhase::Waiting => {}
            ServicePhase::Stopped => return Err(StartError::Stopped),
            _ => return Err(StartError::Busy),
        }
        // Anchor before delivery: a scheduling pause must not make an already
        // accepted password submission fresh again when the actor resumes.
        let lease = Lease::new();
        let admitted = lease.sample().map_err(|_| StartError::Stopped)?;
        let budget = Deadline::after(admitted, AUTH_TIMEOUT).map_err(|_| StartError::Stopped)?;
        let conversation_end =
            Deadline::after(admitted, CONVERSATION_TIMEOUT).map_err(|_| StartError::Stopped)?;
        let (prepared, result) = oneshot::channel();
        let (challenges, events) = mpsc::channel(1);
        let (commit, committed) = oneshot::channel();
        let operation_cancel = CancellationToken::new();
        state.phase = ServicePhase::Authenticating;
        let command = Command {
            input,
            lease,
            budget,
            conversation_end,
            interactive,
            challenges,
            client_cancel,
            operation_cancel: operation_cancel.clone(),
            prepared,
            commit: committed,
        };
        if self.commands.try_send(command).is_err() {
            state.phase = ServicePhase::Stopped;
            state.stopping = true;
            return Err(StartError::Stopped);
        }
        Ok(AuthOperation {
            result: Some(result),
            challenges: events,
            commit: Some(commit),
            cancel: operation_cancel,
            ready: false,
            committed: false,
        })
    }
}

/// Prepared is not network availability. The caller writes its bounded
/// "accepted" response before committing; status reports subsequent readiness.
pub struct AuthOperation {
    result: Option<oneshot::Receiver<Result<(), AuthFailure>>>,
    challenges: mpsc::Receiver<ChallengeRequest>,
    commit: Option<oneshot::Sender<()>>,
    cancel: CancellationToken,
    ready: bool,
    committed: bool,
}

/// Only the admitted caller receives this prompt and its one-use responder.
/// The gateway's opaque continuation and previous secret never leave Service.
pub struct ChallengeRequest {
    prompt: String,
    round: u8,
    nonce: [u8; 16],
    lease: Lease,
    deadline: Deadline,
    answer: oneshot::Sender<Zeroizing<String>>,
}

impl ChallengeRequest {
    pub fn prompt(&self) -> &str {
        &self.prompt
    }
    pub fn round(&self) -> u8 {
        self.round
    }
    pub fn nonce(&self) -> [u8; 16] {
        self.nonce
    }
    pub fn remaining(&self) -> Result<Duration, AuthFailure> {
        let remaining = self.lease.remaining(self.deadline).map_err(clock_failure)?;
        if remaining.is_zero() {
            Err(AuthFailure::TimedOut)
        } else {
            Ok(remaining)
        }
    }
    pub fn respond(self, answer: Zeroizing<String>) -> Result<(), AuthFailure> {
        self.remaining()?;
        if answer.is_empty() || answer.len() > 8192 || answer.chars().any(char::is_control) {
            return Err(AuthFailure::ProtocolError);
        }
        self.answer.send(answer).map_err(|_| AuthFailure::Cancelled)
    }
    /// Apply the service's original dual-clock deadline to a caller-owned UI
    /// future. Dropping this future drops the one-use responder immediately.
    pub async fn respond_with(
        self,
        input: impl std::future::Future<Output = io::Result<Zeroizing<String>>>,
    ) -> Result<(), AuthFailure> {
        let answer = self
            .lease
            .run_until(Some(self.deadline), input)
            .await
            .map_err(clock_failure)?
            .map_err(|_| AuthFailure::Cancelled)?;
        self.respond(answer)
    }
}

pub enum AuthEvent {
    Challenge(ChallengeRequest),
    Prepared,
}

impl AuthOperation {
    pub async fn prepared(&mut self) -> Result<(), AuthFailure> {
        match self.next_event().await? {
            AuthEvent::Prepared => Ok(()),
            AuthEvent::Challenge(request) => {
                drop(request);
                self.cancel.cancel();
                Err(AuthFailure::InteractiveRequired)
            }
        }
    }

    /// Cancellation-safe: a competing select branch never consumes the result
    /// receiver or loses an already-published challenge.
    pub async fn next_event(&mut self) -> Result<AuthEvent, AuthFailure> {
        if self.ready {
            return Ok(AuthEvent::Prepared);
        }
        let result = self.result.as_mut().ok_or(AuthFailure::Stopped)?;
        tokio::select! {
            biased;
            result = result => {
                self.result = None;
                result.map_err(|_| AuthFailure::Stopped)??;
                self.ready = true;
                Ok(AuthEvent::Prepared)
            },
            request = self.challenges.recv() => request.map(AuthEvent::Challenge).ok_or(AuthFailure::Stopped),
        }
    }

    pub fn commit(mut self) -> Result<(), AuthFailure> {
        if !self.ready {
            return Err(AuthFailure::ProtocolError);
        }
        self.commit
            .take()
            .ok_or(AuthFailure::Stopped)?
            .send(())
            .map_err(|_| AuthFailure::Stopped)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for AuthOperation {
    fn drop(&mut self) {
        if !self.committed {
            self.cancel.cancel();
        }
    }
}

pub struct Service {
    config: Config,
    client: GatewayClient,
    portal: Option<PortalClient>,
    connector: Arc<TunnelConnector>,
    pac: watch::Sender<Arc<Policy>>,
    shutdown: CancellationToken,
    shared: Arc<Shared>,
    commands: mpsc::Receiver<Command>,
    cleanup: CleanupSummary,
}

pub fn new(
    config: Config,
    client: GatewayClient,
    connector: Arc<TunnelConnector>,
    pac: watch::Sender<Arc<Policy>>,
    shutdown: CancellationToken,
) -> io::Result<(ServiceHandle, Service)> {
    new_with_portal(config, client, None, connector, pac, shutdown)
}

pub fn new_with_portal(
    config: Config,
    client: GatewayClient,
    portal: Option<PortalClient>,
    connector: Arc<TunnelConnector>,
    pac: watch::Sender<Arc<Policy>>,
    shutdown: CancellationToken,
) -> io::Result<(ServiceHandle, Service)> {
    let binding = config.auth_binding()?;
    let gateway = Url::parse(&config.gateway)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid service gateway"))?;
    if &gateway != client.gateway() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service client gateway mismatch",
        ));
    }
    match (binding.portal_origin(), &portal) {
        (None, None) => {}
        (Some(origin), Some(portal))
            if Url::parse(origin).ok().as_ref() == Some(portal.origin())
                && &gateway == portal.fixed_gateway() => {}
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "service portal client binding mismatch",
            ));
        }
    }
    connector.reset_authentication(Some(Reason::AuthenticationRequired))?;
    let shared = Arc::new(Shared {
        admission: Mutex::new(Admission {
            phase: ServicePhase::Waiting,
            stopping: false,
            finished: None,
        }),
        binding,
        connector: connector.clone(),
        shutdown: shutdown.clone(),
    });
    let (send, commands) = mpsc::channel(1);
    Ok((
        ServiceHandle {
            shared: shared.clone(),
            commands: send,
        },
        Service {
            config,
            // Keep an unused template, even if the caller supplied a client
            // with prior traffic. It must not retain an earlier TLS session.
            client: client.for_authentication(),
            portal: portal.map(|client| client.for_authentication()),
            connector,
            pac,
            shutdown,
            shared,
            commands,
            cleanup: CleanupSummary::default(),
        },
    ))
}

impl Service {
    pub async fn run(mut self) {
        struct Stop {
            shared: Arc<Shared>,
        }
        impl Drop for Stop {
            fn drop(&mut self) {
                self.shared.stop();
            }
        }
        let _stop = Stop {
            shared: self.shared.clone(),
        };
        loop {
            let command = tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                command = self.commands.recv() => match command { Some(command) => command, None => break },
            };
            self.authenticate(command).await;
            if self.shutdown.is_cancelled() {
                break;
            }
        }
        self.shared.stop();
        {
            // An admitted command is enqueued while holding this same lock.
            // Closing it after permanent admission closure leaves at most the
            // one already-owned command, never a future sender reservation.
            let _state = self.shared.admission.lock().unwrap();
            self.commands.close();
        }
        while let Some(command) = self.commands.recv().await {
            // Passwords must never start another POST here. Imported cookies
            // were transferred at admission and still require owned cleanup.
            self.reject_accepted(command, AuthFailure::Stopped).await;
        }
        self.shared.admission.lock().unwrap().finished = Some(self.cleanup);
    }

    fn phase(&self, phase: ServicePhase) {
        let mut state = self.shared.admission.lock().unwrap();
        state.phase = if state.stopping || self.shutdown.is_cancelled() {
            ServicePhase::Stopped
        } else {
            phase
        };
    }

    fn interrupted(&self, command: &Command) -> bool {
        self.shutdown.is_cancelled()
            || command.client_cancel.is_cancelled()
            || command.operation_cancel.is_cancelled()
    }

    fn waiting(&self, reason: Reason) {
        // The previous supervisor is gone and cookie cleanup is complete.
        if self.connector.reset_authentication(Some(reason)).is_err() {
            self.shutdown.cancel();
        }
        self.phase(if self.shutdown.is_cancelled() {
            ServicePhase::Stopped
        } else {
            ServicePhase::Waiting
        });
    }

    async fn authenticate(&mut self, command: Command) {
        if self.connector.reset_authentication(None).is_err() {
            self.shutdown.cancel();
            self.connector.disconnect();
            self.reject_accepted(command, AuthFailure::Stopped).await;
            return;
        }
        // All control requests, reconnects and logout in this lifecycle share
        // one cache. A subsequent explicit authentication gets a fresh cache
        // and therefore a full certificate-verified TLS handshake.
        let client = self.client.for_authentication();
        // The portal has its own origin, trust and cache. Its per-operation
        // capability is dropped immediately after handoff, before activation.
        let portal = self.portal.as_ref().map(PortalClient::for_authentication);
        let cancelled_before_input = self.interrupted(&command);
        let Command {
            input,
            lease,
            mut budget,
            conversation_end,
            interactive,
            challenges,
            client_cancel,
            operation_cancel,
            prepared,
            mut commit,
        } = command;
        let cancelled = || {
            self.shutdown.is_cancelled()
                || client_cancel.is_cancelled()
                || operation_cancel.is_cancelled()
        };
        let observation = PostObservation::default();
        let acquired = match input {
            AuthInput::Session(session) => Ok(session),
            AuthInput::Password {
                user,
                password,
                computer,
            }
            | AuthInput::PortalPassword {
                user,
                password,
                computer,
                ..
            } => async {
                if cancelled_before_input || cancelled() {
                    return Err(AuthFailure::Cancelled);
                }
                // Admission already checked the input role against the full
                // fixed binding. Constructor validation binds this client to
                // that same immutable plan.
                let authenticator = match &portal {
                    Some(portal) => PasswordClient::Portal(portal),
                    None => PasswordClient::Gateway(&client),
                };
                // Prelogin cannot issue a Session and is promptly cancellable.
                tokio::select! {
                    biased;
                    _ = self.shutdown.cancelled() => return Err(AuthFailure::Cancelled),
                    _ = client_cancel.cancelled() => return Err(AuthFailure::Cancelled),
                    _ = operation_cancel.cancelled() => return Err(AuthFailure::Cancelled),
                    result = lease.run_until(Some(budget), authenticator.prelogin()) => result.map_err(clock_failure)?.map_err(|error| classify(&error))?,
                }
                if cancelled() { return Err(AuthFailure::Cancelled); }
                // Recheck after TLS setup, immediately before the first request
                // write. Once writing begins, finish that bounded request despite
                // cancellation, retaining any late Session for logout.
                let mut progress = acquire_session(
                    &lease, budget, &observation, authenticator.begin(
                        &user, &password, &computer,
                        || observation.admit(&lease, budget, cancelled()),
                    )
                ).await?;
                drop(password);
                drop(user);
                drop(computer);
                loop {
                    let challenge = match progress {
                        PasswordProgress::Session(session) => return Ok(session),
                        PasswordProgress::Cookies(cookies) => {
                            // Portal bearer expiry/audience are opaque. Do not
                            // renew the admission budget or start another
                            // origin after cancellation. Once the gateway POST
                            // starts, preserve a late Session for logout.
                            credential_admission(&lease, budget, cancelled())
                                .map_err(|error| classify(&error))?;
                            let portal = portal.as_ref().ok_or(AuthFailure::ProtocolError)?;
                            return acquire_session(
                                &lease, budget, &observation,
                                client.login_with_portal_cookies_guarded(
                                    cookies, portal.origin(),
                                    || observation.admit(&lease, budget, cancelled()),
                                ),
                            ).await;
                        }
                        PasswordProgress::Challenge(challenge) => challenge,
                    };
                    if cancelled() { return Err(AuthFailure::Cancelled); }
                    // A final poll may yield a Session across its budget so it
                    // can be cleaned up. A late Challenge gets no such extension.
                    if lease.until(Some(budget)).map_err(clock_failure)? {
                        return Err(AuthFailure::TimedOut);
                    }
                    if !interactive { return Err(AuthFailure::InteractiveRequired); }
                    if !(1..=4).contains(&challenge.round()) {
                        return Err(AuthFailure::ProtocolError);
                    }
                    budget = conversation_end;
                    let deadline = lease.deadline_after(ANSWER_TIMEOUT)
                        .map_err(clock_failure)?.earliest(budget);
                    let (answer, response) = oneshot::channel();
                    let request = ChallengeRequest {
                        prompt: challenge.prompt().to_owned(),
                        round: challenge.round(),
                        nonce: rand::random(),
                        lease: lease.clone(),
                        deadline,
                        answer,
                    };
                    // At most one current prompt; no response is queued for a
                    // future round. Publishing latency consumes the same budget.
                    tokio::select! {
                        biased;
                        _ = self.shutdown.cancelled() => return Err(AuthFailure::Cancelled),
                        _ = client_cancel.cancelled() => return Err(AuthFailure::Cancelled),
                        _ = operation_cancel.cancelled() => return Err(AuthFailure::Cancelled),
                        result = lease.run_until(Some(deadline), challenges.send(request)) => result.map_err(clock_failure)?.map_err(|_| AuthFailure::Cancelled)?,
                    }
                    let answer = tokio::select! {
                        biased;
                        _ = self.shutdown.cancelled() => return Err(AuthFailure::Cancelled),
                        _ = client_cancel.cancelled() => return Err(AuthFailure::Cancelled),
                        _ = operation_cancel.cancelled() => return Err(AuthFailure::Cancelled),
                        result = lease.run_until(Some(deadline), response) => result.map_err(clock_failure)?.map_err(|_| AuthFailure::Cancelled)?,
                    };
                    if cancelled() { return Err(AuthFailure::Cancelled); }
                    progress = acquire_session(
                        &lease, budget, &observation, authenticator.answer(
                            challenge, answer,
                            || observation.admit(&lease, budget, cancelled()),
                        )
                    ).await?;
                }
            }.await,
        };
        if observation.pending.load(Ordering::Relaxed) {
            self.cleanup.remote_outcome_unknown =
                self.cleanup.remote_outcome_unknown.saturating_add(1);
        }
        drop(portal);
        let session = match acquired {
            Ok(session) => session,
            Err(failure) => {
                drop(client);
                self.waiting(failure.reason());
                let _ = prepared.send(Err(failure));
                return;
            }
        };
        self.cleanup.known_sessions = self.cleanup.known_sessions.saturating_add(1);
        // Session preparation gets at most its original 90s window, also
        // clipped to the admission-anchored overall conversation deadline.
        budget = match lease.deadline_after(AUTH_TIMEOUT) {
            Ok(end) => end.earliest(budget),
            Err(_) => budget, // Existing cleanup path retains the known cookie.
        };
        let initial = if cancelled() {
            Err(AuthFailure::Cancelled)
        } else {
            // The Session is already owned, so read-only configuration work
            // can stop promptly. The retained cookie still goes through logout.
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => Err(AuthFailure::Cancelled),
                _ = client_cancel.cancelled() => Err(AuthFailure::Cancelled),
                _ = operation_cancel.cancelled() => Err(AuthFailure::Cancelled),
                result = lease.run_until(Some(budget), self.prepare(&client, &session)) => result.map_err(clock_failure).and_then(|value| value),
            }
        };
        let mut prepared = Some(prepared);
        let mut failure = None;
        let mut terminal_reason = Reason::AuthenticationRequired;
        if let Ok(initial) = initial {
            let anchor = crate::lease::Sample {
                monotonic: initial.received_at,
                wall: initial.received_wall,
            };
            let observed = lease.observe(anchor, initial.lifetime);
            if let Err(error) = observed {
                failure = Some(clock_failure(error));
            } else if cancelled() || prepared.take().unwrap().send(Ok(())).is_err() {
                failure = Some(AuthFailure::Cancelled);
            } else {
                let confirm_end = lease
                    .deadline_after(COMMIT_TIMEOUT)
                    .map(|end| end.earliest(budget));
                let confirmed = match confirm_end {
                    Err(error) => Err(clock_failure(error)),
                    Ok(end) => tokio::select! {
                        biased;
                        _ = self.shutdown.cancelled() => Err(AuthFailure::Cancelled),
                        _ = client_cancel.cancelled() => Err(AuthFailure::Cancelled),
                        _ = operation_cancel.cancelled() => Err(AuthFailure::Cancelled),
                        result = lease.run_until(Some(end), &mut commit) => result.map_err(clock_failure).and_then(|value| value.map_err(|_| AuthFailure::Cancelled)),
                    },
                };
                match confirmed {
                    Err(error) => failure = Some(error),
                    Ok(()) => {
                        self.phase(ServicePhase::Active);
                        // supervise owns its bounded Session clone and joins all
                        // generation tasks before returning. Drop it before logout.
                        let result = session::supervise(
                            self.config.clone(),
                            client.clone(),
                            session.clone(),
                            initial,
                            self.connector.clone(),
                            self.pac.clone(),
                            self.shutdown.child_token(),
                        )
                        .await;
                        terminal_reason = self.connector.status().reason;
                        if terminal_reason == Reason::None {
                            terminal_reason = result
                                .err()
                                .map(|error| classify(&error).reason())
                                .unwrap_or(Reason::Stopped);
                        }
                        if !self.shutdown.is_cancelled() {
                            tracing::warn!(
                                reason = ?terminal_reason,
                                "VPN session stopped; egress closed. Use status, then explicitly reauthenticate when cleanup completes"
                            );
                        }
                    }
                }
            }
        } else {
            failure = initial.err();
        }
        self.phase(ServicePhase::Cleaning);
        self.connector.disconnect();
        self.cleanup.logout(discard_session(&client, session).await);
        // The supervisor has joined its tasks and logout has finished. Release
        // transport credentials before advertising admission for another login.
        drop(client);
        if let Some(error) = failure {
            terminal_reason = error.reason();
        }
        self.waiting(terminal_reason);
        if let Some(prepared) = prepared {
            let _ = prepared.send(Err(failure.unwrap_or(AuthFailure::Stopped)));
        }
    }

    async fn reject_accepted(&mut self, command: Command, failure: AuthFailure) {
        if let AuthInput::Session(session) = command.input {
            self.cleanup.known_sessions = self.cleanup.known_sessions.saturating_add(1);
            self.phase(ServicePhase::Cleaning);
            let client = self.client.for_authentication();
            self.cleanup.logout(discard_session(&client, session).await);
        }
        self.waiting(failure.reason());
        let _ = command.prepared.send(Err(failure));
    }

    async fn prepare(
        &self,
        client: &GatewayClient,
        session: &Session,
    ) -> Result<TunnelConfig, AuthFailure> {
        let initial = client
            .get_config(session)
            .await
            .map_err(|error| classify(&error))?;
        let current = session::effective_policy(&self.config, &initial)
            .map_err(|_| AuthFailure::ProtocolError)?;
        let next = self
            .pac
            .borrow()
            .merge_classification(&current)
            .map_err(|_| AuthFailure::ProtocolError)?;
        let next = if let Some(history) = &self.config.pac_history {
            history
                .remember(&next)
                .map_err(|_| AuthFailure::ProtocolError)?
        } else {
            next
        };
        // Classification is conservative, not an egress capability. Once the
        // validated scope is remembered, the running PAC must retain it even
        // if the client cancels before commit. Only supervise activates a tunnel.
        self.pac.send_replace(Arc::new(next));
        Ok(initial)
    }
}

/// Consume an owned cookie after a bounded best-effort logout. Callers must
/// await this cleanup, including on initial startup failure or cancellation.
pub async fn discard_session(client: &GatewayClient, session: Session) -> LogoutOutcome {
    let lease = Lease::new();
    let confirmed = if let Ok(end) = lease.deadline_after(LOGOUT_TIMEOUT) {
        matches!(
            lease.run_until(Some(end), client.logout(&session)).await,
            Ok(Ok(()))
        )
    } else {
        false
    };
    drop(session);
    if confirmed {
        tracing::info!("gateway logout confirmed");
        LogoutOutcome::Confirmed
    } else {
        tracing::warn!("gateway logout not confirmed");
        LogoutOutcome::Unconfirmed
    }
}

fn clock_failure(failure: LeaseFailure) -> AuthFailure {
    match failure {
        LeaseFailure::Renewal => AuthFailure::TimedOut,
        LeaseFailure::Expired | LeaseFailure::ClockUncertain => AuthFailure::AuthenticationRequired,
    }
}

fn classify(error: &GpError) -> AuthFailure {
    match error {
        GpError::Cancelled => AuthFailure::Cancelled,
        GpError::Authentication | GpError::HttpStatus(401 | 403) => {
            AuthFailure::AuthenticationRequired
        }
        GpError::UnsupportedAuthentication => AuthFailure::UnsupportedAuthentication,
        GpError::ConfigurationRejected => AuthFailure::ConfigurationRejected,
        GpError::Timeout => AuthFailure::TimedOut,
        GpError::Io(_) => AuthFailure::TransportUnavailable,
        GpError::HttpStatus(code) if matches!(code, 408 | 429) || (500..600).contains(code) => {
            AuthFailure::TransportUnavailable
        }
        _ => AuthFailure::ProtocolError,
    }
}

/// The protocol owns transport setup; the service owns cancellation and clocks.
/// This synchronous gate runs after TLS setup and before any credential write.
fn credential_admission(lease: &Lease, budget: Deadline, cancelled: bool) -> Result<(), GpError> {
    if cancelled {
        return Err(GpError::Cancelled);
    }
    match lease.until(Some(budget)) {
        Ok(false) => Ok(()),
        Ok(true) | Err(LeaseFailure::Renewal) => Err(GpError::Timeout),
        Err(LeaseFailure::Expired | LeaseFailure::ClockUncertain) => Err(GpError::Authentication),
    }
}

#[derive(Default)]
struct PostObservation {
    pending: AtomicBool,
}

impl PostObservation {
    fn admit(&self, lease: &Lease, budget: Deadline, cancelled: bool) -> Result<(), GpError> {
        credential_admission(lease, budget, cancelled)?;
        // This is the actual post-TLS, pre-write gate, not an assertion that
        // bytes reached the peer. A failed/partial write may still have issued
        // a remote session, so keep the uncertainty until a valid result.
        self.pending.store(true, Ordering::Relaxed);
        Ok(())
    }
}

async fn acquire_session<T>(
    lease: &Lease,
    budget: Deadline,
    observation: &PostObservation,
    operation: impl std::future::Future<Output = Result<T, GpError>>,
) -> Result<T, AuthFailure> {
    tokio::pin!(operation);
    let acquire = poll_fn(|context| {
        if lease.until(Some(budget)).map_err(clock_failure)? {
            return Poll::Ready(Err(AuthFailure::TimedOut));
        }
        // Do not discard a Ready cookie if its final poll crossed the budget.
        operation.as_mut().poll(context).map(|result| {
            // Authentication is deliberately NOT included: the current GP
            // parser also uses it for unexpected XML roots, which cannot
            // prove that no remote session was issued.
            if result.is_ok() || matches!(&result, Err(GpError::HttpStatus(401 | 403))) {
                observation.pending.store(false, Ordering::Relaxed);
            }
            result.map_err(|error| classify(&error))
        })
    });
    tokio::select! {
        biased;
        result = lease.wait(Some(budget)) => result.map_err(clock_failure).and(Err(AuthFailure::TimedOut)),
        result = acquire => result,
    }
}

#[cfg(test)]
#[path = "../tests/support/reauth_lifecycle.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/support/challenge_lifecycle.rs"]
pub(crate) mod challenge_tests;

#[cfg(test)]
#[path = "../tests/support/portal_lifecycle.rs"]
mod portal_tests;

#[cfg(test)]
#[path = "../tests/support/auth_post_disconnect.rs"]
mod auth_post_disconnect_tests;

#[cfg(test)]
#[path = "../tests/support/service_stop.rs"]
mod stop_tests;
