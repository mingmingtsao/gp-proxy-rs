//! Session generations are capabilities: an old handle can never enter a new tunnel.
use crate::{
    config::Config,
    dns::Resolver,
    gp::{self, Frame, GatewayClient, GpError, HipStatus, Session, TunnelConfig},
    lease::{Deadline, Failure as LeaseFailure, GuardedIo, Lease, Sample},
    policy::Policy,
    proxy::{BoxStream, ConnectFuture, Connector, Target},
    stack::{self, StackConfig, StackHandle},
    status::{Phase, Reason, Snapshot},
};
use futures_util::stream::{FuturesUnordered, StreamExt};
#[cfg(test)]
use std::future::pending;
use std::{
    collections::VecDeque,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
    time::Duration,
};
#[cfg(test)]
use tokio::time::timeout;
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream},
    sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

struct Generation {
    stack: StackHandle,
    dial_hedges: Arc<Semaphore>,
    resolver: Resolver,
    policy: Policy,
    address: Ipv4Addr,
    cancel: CancellationToken,
    lease: Lease,
    renew_at: Option<Deadline>,
}

#[derive(Default)]
pub struct TunnelConnector {
    state: RwLock<ConnectorState>,
}

struct ConnectorState {
    current: Option<Arc<Generation>>,
    phase: Phase,
    reason: Reason,
    retry_count: u64,
    lease: Option<Lease>,
}

impl Default for ConnectorState {
    fn default() -> Self {
        Self {
            current: None,
            phase: Phase::Connecting,
            reason: Reason::None,
            retry_count: 0,
            lease: None,
        }
    }
}

impl TunnelConnector {
    /// Only the service owner calls this after the preceding supervisor has
    /// returned and its logout/credential cleanup has finished.
    pub(crate) fn reset_authentication(&self, reason: Option<Reason>) -> io::Result<()> {
        let mut state = self.state.write().unwrap();
        if state.current.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a VPN generation still owns the connector",
            ));
        }
        state.lease = None;
        state.phase = if reason.is_some() {
            Phase::Stopped
        } else {
            Phase::Connecting
        };
        state.reason = reason.unwrap_or(Reason::None);
        // retry_count is a service-lifetime diagnostic, not login state.
        Ok(())
    }

    pub fn disconnect(&self) {
        self.stop_with_reason(None);
    }
    fn stop_with_reason(&self, reason: Option<Reason>) {
        let mut state = self.state.write().unwrap();
        if let Some(reason) = reason {
            state.reason = reason;
        }
        if let Some(reason) = state.lease.as_ref().and_then(lease_reason) {
            state.reason = reason;
        }
        if let Some(old) = state.current.take() {
            old.cancel.cancel();
        }
        state.phase = Phase::Stopped;
        // Supervisor cleanup, its drop guard and main's final disconnect may
        // all run. A generic cleanup must not erase a known terminal reason.
        if state.reason == Reason::None {
            state.reason = Reason::Stopped;
        }
    }
    fn activate(&self, generation: Generation) {
        let mut state = self.state.write().unwrap();
        if let Some(old) = state.current.take() {
            old.cancel.cancel();
        }
        state.lease = Some(generation.lease.clone());
        state.current = Some(Arc::new(generation));
        state.phase = Phase::Connected;
        state.reason = Reason::None;
    }
    fn connecting(&self) {
        let mut state = self.state.write().unwrap();
        state.phase = Phase::Connecting;
        if state.reason == Reason::Stopped {
            state.reason = Reason::None;
        }
    }
    fn retry_wait(&self) {
        let mut state = self.state.write().unwrap();
        state.phase = Phase::RetryWait;
        state.reason = Reason::TransportUnavailable;
        state.retry_count = state.retry_count.saturating_add(1);
    }
    fn observe_expiry(&self, lease: Lease) {
        self.state.write().unwrap().lease = Some(lease);
    }
}

impl Connector for TunnelConnector {
    fn status(&self) -> Snapshot {
        let state = self.state.read().unwrap();
        let logs = crate::logging::snapshot();
        let mut snapshot = Snapshot {
            phase: state.phase,
            reason: state.reason,
            retry_count: state.retry_count,
            dropped_log_records: logs.dropped,
            log_truncations: logs.truncated,
            log_write_errors: logs.write_errors,
            ..Snapshot::default()
        };
        if let Some(generation) = &state.current {
            let stats = generation.stack.stats();
            snapshot.active_tcp = stats.active_tcp;
            snapshot.pending_tcp = stats.pending_tcp;
            snapshot.active_udp = stats.active_udp;
            snapshot.closing_tcp = stats.time_wait;
            snapshot.command_queue = stats.command_queue;
            snapshot.incoming_packets = stats.incoming_queue;
            snapshot.outgoing_packets = stats.outgoing_queue;
            // Cancellation may precede the supervisor's cleanup/publication.
            // Check after reading counters so an expired generation never gains
            // readiness merely because it still occupies the current slot.
            let expired = generation.lease.until(generation.renew_at) != Ok(false);
            if expired {
                generation.cancel.cancel();
            }
            snapshot.available =
                state.phase == Phase::Connected && !generation.cancel.is_cancelled() && !expired;
            if !snapshot.available {
                snapshot.phase = Phase::Stopped;
                snapshot.reason = if expired {
                    lease_reason(&generation.lease).unwrap_or(Reason::TransportUnavailable)
                } else if snapshot.reason == Reason::None {
                    Reason::Stopped
                } else {
                    snapshot.reason
                };
            }
        }
        // The login deadline also applies while the old generation is gone
        // and the supervisor is in setup or backoff. No scheduling dependency.
        if let Some(reason) = state.lease.as_ref().and_then(lease_reason) {
            snapshot.phase = Phase::Stopped;
            snapshot.reason = reason;
            snapshot.available = false;
        }
        snapshot
    }

    fn connect(&self, target: Target) -> ConnectFuture<'_> {
        // Snapshot before awaiting; the generation owns DNS, routes and cancellation.
        let generation = self.state.read().unwrap().current.clone();
        Box::pin(async move {
            // Target fields are public: library callers may bypass its parser.
            // Authorization and resolution must consume the same canonical host.
            let target = Target::new(&target.host, target.port)?;
            let generation = generation.ok_or_else(unavailable)?;
            if generation.lease.until(generation.renew_at) != Ok(false) {
                generation.cancel.cancel();
                return Err(unavailable());
            }
            if !generation.policy.allows(&target) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "destination not authorized",
                ));
            }
            // The configured budget covers DNS and every candidate together.
            // The lease wrapper also checks the wall clock after suspension.
            let budget = generation
                .lease
                .deadline_after(generation.stack.connect_timeout())
                .map_err(|_| unavailable())?;
            let dial_deadline = Instant::now() + generation.stack.connect_timeout();
            let connect = async {
                let ips = generation
                    .resolver
                    .resolve(&generation.stack, &target.host)
                    .await
                    .inspect_err(|error| {
                        tracing::debug!(kind = ?error.kind(), "VPN destination DNS lookup failed");
                    })?;
                let eligible: Vec<_> = ips
                    .into_iter()
                    .take(16)
                    .filter(|ip| {
                        // Reserved/link-local/multicast destinations are not application services.
                        if ip.is_unspecified()
                            || ip.is_loopback()
                            || ip.is_link_local()
                            || ip.is_multicast()
                            || ip.is_broadcast()
                            || ip.octets()[0] == 0
                            || *ip == generation.address
                            || generation.policy.excludes_ip(IpAddr::V4(*ip))
                        {
                            return false;
                        }
                        true
                    })
                    .collect();
                let stream =
                    dial_addresses(&generation, eligible, target.port, dial_deadline).await?;
                Ok(Box::new(GuardedIo::new(
                    stream,
                    generation.lease.clone(),
                    generation.renew_at,
                    generation.cancel.clone(),
                )) as BoxStream)
            };
            let budgeted = async {
                generation
                    .lease
                    .run_until(Some(budget), connect)
                    .await
                    .map_err(|failure| {
                        if failure == LeaseFailure::Renewal {
                            dial_timed_out()
                        } else {
                            unavailable()
                        }
                    })?
            };
            tokio::select! {
                biased;
                _ = generation.cancel.cancelled() => Err(unavailable()),
                result = generation.lease.run_until(generation.renew_at, budgeted) => {
                    if generation.lease.until(generation.renew_at) != Ok(false) {
                        generation.cancel.cancel();
                        return Err(unavailable());
                    }
                    result.map_err(|_| unavailable())?
                },
            }
        })
    }
}

// All requests in a generation share these four extra sockets. Each request
// also has its ordinary business slot; no task or unbounded admission queue is
// created for racing addresses. The stack reserves the same fixed allowance.
const MAX_DIAL_HEDGES: usize = 4;
const MAX_DIAL_ATTEMPTS: usize = 4;
const DIAL_STAGGER: Duration = Duration::from_millis(250);
const MIN_ADDRESS_ATTEMPT: Duration = Duration::from_secs(2);

fn dial_timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "VPN destination dial budget expired",
    )
}

async fn dial_addresses(
    generation: &Generation,
    addresses: Vec<Ipv4Addr>,
    port: u16,
    deadline: Instant,
) -> io::Result<DuplexStream> {
    if addresses.is_empty() {
        return Err(unavailable());
    }
    let mut slots = vec![None];
    for _ in 1..addresses.len().min(MAX_DIAL_ATTEMPTS) {
        match generation.dial_hedges.clone().try_acquire_owned() {
            Ok(permit) => slots.push(Some(permit)),
            Err(_) => break,
        }
    }
    let waves = addresses.len().div_ceil(slots.len()) as u32;
    let stagger = DIAL_STAGGER * (slots.len() as u32 - 1);
    let remaining = deadline.saturating_duration_since(Instant::now());
    let slice = (remaining.saturating_sub(stagger) / waves).max(MIN_ADDRESS_ATTEMPT);
    let mut addresses = addresses.into_iter().peekable();
    let mut idle: VecDeque<_> = slots.into();
    let mut attempts = FuturesUnordered::new();
    let mut next_launch = Instant::now();
    let mut last_error = unavailable();
    loop {
        if addresses.peek().is_none() {
            // No planned attempt still needs these reserved extra slots.
            idle.clear();
        }
        if !idle.is_empty()
            && addresses.peek().is_some()
            && (attempts.is_empty() || Instant::now() >= next_launch)
        {
            attempts.push(dial_candidate(
                generation.stack.clone(),
                SocketAddr::new(IpAddr::V4(addresses.next().unwrap()), port),
                slice,
                deadline,
                idle.pop_front().unwrap(),
            ));
            next_launch = Instant::now() + DIAL_STAGGER;
        }
        if attempts.is_empty() {
            return Err(last_error);
        }
        let (permit, result) = tokio::select! {
            result = attempts.next() => result.unwrap(),
            _ = tokio::time::sleep_until(next_launch), if !idle.is_empty() && addresses.peek().is_some() => continue,
        };
        match result {
            // Dropping the remaining futures cancels their stack replies and
            // releases all extra permits, including this winner's permit.
            Ok(stream) => return Ok(stream),
            Err(error) => {
                tracing::debug!(kind = ?error.kind(), "VPN destination TCP connect failed");
                last_error = error;
            }
        }
        idle.push_front(permit);
        // A failure need not wait for the next stagger tick.
        next_launch = Instant::now();
    }
}

async fn dial_candidate(
    stack: StackHandle,
    address: SocketAddr,
    slice: Duration,
    total_deadline: Instant,
    permit: Option<OwnedSemaphorePermit>,
) -> (Option<OwnedSemaphorePermit>, io::Result<DuplexStream>) {
    let deadline = (Instant::now() + slice).min(total_deadline);
    let result = if deadline <= Instant::now() {
        Err(dial_timed_out())
    } else {
        tokio::time::timeout_at(deadline, async {
            loop {
                let result = stack.connect(address).await;
                match result {
                    // A cancelled prior attempt can take one stack poll to
                    // release its slot. Retry within this attempt's slice only.
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    result => break result,
                }
            }
        })
        .await
        .unwrap_or_else(|_| Err(dial_timed_out()))
    };
    (permit, result)
}

const HIP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const TUNNEL_READ_TIMEOUT: Duration = Duration::from_secs(90);
const TUNNEL_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

#[cfg(test)]
#[path = "../tests/support/session_proxy_lifecycle.rs"]
pub(crate) mod proxy_lifecycle_tests;

#[cfg(test)]
#[path = "../tests/support/connect_address_fallback.rs"]
mod address_fallback_tests;

#[cfg(test)]
#[path = "../tests/support/session_clock.rs"]
mod clock_tests;

#[cfg(test)]
#[path = "../tests/support/hip_clock.rs"]
mod hip_clock_tests;

#[cfg(test)]
#[path = "../tests/support/tunnel_clock.rs"]
mod tunnel_clock_tests;

/// A remaining lifetime in a fresh configuration may shorten this login, but
/// reconnecting with the same cookie must never silently extend its old lease.
fn observe_lifetime(lease: &Lease, tunnel: &TunnelConfig) -> Result<(), GpError> {
    lease
        .observe(config_anchor(tunnel), tunnel.lifetime)
        .map_err(lease_error)
}

fn config_anchor(tunnel: &TunnelConfig) -> Sample {
    Sample {
        monotonic: tunnel.received_at,
        wall: tunnel.received_wall,
    }
}

fn lease_error(failure: LeaseFailure) -> GpError {
    if failure == LeaseFailure::ClockUncertain {
        tracing::warn!("session clock became uncertain; authentication must be renewed");
    }
    GpError::Authentication
}

fn operation_error(failure: LeaseFailure) -> GpError {
    match failure {
        LeaseFailure::Renewal => GpError::Timeout,
        other => lease_error(other),
    }
}

fn lease_reason(lease: &Lease) -> Option<Reason> {
    lease.check().err().map(|failure| match failure {
        LeaseFailure::Expired => Reason::SessionExpired,
        LeaseFailure::ClockUncertain => Reason::AuthenticationRequired,
        LeaseFailure::Renewal => Reason::TransportUnavailable,
    })
}

/// Control requests and reconnect backoff are cancelled at the same login
/// deadline as the data plane. No new request starts after an expired lease.
async fn session_operation<T>(
    shutdown: &CancellationToken,
    lease: &Lease,
    operation: impl Future<Output = Result<T, GpError>>,
) -> Result<T, GpError> {
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => Err(GpError::Io(unavailable())),
        result = lease.run(operation) => result.map_err(lease_error)?,
    }
}

fn renewal_deadline(tunnel: &TunnelConfig) -> Result<Option<Deadline>, GpError> {
    tunnel
        .timeout
        .map(|duration| {
            let margin = (duration / 10).min(Duration::from_secs(60));
            Deadline::after(config_anchor(tunnel), duration.saturating_sub(margin))
                .map_err(lease_error)
        })
        .transpose()
}

/// A distinct HTTPS request refreshes HIP state without replacing a working
/// userspace TCP stack. There is only one request in flight and no catch-up burst.
fn maintain_hip<F, H>(
    lease: Lease,
    interval: Duration,
    mut check: F,
) -> impl Future<Output = Result<(), GpError>>
where
    F: FnMut() -> H,
    H: Future<Output = Result<HipStatus, GpError>>,
{
    // Capture at future construction, not its first poll: scheduling/suspend
    // between generation setup and polling must not restart the first period.
    let first = (Duration::from_secs(60)..=Duration::from_secs(3600))
        .contains(&interval)
        .then(|| lease.deadline_after(interval));
    async move {
        let mut next = first
            .ok_or(GpError::Protocol("HIP interval outside supported range"))?
            .map_err(lease_error)?;
        loop {
            lease.wait(Some(next)).await.map_err(lease_error)?;
            // Anchor to the actual start of this request, not the missed slot.
            // A suspend or scheduling gap therefore produces one refresh, never
            // a burst proportional to the number of missed intervals. Normal
            // operation retains the configured start-to-start cadence.
            next = lease.deadline_after(interval).map_err(lease_error)?;
            let request_end = lease
                .deadline_after(HIP_REQUEST_TIMEOUT)
                .map_err(lease_error)?;
            tracing::info!("periodic gateway HIP check started");
            let status = lease
                .run_until(Some(request_end), async { check().await })
                .await
                .map_err(operation_error)??;
            match status {
                HipStatus::NotRequested => tracing::info!("periodic gateway HIP check completed"),
                HipStatus::ReportRequested => tracing::warn!(
                    "gateway requested HIP report; no report submitted, access remains subject to gateway policy"
                ),
            }
        }
    }
}

struct GenerationControl<M> {
    cancel: CancellationToken,
    lease: Lease,
    maintenance: M,
}

fn retryable(error: &GpError) -> bool {
    match error {
        GpError::Io(_) | GpError::Timeout => true,
        GpError::HttpStatus(code) => matches!(code, 408 | 429) || (500..600).contains(code),
        _ => false,
    }
}

fn failure_reason(error: &GpError, lease: &Lease) -> Reason {
    if let Some(reason) = lease_reason(lease) {
        return reason;
    }
    match error {
        GpError::Authentication | GpError::HttpStatus(401 | 403) => Reason::AuthenticationRequired,
        GpError::UnsupportedAuthentication => Reason::UnsupportedAuthentication,
        GpError::ConfigurationRejected => Reason::ConfigurationRejected,
        error if retryable(error) => Reason::TransportUnavailable,
        _ => Reason::ProtocolError,
    }
}

pub fn effective_policy(config: &Config, tunnel: &TunnelConfig) -> io::Result<Policy> {
    let domains = config.domains.clone();
    let mut networks = config.networks.clone();
    let mut gateway_domains = Vec::new();
    if config.trust_gateway_routes {
        // Search suffixes only complete names; they are not authorization.
        gateway_domains.extend_from_slice(&tunnel.include_domains);
        networks.extend(tunnel.include_routes.iter().copied().map(ipnet::IpNet::V4));
    }
    if domains.len() + networks.len() + gateway_domains.len() > 8192 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "too many gateway policy rules",
        ));
    }
    Ok(Policy::new(domains, networks)?
        .with_gateway_domains(gateway_domains, tunnel.exclude_domains.clone())?
        .with_excludes(
            tunnel
                .exclude_routes
                .iter()
                .copied()
                .map(ipnet::IpNet::V4)
                .collect(),
        ))
}

/// Keep every previously classified company destination on the proxy path.
/// Only the current generation's stricter policy authorizes egress.
fn extend_pac(previous: &Policy, current: &Policy) -> io::Result<Policy> {
    previous.merge_classification(current)
}

/// Retry transport errors with bounded exponential backoff. Authentication,
/// unsupported policy, and malformed protocol errors require operator action.
pub async fn supervise(
    config: Config,
    client: GatewayClient,
    mut session: Session,
    initial: TunnelConfig,
    connector: Arc<TunnelConnector>,
    pac: watch::Sender<Arc<Policy>>,
    shutdown: CancellationToken,
) -> Result<(), GpError> {
    // Keep the observable phase terminal on every return, panic or task abort.
    // The generation already owns cancellation of its asynchronous resources.
    struct StopOnDrop(Arc<TunnelConnector>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.disconnect();
        }
    }
    let _stop_on_drop = StopOnDrop(connector.clone());
    let mut initial = Some(initial);
    let mut backoff = 1u64;
    let lease = Lease::new();
    connector.observe_expiry(lease.clone());
    loop {
        if shutdown.is_cancelled() {
            connector.disconnect();
            return Ok(());
        }
        if let Err(failure) = lease.check() {
            connector.stop_with_reason(lease_reason(&lease));
            return Err(lease_error(failure));
        }
        connector.connecting();
        // Setup has no background tasks and can be dropped promptly. Once a
        // generation starts, let its cancellation path join every owned task.
        let setup = async {
            let tunnel = match initial.take() {
                Some(config) => config,
                None => session_operation(&shutdown, &lease, client.get_config(&session)).await?,
            };
            observe_lifetime(&lease, &tunnel)?;
            let policy = effective_policy(&config, &tunnel)
                .map_err(|_| GpError::Protocol("invalid effective destination policy"))?;
            let next_pac = extend_pac(&pac.borrow(), &policy)
                .map_err(|_| GpError::Protocol("cumulative PAC policy limit reached"))?;
            // Commit before publication or generation activation. A filesystem
            // failure must not produce a PAC that can forget rules on restart.
            let next_pac = match &config.pac_history {
                Some(history) => history
                    .remember(&next_pac)
                    .map_err(|_| GpError::Protocol("cannot persist PAC classification history"))?,
                None => next_pac,
            };
            pac.send_replace(Arc::new(next_pac));
            let transport =
                session_operation(&shutdown, &lease, client.connect_tunnel(&session, &tunnel))
                    .await?;
            Ok::<_, GpError>((tunnel, policy, transport))
        };
        let setup_result = setup.await;
        let result = if let Ok((tunnel, policy, transport)) = setup_result {
            session.preferred_ip = Some(tunnel.address);
            let started = Instant::now();
            if let Err(failure) = lease.check() {
                connector.stop_with_reason(lease_reason(&lease));
                return Err(lease_error(failure));
            }
            let maintenance = maintain_hip(
                lease.clone(),
                Duration::from_secs(config.hip_check_interval_secs),
                || client.check_hip(&session, &tunnel),
            );
            let result = run_generation(
                &config,
                tunnel.clone(),
                policy,
                transport,
                connector.clone(),
                GenerationControl {
                    cancel: shutdown.child_token(),
                    lease: lease.clone(),
                    maintenance,
                },
            )
            .await;
            if started.elapsed() >= Duration::from_secs(30) {
                backoff = 1;
            }
            result
        } else {
            setup_result.map(|_| ())
        };
        connector.disconnect();
        if shutdown.is_cancelled() {
            return Ok(());
        }
        match result {
            Err(error) if !retryable(&error) => {
                connector.stop_with_reason(Some(failure_reason(&error, &lease)));
                return Err(error);
            }
            Err(error) => {
                tracing::warn!(%error, "tunnel unavailable; all business egress remains closed")
            }
            Ok(()) => {
                tracing::info!("renewing tunnel; existing connections closed");
                // A planned renewal is not a failed connection attempt.
                backoff = 1;
                continue;
            }
        }
        let delay = Duration::from_millis(backoff * 1000 + u64::from(rand::random::<u16>()) % 251);
        backoff = (backoff * 2).min(config.reconnect_max_secs);
        connector.retry_wait();
        let wait = session_operation(&shutdown, &lease, async {
            tokio::time::sleep(delay).await;
            Ok(())
        })
        .await;
        if shutdown.is_cancelled() {
            return Ok(());
        }
        if let Err(error) = wait {
            connector.stop_with_reason(Some(failure_reason(&error, &lease)));
            return Err(error);
        }
    }
}

async fn run_generation<T, M>(
    config: &Config,
    tunnel: TunnelConfig,
    policy: Policy,
    transport: T,
    connector: Arc<TunnelConnector>,
    control: GenerationControl<M>,
) -> Result<(), GpError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    M: Future<Output = Result<(), GpError>>,
{
    let GenerationControl {
        cancel,
        lease,
        maintenance,
    } = control;
    lease.check().map_err(lease_error)?;
    if cancel.is_cancelled() {
        return Err(GpError::Io(unavailable()));
    }
    let renew_at = renewal_deadline(&tunnel)?;
    if lease.until(renew_at).map_err(lease_error)? {
        // Setup already consumed the lease: retry with backoff, never publish
        // an expired generation or spin through immediate renewals.
        return Err(GpError::Timeout);
    }
    // Drop guard also cancels tasks if the outer supervisor future is dropped.
    let _cancel_on_drop = cancel.clone().drop_guard();
    let (to_stack, inbound) = mpsc::channel(64);
    let (outbound, from_stack) = mpsc::channel(64);
    let (stack, mut stack_task) = stack::spawn(
        StackConfig {
            ipv4: tunnel.address,
            ipv6: None,
            mtu: tunnel.mtu,
            max_connections: config
                .max_connections
                .checked_add(crate::dns::MAX_DNS_SERVERS)
                .and_then(|limit| limit.checked_add(MAX_DIAL_HEDGES))
                .ok_or(GpError::Protocol("invalid userspace connection budget"))?,
            connect_timeout: Duration::from_secs(config.connect_timeout_secs),
            idle_timeout: Duration::from_secs(config.idle_timeout_secs),
            random_seed: rand::random(),
        },
        inbound,
        outbound,
        cancel.clone(),
    )?;
    // The stack may have been initialized across a scheduling pause. Recheck
    // before exposing its capability, and still join the actor on rejection.
    if lease.until(renew_at) != Ok(false) {
        cancel.cancel();
        let _ = stack_task.await;
        return lease
            .check()
            .map_err(lease_error)
            .and(Err(GpError::Timeout));
    }
    connector.activate(Generation {
        stack,
        dial_hedges: Arc::new(Semaphore::new(MAX_DIAL_HEDGES)),
        resolver: Resolver::new(tunnel.dns.clone()),
        policy,
        address: tunnel.address,
        cancel: cancel.clone(),
        lease: lease.clone(),
        renew_at,
    });
    tracing::info!("GlobalProtect tunnel connected; proxy egress enabled");
    let mut io_tasks = JoinSet::new();
    let transport = GuardedIo::new(transport, lease.clone(), renew_at, cancel.clone());
    let (reader, writer) = tokio::io::split(transport);
    let mtu = tunnel.mtu;
    io_tasks.spawn(read_packets(
        reader,
        to_stack,
        mtu,
        lease.clone(),
        cancel.clone(),
    ));
    io_tasks.spawn(write_packets(
        writer,
        from_stack,
        mtu,
        lease.clone(),
        cancel.clone(),
    ));
    let mut stack_joined = false;
    let result = tokio::select! {
        biased;
        result = lease.wait(renew_at) => result.map_err(lease_error),
        result = lease.run(maintenance) => result.map_err(lease_error).and_then(|result| result),
        // Reader failure may also make the stack cancel its generation. Keep
        // the original protocol error rather than misclassifying it as renewal.
        result = io_tasks.join_next() => match result {
            Some(Ok(result)) => result,
            _ => Err(GpError::Protocol("tunnel I/O task failed")),
        },
        result = &mut stack_task => {
            stack_joined = true;
            match result {
                Ok(Ok(())) => Err(GpError::Io(unavailable())),
                Ok(Err(e)) => Err(GpError::Io(e)),
                Err(_) => Err(GpError::Protocol("userspace stack task failed")),
            }
        },
        _ = cancel.cancelled() => Err(GpError::Io(unavailable())),
    };
    // A per-poll I/O guard can detect expiry before the supervisor's timer.
    // Preserve terminal authentication expiry and distinguish tunnel renewal
    // from a transport failure, so renewal does not acquire retry backoff.
    let result = match lease.until(renew_at) {
        Err(failure) => Err(lease_error(failure)),
        Ok(true) => Ok(()),
        Ok(false) => result,
    };
    connector.disconnect();
    cancel.cancel();
    io_tasks.abort_all();
    while io_tasks.join_next().await.is_some() {}
    if !stack_joined {
        let _ = (&mut stack_task).await;
    }
    result
}

async fn read_packets<R: AsyncRead + Unpin>(
    mut reader: R,
    inbound: mpsc::Sender<Vec<u8>>,
    mtu: usize,
    lease: Lease,
    cancel: CancellationToken,
) -> Result<(), GpError> {
    loop {
        // A complete frame has its own deadline; this future is never resumed
        // after cancellation. A blocked or partial TLS frame closes the session.
        let deadline = lease
            .deadline_after(TUNNEL_READ_TIMEOUT)
            .map_err(lease_error)?;
        let mut bounded =
            GuardedIo::new(&mut reader, lease.clone(), Some(deadline), cancel.clone());
        let frame = lease
            .run_until(Some(deadline), gp::read_frame(&mut bounded, mtu))
            .await
            .map_err(operation_error)??;
        if let Frame::Ip(packet) = frame {
            let deadline = lease
                .deadline_after(TUNNEL_WRITE_TIMEOUT)
                .map_err(lease_error)?;
            lease
                .run_until(Some(deadline), inbound.send(packet))
                .await
                .map_err(operation_error)?
                .map_err(|_| GpError::Io(unavailable()))?;
        }
    }
}

async fn write_packets<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    mtu: usize,
    lease: Lease,
    cancel: CancellationToken,
) -> Result<(), GpError> {
    let mut heartbeat = lease.deadline_after(Duration::ZERO).map_err(lease_error)?;
    loop {
        let frame = tokio::select! {
            biased;
            result = lease.wait(Some(heartbeat)) => {
                result.map_err(lease_error)?;
                // Preserve the immediate first DPD; a scheduling gap produces
                // just one later heartbeat and then starts a fresh interval.
                heartbeat = lease.deadline_after(KEEPALIVE_INTERVAL).map_err(lease_error)?;
                Frame::Keepalive
            },
            packet = outbound.recv() => Frame::Ip(packet.ok_or_else(|| GpError::Io(unavailable()))?),
        };
        let deadline = lease
            .deadline_after(TUNNEL_WRITE_TIMEOUT)
            .map_err(lease_error)?;
        let mut bounded =
            GuardedIo::new(&mut writer, lease.clone(), Some(deadline), cancel.clone());
        lease
            .run_until(Some(deadline), gp::write_frame(&mut bounded, &frame, mtu))
            .await
            .map_err(operation_error)??;
    }
}

fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "GlobalProtect tunnel unavailable",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn tunnel_config() -> TunnelConfig {
        TunnelConfig {
            received_at: Instant::now(),
            received_wall: std::time::SystemTime::now(),
            address: Ipv4Addr::new(10, 77, 0, 2),
            dns: vec![],
            dns_suffixes: vec![],
            include_domains: vec![],
            exclude_domains: vec![],
            include_routes: vec![],
            exclude_routes: vec![],
            mtu: 1400,
            timeout: None,
            lifetime: None,
            ssl_tunnel_path: "/ssl-tunnel-connect.sslvpn".into(),
        }
    }

    fn test_lease(remaining: Option<Duration>) -> Lease {
        let lease = Lease::new();
        let observed = lease.observe(Sample::now(), remaining);
        if remaining == Some(Duration::ZERO) {
            assert_eq!(observed, Err(LeaseFailure::Expired));
        } else {
            observed.unwrap();
        }
        lease
    }

    fn control(
        cancel: CancellationToken,
        remaining: Option<Duration>,
    ) -> GenerationControl<std::future::Pending<Result<(), GpError>>> {
        GenerationControl {
            cancel,
            lease: test_lease(remaining),
            maintenance: pending(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn status_rechecks_cancellation_and_expiry_before_supervisor_cleanup() {
        let connector = TunnelConnector::default();
        assert_eq!(connector.status().phase, Phase::Connecting);
        assert_eq!(connector.status().reason, Reason::None);
        assert!(!connector.status().available);
        connector.retry_wait();
        assert_eq!(connector.status().phase, Phase::RetryWait);
        assert_eq!(connector.status().reason, Reason::TransportUnavailable);
        assert_eq!(connector.status().retry_count, 1);
        connector.connecting();
        assert_eq!(connector.status().phase, Phase::Connecting);
        assert_eq!(connector.status().reason, Reason::TransportUnavailable);
        for expired in [false, true] {
            // A newly activated generation clears even a previous terminal
            // reason; only an explicit activation can make it ready again.
            connector.stop_with_reason(Some(Reason::AuthenticationRequired));
            let cancel = CancellationToken::new();
            let (_inbound, incoming) = mpsc::channel(64);
            let (outgoing, _outbound) = mpsc::channel(64);
            let (stack, actor) = stack::spawn(
                StackConfig {
                    ipv4: Ipv4Addr::new(10, 77, 0, 2),
                    ipv6: None,
                    mtu: 1400,
                    max_connections: 2,
                    connect_timeout: Duration::from_secs(3),
                    idle_timeout: Duration::from_secs(30),
                    random_seed: 1,
                },
                incoming,
                outgoing,
                cancel.clone(),
            )
            .unwrap();
            connector.activate(Generation {
                stack,
                dial_hedges: Arc::new(Semaphore::new(MAX_DIAL_HEDGES)),
                resolver: Resolver::new(vec![]),
                policy: Policy::new(vec!["private.invalid".into()], vec![]).unwrap(),
                address: Ipv4Addr::new(10, 77, 0, 2),
                cancel: cancel.clone(),
                lease: test_lease(Some(Duration::from_secs(5))),
                renew_at: None,
            });
            assert!(connector.status().available);
            assert_eq!(connector.status().phase, Phase::Connected);
            assert_eq!(connector.status().reason, Reason::None);
            if expired {
                tokio::time::advance(Duration::from_secs(5)).await;
            } else {
                cancel.cancel();
            }
            // Deliberately leave the generation published: status must not rely
            // on the supervisor being scheduled to revoke its availability.
            assert!(connector.state.read().unwrap().current.is_some());
            assert!(!connector.status().available);
            assert_eq!(connector.status().phase, Phase::Stopped);
            let reason = if expired {
                Reason::SessionExpired
            } else {
                Reason::Stopped
            };
            assert_eq!(connector.status().reason, reason);
            assert_eq!(connector.status().retry_count, 1);
            let json = serde_json::to_string(&connector.status()).unwrap();
            assert!(!json.contains("private.invalid"));
            assert!(!json.contains("10.77.0.2"));
            connector.disconnect();
            actor.await.unwrap().unwrap();
            assert_eq!(connector.status().phase, Phase::Stopped);
            assert_eq!(connector.status().reason, reason);
            assert_eq!(connector.status().active_tcp, 0);
        }
    }

    #[tokio::test]
    async fn raw_target_ipv4_is_canonicalized_before_authorization_and_dns() {
        let cancel = CancellationToken::new();
        let (_incoming, inbound) = mpsc::channel(4);
        let (outbound, mut packets) = mpsc::channel(4);
        let (stack, actor) = stack::spawn(
            StackConfig {
                ipv4: Ipv4Addr::new(10, 77, 0, 2),
                ipv6: None,
                mtu: 1400,
                max_connections: 2,
                connect_timeout: Duration::from_secs(3),
                idle_timeout: Duration::from_secs(30),
                random_seed: 1,
            },
            inbound,
            outbound,
            cancel.clone(),
        )
        .unwrap();
        let connector = Arc::new(TunnelConnector::default());
        connector.activate(Generation {
            stack,
            dial_hedges: Arc::new(Semaphore::new(MAX_DIAL_HEDGES)),
            resolver: Resolver::new(vec![Ipv4Addr::new(10, 77, 0, 53)]),
            policy: Policy::new(vec![], vec!["10.77.0.0/24".parse().unwrap()]).unwrap(),
            address: Ipv4Addr::new(10, 77, 0, 2),
            cancel: cancel.clone(),
            lease: Lease::new(),
            renew_at: None,
        });
        let dialing = connector.clone();
        let pending = tokio::spawn(async move {
            // Public fields let library callers skip Target::new, unlike the
            // HTTP/SOCKS parsers. The connector is the final capability check.
            dialing
                .connect(Target {
                    host: "10.77.0.1.".into(),
                    port: 443,
                })
                .await
        });
        // Deliberately never supply a DNS response. The very first IP packet
        // must be a SYN to the literal, not a query to the configured resolver.
        let packet = timeout(Duration::from_secs(1), packets.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            packet[9], 6,
            "numeric destination unexpectedly emitted a DNS packet"
        );
        assert_eq!(&packet[16..20], &[10, 77, 0, 1]);
        let tcp = usize::from(packet[0] & 15) * 4;
        assert_eq!(u16::from_be_bytes([packet[tcp + 2], packet[tcp + 3]]), 443);
        assert_eq!(packet[tcp + 13] & 0x02, 0x02);
        for target in [
            Target {
                host: "invalid host".into(),
                port: 443,
            },
            Target {
                host: "10.77.0.1".into(),
                port: 0,
            },
        ] {
            assert_eq!(
                connector.connect(target).await.err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert!(
            packets.try_recv().is_err(),
            "invalid targets emitted an IP packet"
        );
        cancel.cancel();
        assert_eq!(
            pending.await.unwrap().err().unwrap().kind(),
            io::ErrorKind::NotConnected
        );
        connector.disconnect();
        actor.await.unwrap().unwrap();
    }

    #[test]
    fn status_failure_categories_never_include_raw_error_text() {
        for (error, reason) in [
            (GpError::Authentication, Reason::AuthenticationRequired),
            (
                GpError::UnsupportedAuthentication,
                Reason::UnsupportedAuthentication,
            ),
            (
                GpError::ConfigurationRejected,
                Reason::ConfigurationRejected,
            ),
            (
                GpError::Protocol("private-error-marker"),
                Reason::ProtocolError,
            ),
            (
                GpError::Io(io::Error::other("private-error-marker")),
                Reason::TransportUnavailable,
            ),
            (GpError::Timeout, Reason::TransportUnavailable),
            (GpError::HttpStatus(403), Reason::AuthenticationRequired),
            (GpError::HttpStatus(302), Reason::ProtocolError),
            (GpError::HttpStatus(429), Reason::TransportUnavailable),
            (GpError::HttpStatus(503), Reason::TransportUnavailable),
        ] {
            assert_eq!(failure_reason(&error, &Lease::new()), reason);
            let connector = TunnelConnector::default();
            connector.stop_with_reason(Some(failure_reason(&error, &Lease::new())));
            // Main calls this after joining the supervisor and once more when
            // stopping the listeners. Neither cleanup may erase its reason.
            connector.disconnect();
            connector.disconnect();
            assert_eq!(connector.status().reason, reason);
            assert!(!connector.status().available);
            assert!(!serde_json::to_string(&connector.status())
                .unwrap()
                .contains("private-error-marker"));
        }
        let expired = Lease::new();
        assert_eq!(
            expired.observe(Sample::now(), Some(Duration::ZERO)),
            Err(LeaseFailure::Expired)
        );
        assert_eq!(
            failure_reason(&GpError::Authentication, &expired),
            Reason::SessionExpired
        );
    }

    #[tokio::test(start_paused = true)]
    async fn status_terminal_reason_survives_supervisor_exit_and_main_cleanup() {
        // Both fixtures fail during setup, before any network request is polled:
        // one has an exhausted login lease; one has invalid local policy.
        for expired in [true, false] {
            let connector = Arc::new(TunnelConnector::default());
            let mut tunnel = tunnel_config();
            let mut config = Config::default();
            if expired {
                tunnel.lifetime = Some(Duration::ZERO);
            } else {
                config.domains = vec!["invalid local domain".into()];
            }
            let client = GatewayClient::new(
                url::Url::parse("https://127.0.0.1:9").unwrap(),
                crate::tls::client_config(None).unwrap(),
                crate::gp::ResumptionPolicy::Memory {
                    tls12: rustls::client::Tls12Resumption::SessionIdOrTickets,
                },
            )
            .unwrap();
            let session = Session::new(
                "synthetic".into(),
                "synthetic-cookie".into(),
                String::new(),
                String::new(),
                "test".into(),
                None,
            )
            .unwrap();
            let (pac, _receiver) = watch::channel(Arc::new(Policy::new(vec![], vec![]).unwrap()));
            let result = timeout(
                Duration::from_secs(1),
                supervise(
                    config,
                    client,
                    session,
                    tunnel,
                    connector.clone(),
                    pac,
                    CancellationToken::new(),
                ),
            )
            .await
            .unwrap();
            let reason = if expired {
                assert!(matches!(result, Err(GpError::Authentication)));
                Reason::SessionExpired
            } else {
                assert!(matches!(result, Err(GpError::Protocol(_))));
                Reason::ProtocolError
            };
            // supervise has returned and its drop guard has already run.
            assert_eq!(connector.status().reason, reason);
            connector.disconnect(); // main: supervisor completion branch
            assert_eq!(connector.status().reason, reason);
            connector.disconnect(); // main: final shutdown cleanup
            assert_eq!(connector.status().reason, reason);
            assert_eq!(connector.status().phase, Phase::Stopped);
            assert!(!connector.status().available);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn status_expiry_applies_during_retry_wait_without_an_active_generation() {
        let connector = TunnelConnector::default();
        connector.observe_expiry(test_lease(Some(Duration::from_secs(5))));
        connector.retry_wait();
        assert_eq!(connector.status().reason, Reason::TransportUnavailable);
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(connector.status().phase, Phase::Stopped);
        assert_eq!(connector.status().reason, Reason::SessionExpired);
        connector.disconnect();
        assert_eq!(connector.status().reason, Reason::SessionExpired);
    }

    #[test]
    fn authentication_protocol_and_redirect_failures_are_terminal() {
        for failure in [
            GpError::Authentication,
            GpError::UnsupportedAuthentication,
            GpError::ConfigurationRejected,
            GpError::Protocol("synthetic"),
            GpError::HttpStatus(200),
            GpError::HttpStatus(302),
            GpError::HttpStatus(403),
        ] {
            assert!(!retryable(&failure));
        }
        for failure in [
            GpError::Timeout,
            GpError::HttpStatus(408),
            GpError::HttpStatus(429),
            GpError::HttpStatus(503),
        ] {
            assert!(retryable(&failure));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn hip_refresh_is_periodic_without_immediate_or_overlapping_requests() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let maintenance = tokio::spawn(maintain_hip(
            Lease::new(),
            Duration::from_secs(60),
            move || {
                observed.fetch_add(1, Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Ok(HipStatus::ReportRequested)
                }
            },
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(59)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(50)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(!maintenance.is_finished());
        maintenance.abort();
        assert!(maintenance.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn hip_request_stall_has_a_bounded_timeout() {
        let maintenance =
            tokio::spawn(maintain_hip(Lease::new(), Duration::from_secs(60), pending));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        assert!(!maintenance.is_finished());
        tokio::time::advance(HIP_REQUEST_TIMEOUT).await;
        assert!(matches!(maintenance.await.unwrap(), Err(GpError::Timeout)));
    }

    #[tokio::test(start_paused = true)]
    async fn refreshed_configuration_cannot_extend_the_login_lifetime() {
        let mut first = tunnel_config();
        first.lifetime = Some(Duration::from_secs(120));
        let lease = Lease::new();
        observe_lifetime(&lease, &first).unwrap();
        let original = lease.deadline();
        tokio::time::advance(Duration::from_secs(30)).await;
        let mut next = tunnel_config();
        next.lifetime = Some(Duration::from_secs(120));
        observe_lifetime(&lease, &next).unwrap();
        assert_eq!(lease.deadline(), original);
        next.lifetime = None;
        observe_lifetime(&lease, &next).unwrap();
        assert_eq!(lease.deadline(), original);
        next.lifetime = Some(Duration::from_secs(10));
        observe_lifetime(&lease, &next).unwrap();
        assert_eq!(
            lease.deadline(),
            Some(Deadline::after(config_anchor(&next), Duration::from_secs(10)).unwrap())
        );

        // A stalled setup request or backoff is interrupted at that same deadline.
        let operation = tokio::spawn(async move {
            session_operation(
                &CancellationToken::new(),
                &lease,
                pending::<Result<(), GpError>>(),
            )
            .await
        });
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(matches!(
            operation.await.unwrap(),
            Err(GpError::Authentication)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn setup_delay_consumes_the_rekey_lease() {
        let mut tunnel = tunnel_config();
        tunnel.timeout = Some(Duration::from_secs(100));
        tokio::time::advance(Duration::from_secs(80)).await;
        let connector = Arc::new(TunnelConnector::default());
        let active = connector.clone();
        let (mut peer, transport) = tokio::io::duplex(128);
        let generation = tokio::spawn(async move {
            run_generation(
                &Config::default(),
                tunnel,
                Policy::new(vec![], vec![]).unwrap(),
                transport,
                active,
                control(CancellationToken::new(), None),
            )
            .await
        });
        assert_eq!(
            gp::read_frame(&mut peer, 1400).await.unwrap(),
            Frame::Keepalive
        );
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(!generation.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(generation.await.unwrap().is_ok());
        assert!(connector.state.read().unwrap().current.is_none());
        assert_eq!(peer.read(&mut [0u8; 1]).await.unwrap(), 0);
        assert!(renewal_deadline(&tunnel_config()).unwrap().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn exhausted_rekey_lease_fails_before_publication_and_requires_backoff() {
        let mut tunnel = tunnel_config();
        tunnel.timeout = Some(Duration::from_secs(10));
        tokio::time::advance(Duration::from_secs(11)).await;
        let connector = Arc::new(TunnelConnector::default());
        let (mut peer, transport) = tokio::io::duplex(128);
        let error = run_generation(
            &Config::default(),
            tunnel,
            Policy::new(vec![], vec![]).unwrap(),
            transport,
            connector.clone(),
            control(CancellationToken::new(), None),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, GpError::Timeout));
        assert!(retryable(&error));
        assert!(connector.state.read().unwrap().current.is_none());
        assert_eq!(peer.read(&mut [0u8; 1]).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn hip_failure_revokes_pending_and_future_application_connections() {
        for failure in [GpError::Authentication, GpError::Timeout] {
            let connector = Arc::new(TunnelConnector::default());
            let active = connector.clone();
            let (mut peer, transport) = tokio::io::duplex(4096);
            let generation = tokio::spawn(async move {
                run_generation(
                    &Config::default(),
                    tunnel_config(),
                    Policy::new(vec![], vec!["10.77.0.0/24".parse().unwrap()]).unwrap(),
                    transport,
                    active,
                    GenerationControl {
                        cancel: CancellationToken::new(),
                        lease: Lease::new(),
                        maintenance: async {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            Err(failure)
                        },
                    },
                )
                .await
            });
            assert_eq!(
                gp::read_frame(&mut peer, 1400).await.unwrap(),
                Frame::Keepalive
            );
            let dialing = connector.clone();
            let pending_connection = tokio::spawn(async move {
                dialing
                    .connect(Target::new("10.77.0.1", 443).unwrap())
                    .await
            });
            assert!(matches!(
                gp::read_frame(&mut peer, 1400).await.unwrap(),
                Frame::Ip(_)
            ));
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(matches!(
                generation.await.unwrap(),
                Err(GpError::Authentication | GpError::Timeout)
            ));
            assert!(pending_connection.await.unwrap().is_err());
            assert_eq!(
                connector
                    .connect(Target::new("10.77.0.1", 443).unwrap())
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::NotConnected
            );
            let mut remainder = Vec::new();
            peer.read_to_end(&mut remainder).await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn login_expiry_cancels_a_stalled_periodic_hip_check() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let connector = Arc::new(TunnelConnector::default());
        let active = connector.clone();
        let (mut peer, transport) = tokio::io::duplex(4096);
        let generation = tokio::spawn(async move {
            run_generation(
                &Config::default(),
                tunnel_config(),
                Policy::new(vec![], vec![]).unwrap(),
                transport,
                active,
                GenerationControl {
                    cancel: CancellationToken::new(),
                    lease: test_lease(Some(Duration::from_secs(61))),
                    maintenance: maintain_hip(Lease::new(), Duration::from_secs(60), move || {
                        observed.fetch_add(1, Ordering::SeqCst);
                        pending()
                    }),
                },
            )
            .await
        });
        assert_eq!(
            gp::read_frame(&mut peer, 1400).await.unwrap(),
            Frame::Keepalive
        );
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            generation.await.unwrap(),
            Err(GpError::Authentication)
        ));
        assert!(connector.state.read().unwrap().current.is_none());
        let mut remainder = Vec::new();
        peer.read_to_end(&mut remainder).await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_joins_generation_and_closes_partial_transport() {
        let connector = Arc::new(TunnelConnector::default());
        let shutdown = CancellationToken::new();
        let (mut peer, transport) = tokio::io::duplex(128);
        let active_connector = connector.clone();
        let generation_cancel = shutdown.child_token();
        let generation = tokio::spawn(async move {
            run_generation(
                &Config::default(),
                tunnel_config(),
                Policy::new(vec![], vec![]).unwrap(),
                transport,
                active_connector,
                control(generation_cancel, None),
            )
            .await
        });
        timeout(Duration::from_secs(2), async {
            assert_eq!(
                gp::read_frame(&mut peer, 1400).await.unwrap(),
                Frame::Keepalive
            );
            // Leave the dedicated reader inside an incomplete frame.
            peer.write_all(&[0x1a]).await.unwrap();
            shutdown.cancel();
            assert!(generation.await.unwrap().is_err());
            assert!(connector.state.read().unwrap().current.is_none());
            assert_eq!(peer.read(&mut [0u8; 1]).await.unwrap(), 0);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn expired_session_is_never_published() {
        let connector = Arc::new(TunnelConnector::default());
        let (_peer, transport) = tokio::io::duplex(4096);
        let result = run_generation(
            &Config::default(),
            tunnel_config(),
            Policy::new(vec![], vec![]).unwrap(),
            transport,
            connector.clone(),
            control(CancellationToken::new(), Some(Duration::ZERO)),
        )
        .await;
        assert!(matches!(result, Err(GpError::Authentication)));
        assert!(connector.state.read().unwrap().current.is_none());
    }

    #[tokio::test]
    async fn framed_transport_eof_revokes_pending_and_future_connections() {
        let connector = Arc::new(TunnelConnector::default());
        let policy = Policy::new(vec![], vec!["10.77.0.0/24".parse().unwrap()]).unwrap();
        let (mut peer, transport) = tokio::io::duplex(4096);
        let active_connector = connector.clone();
        let generation = tokio::spawn(async move {
            run_generation(
                &Config::default(),
                tunnel_config(),
                policy,
                transport,
                active_connector,
                control(CancellationToken::new(), None),
            )
            .await
        });
        assert_eq!(
            timeout(Duration::from_secs(2), gp::read_frame(&mut peer, 1400))
                .await
                .unwrap()
                .unwrap(),
            Frame::Keepalive
        );
        let dialing_connector = connector.clone();
        let pending = tokio::spawn(async move {
            dialing_connector
                .connect(Target::new("10.77.0.1", 443).unwrap())
                .await
        });
        assert!(matches!(
            timeout(Duration::from_secs(2), gp::read_frame(&mut peer, 1400))
                .await
                .unwrap()
                .unwrap(),
            Frame::Ip(_)
        ));
        drop(peer);
        assert!(timeout(Duration::from_secs(2), generation)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(timeout(Duration::from_secs(2), pending)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(connector.state.read().unwrap().current.is_none());
        assert_eq!(
            connector
                .connect(Target::new("10.77.0.1", 443).unwrap())
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::NotConnected
        );
    }
    #[tokio::test]
    async fn offline_connector_fails_without_destination_socket() {
        let connector = TunnelConnector::default();
        assert_eq!(
            connector
                .connect(Target::new("127.0.0.1", 80).unwrap())
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::NotConnected
        );
    }
    #[test]
    fn pac_remembers_old_enterprise_destinations() {
        let old = Policy::new(vec!["old.corp".into()], vec![]).unwrap();
        let next = Policy::new(vec!["new.corp".into()], vec![]).unwrap();
        let pac = extend_pac(&old, &next).unwrap();
        assert!(pac.allows_host("old.corp"));
        assert!(pac.allows_host("new.corp"));
        assert!(!next.allows_host("old.corp"));
    }

    #[test]
    fn gateway_search_suffix_never_authorizes_and_domain_exclusions_always_apply() {
        use crate::gp::GatewayDomainRule::{Exact, Subdomains};
        let mut tunnel = tunnel_config();
        tunnel.dns_suffixes = vec!["search.corp".into()];
        tunnel.include_domains = vec![Exact("jira.corp".into()), Subdomains("svc.corp".into())];
        tunnel.exclude_domains = vec![Exact("denied.local.corp".into())];
        tunnel.include_routes = vec!["10.0.0.0/8".parse().unwrap()];
        tunnel.exclude_routes = vec!["10.1.0.0/16".parse().unwrap()];
        let mut config = Config {
            domains: vec!["local.corp".into()],
            trust_gateway_routes: true,
            ..Config::default()
        };
        let policy = effective_policy(&config, &tunnel).unwrap();
        assert!(!policy.allows_host("search.corp"));
        assert!(!policy.allows_host("a.search.corp"));
        assert!(policy.allows_host("jira.corp"));
        assert!(!policy.allows_host("a.jira.corp"));
        assert!(policy.allows_host("a.svc.corp"));
        assert!(!policy.allows_host("svc.corp"));
        assert!(!policy.allows_host("denied.local.corp"));
        assert!(policy.allows_host("10.2.3.4"));
        assert!(!policy.allows_host("10.1.3.4"));
        config.trust_gateway_routes = false;
        let local = effective_policy(&config, &tunnel).unwrap();
        assert!(local.allows_host("local.corp"));
        assert!(!local.allows_host("denied.local.corp"));
        assert!(!local.allows_host("jira.corp"));
        assert!(!local.allows_host("10.2.3.4"));
    }
    #[tokio::test]
    async fn silent_tunnel_times_out_and_partial_frame_cannot_hang() {
        tokio::time::pause();
        let (_peer, reader) = tokio::io::duplex(128);
        let (tx, _rx) = mpsc::channel(1);
        let task = tokio::spawn(read_packets(
            reader,
            tx,
            1400,
            Lease::new(),
            CancellationToken::new(),
        ));
        tokio::time::advance(Duration::from_secs(91)).await;
        assert!(matches!(task.await.unwrap(), Err(GpError::Timeout)));
    }
}
