//! A bounded, one-shot online check. Runtime credentials and gateway response
//! contents never appear in diagnostics; completed and cancelled checks attempt logout.
use crate::{
    credentials::Credentials,
    dns::Resolver,
    gp::{self, Frame, GatewayClient, GpError, LoginProgress, Session, TunnelConfig},
    lease::{Deadline, Failure as LeaseFailure, GuardedIo, Lease, Sample},
    stack::{self, StackConfig, StackHandle},
};
use std::{
    future::{poll_fn, Future},
    io,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

const CHECK_TIMEOUT: Duration = Duration::from_secs(90);
const DPD_TIMEOUT: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(test)]
#[path = "../tests/support/probe_expiry.rs"]
mod expiry_tests;

#[cfg(test)]
#[path = "../tests/support/probe_auth_cancellation.rs"]
mod authentication_tests;

pub async fn run(
    client: &GatewayClient,
    credentials: Credentials,
    computer: &str,
    dns_name: Option<&str>,
    shutdown: CancellationToken,
) -> Result<(), GpError> {
    if shutdown.is_cancelled() {
        return Err(interrupted());
    }
    let lease = Lease::new();
    let budget = Deadline::after(Sample::now(), CHECK_TIMEOUT).map_err(clock_error)?;
    tracing::info!("online check: authentication started");
    let session = async {
        // Read-only discovery cannot issue a cookie and is promptly cancellable.
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Err(interrupted()),
            result = lease.run_until(Some(budget), client.prelogin()) => {
                result.map_err(clock_error)??;
            },
        }
        if shutdown.is_cancelled() {
            return Err(interrupted());
        }
        let progress = acquire_session(
            &lease,
            budget,
            client.begin_login_guarded(&credentials.user, &credentials.password, computer, || {
                // TLS setup can outlive cancellation or consume the budget.
                // Recheck before its first credential write, but retain an
                // already-issued request's late cookie for logout below.
                if shutdown.is_cancelled() {
                    return Err(interrupted());
                }
                if lease.until(Some(budget)).map_err(clock_error)? {
                    return Err(GpError::Timeout);
                }
                Ok(())
            }),
        )
        .await?;
        match progress {
            LoginProgress::Session(session) => Ok(session),
            LoginProgress::Challenge(_) => Err(GpError::UnsupportedAuthentication),
        }
    }
    .await;
    // Release the password on both success and error, before any further work.
    drop(credentials);
    let session = session?;
    tracing::info!("online check: authentication succeeded");
    tracing::info!(
        portal_present = !session.portal.is_empty(),
        "online check: required session metadata checked"
    );
    check_authenticated(client, &session, dns_name, shutdown, lease, budget).await
}

/// Unlike ordinary guarded operations, a completed authentication must retain
/// its Session even if its final poll crossed the budget, so cleanup can logout.
async fn acquire_session<T>(
    lease: &Lease,
    budget: Deadline,
    operation: impl Future<Output = Result<T, GpError>>,
) -> Result<T, GpError> {
    tokio::pin!(operation);
    let acquire = poll_fn(|cx| {
        if lease.until(Some(budget)).map_err(clock_error)? {
            return std::task::Poll::Ready(Err(GpError::Timeout));
        }
        operation.as_mut().poll(cx)
    });
    tokio::select! {
        biased;
        result = lease.wait(Some(budget)) => result.map_err(clock_error).and(Err(GpError::Timeout)),
        result = acquire => result,
    }
}

fn clock_error(failure: LeaseFailure) -> GpError {
    match failure {
        LeaseFailure::Renewal => GpError::Timeout,
        LeaseFailure::Expired => GpError::Authentication,
        LeaseFailure::ClockUncertain => {
            tracing::warn!(
                "online check: session clock became uncertain; authentication must be renewed"
            );
            GpError::Authentication
        }
    }
}

async fn check_authenticated(
    client: &GatewayClient,
    session: &Session,
    dns_name: Option<&str>,
    shutdown: CancellationToken,
    lease: Lease,
    budget: Deadline,
) -> Result<(), GpError> {
    // Own task handles outside the timeout future so timeout/error paths can
    // cancel and join them before logging out, instead of detaching the stack.
    let mut network: Option<ProbeNetwork> = None;
    let check = lease.run_until(Some(budget), async {
        tracing::info!("online check: gateway configuration requested");
        let config = client.get_config(session).await?;
        let anchor = Sample {
            monotonic: config.received_at,
            wall: config.received_wall,
        };
        lease
            .observe(anchor, config.lifetime)
            .map_err(clock_error)?;
        let deadline = config
            .timeout
            .map(|duration| Deadline::after(anchor, duration).map(|end| budget.earliest(end)))
            .transpose()
            .map_err(clock_error)?
            .unwrap_or(budget);
        tracing::info!(
            dns_servers = config.dns.len(),
            included_routes = config.include_routes.len(),
            excluded_routes = config.exclude_routes.len(),
            "online check: gateway configuration accepted"
        );
        tracing::info!("online check: HIP check and TLS tunnel establishment started");
        lease
            .run_until(Some(deadline), async {
                let tunnel = client.connect_tunnel(session, &config).await?;
                tracing::info!("online check: START_TUNNEL accepted");
                network = Some(ProbeNetwork::start(
                    tunnel,
                    config,
                    lease.clone(),
                    deadline,
                )?);
                network.as_mut().unwrap().verify(dns_name).await
            })
            .await
            .map_err(clock_error)?
    });
    let result = tokio::select! {
        biased;
        _ = shutdown.cancelled() => Err(interrupted()),
        result = check => result.map_err(clock_error).and_then(|result| result),
    };

    if let Some(network) = network {
        network.close().await;
    }
    // Cleanup is allowed after the login lease expires, but has its own
    // independent wall/monotonic budget; never reuse the expired authority.
    let cleanup = Lease::new();
    let logout = match Deadline::after(Sample::now(), Duration::from_secs(3)) {
        Ok(deadline) => cleanup
            .run_until(Some(deadline), client.logout(session))
            .await
            .map_err(clock_error)
            .and_then(|result| result),
        Err(failure) => Err(clock_error(failure)),
    };
    match logout {
        Ok(()) => tracing::info!("online check: gateway logout confirmed"),
        _ => tracing::warn!("online check: gateway logout not confirmed"),
    }
    result
}

fn interrupted() -> GpError {
    GpError::Io(io::Error::new(
        io::ErrorKind::Interrupted,
        "online check interrupted",
    ))
}

struct ProbeNetwork {
    stack: StackHandle,
    resolver: Resolver,
    cancel: CancellationToken,
    stack_task: JoinHandle<io::Result<()>>,
    io_tasks: JoinSet<Result<(), GpError>>,
    dpd: oneshot::Receiver<()>,
}

impl ProbeNetwork {
    fn start<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        tunnel: T,
        config: TunnelConfig,
        lease: Lease,
        deadline: Deadline,
    ) -> Result<Self, GpError> {
        if lease.until(Some(deadline)).map_err(clock_error)? {
            return Err(GpError::Timeout);
        }
        let cancel = CancellationToken::new();
        let (to_stack, incoming) = mpsc::channel(64);
        let (outgoing, from_stack) = mpsc::channel(64);
        let (stack, stack_task) = stack::spawn(
            StackConfig {
                ipv4: config.address,
                ipv6: None,
                mtu: config.mtu,
                max_connections: 8,
                connect_timeout: Duration::from_secs(10),
                idle_timeout: Duration::from_secs(30),
                random_seed: rand::random(),
            },
            incoming,
            outgoing,
            cancel.clone(),
        )?;
        let tunnel = GuardedIo::new(tunnel, lease, Some(deadline), cancel.clone());
        let (reader, writer) = tokio::io::split(tunnel);
        let (dpd_tx, dpd) = oneshot::channel();
        let mut io_tasks = JoinSet::new();
        io_tasks.spawn(read_packets(reader, to_stack, config.mtu, dpd_tx));
        io_tasks.spawn(write_packets(writer, from_stack, config.mtu));
        Ok(Self {
            stack,
            resolver: Resolver::new(config.dns),
            cancel,
            stack_task,
            io_tasks,
            dpd,
        })
    }

    async fn verify(&mut self, dns_name: Option<&str>) -> Result<(), GpError> {
        tokio::select! {
            biased;
            result = self.io_tasks.join_next() => return Err(transport_stopped(result)),
            result = timeout(DPD_TIMEOUT, &mut self.dpd) => {
                result.map_err(|_| GpError::Timeout)?
                    .map_err(|_| GpError::Protocol("tunnel closed before DPD response"))?;
            }
        }
        tracing::info!("online check: GlobalProtect DPD response received");
        if let Some(name) = dns_name {
            tracing::info!("online check: tunnel DNS lookup started");
            let addresses = tokio::select! {
                biased;
                result = self.io_tasks.join_next() => return Err(transport_stopped(result)),
                result = self.resolver.resolve(&self.stack, name) => result?,
            };
            tracing::info!(
                addresses = addresses.len(),
                "online check: tunnel DNS lookup succeeded"
            );
            tracing::info!("online check: tunnel TCP DNS lookup started");
            let addresses = tokio::select! {
                biased;
                result = self.io_tasks.join_next() => return Err(transport_stopped(result)),
                result = self.resolver.resolve_tcp(&self.stack, name) => result?,
            };
            tracing::info!(
                addresses = addresses.len(),
                "online check: tunnel TCP DNS lookup succeeded"
            );
        }
        Ok(())
    }

    async fn close(mut self) {
        self.cancel.cancel();
        self.io_tasks.abort_all();
        while self.io_tasks.join_next().await.is_some() {}
        let _ = (&mut self.stack_task).await;
    }
}

impl Drop for ProbeNetwork {
    fn drop(&mut self) {
        // Also cover cancellation of the entire command by its caller.
        self.cancel.cancel();
        self.io_tasks.abort_all();
    }
}

fn transport_stopped(
    result: Option<Result<Result<(), GpError>, tokio::task::JoinError>>,
) -> GpError {
    match result {
        Some(Ok(Err(error))) => error,
        _ => GpError::Protocol("online check transport task stopped"),
    }
}

async fn read_packets<R: AsyncRead + Unpin>(
    mut reader: R,
    incoming: mpsc::Sender<Vec<u8>>,
    mtu: usize,
    dpd: oneshot::Sender<()>,
) -> Result<(), GpError> {
    let mut dpd = Some(dpd);
    loop {
        // Only a complete frame is exposed. If timeout/cancellation interrupts a
        // partial frame, the complete transport is closed and never reused.
        match timeout(CHECK_TIMEOUT, gp::read_frame(&mut reader, mtu))
            .await
            .map_err(|_| GpError::Timeout)??
        {
            Frame::Keepalive => {
                if let Some(dpd) = dpd.take() {
                    let _ = dpd.send(());
                }
            }
            Frame::Ip(packet) => {
                timeout(WRITE_TIMEOUT, incoming.send(packet))
                    .await
                    .map_err(|_| GpError::Timeout)?
                    .map_err(|_| GpError::Protocol("online check stack closed"))?;
            }
        }
    }
}

async fn write_packets<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    mtu: usize,
) -> Result<(), GpError> {
    let mut keepalive = tokio::time::interval(Duration::from_secs(20));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let frame = tokio::select! {
            _ = keepalive.tick() => Frame::Keepalive,
            packet = outgoing.recv() => Frame::Ip(packet.ok_or(GpError::Protocol("online check stack closed"))?),
        };
        timeout(WRITE_TIMEOUT, gp::write_frame(&mut writer, &frame, mtu))
            .await
            .map_err(|_| GpError::Timeout)??;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::TestClock;
    use tokio::io::AsyncWriteExt;

    fn config() -> TunnelConfig {
        gp::parse_config("<response status='success'><need-tunnel>yes</need-tunnel><ip-address>10.77.0.2</ip-address><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url></response>").unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn completed_authentication_crossing_budget_is_retained_for_logout() {
        let clock = TestClock::new();
        let lease = clock.lease(None);
        let budget = Deadline::after(clock.sample(), CHECK_TIMEOUT).unwrap();
        let session = acquire_session(&lease, budget, async {
            clock.advance(Duration::ZERO, CHECK_TIMEOUT);
            Session::new(
                "fixture-user".into(),
                "fixture-cookie".into(),
                "fixture-portal".into(),
                "fixture-domain".into(),
                "fixture-computer".into(),
                None,
            )
        })
        .await
        .unwrap();
        assert_eq!(session.user, "fixture-user");
        assert_eq!(lease.until(Some(budget)), Ok(true));
        // check_authenticated owns this returned Session's logout even when
        // its very first clock check fails. Ordinary postchecked run() would
        // have discarded the Session and lost that cleanup opportunity.
    }

    #[tokio::test(start_paused = true)]
    async fn probe_network_cannot_start_after_wall_budget_or_login_expiry() {
        for login_expired in [false, true] {
            let clock = TestClock::new();
            let lease = clock.lease(Some(Duration::from_secs(if login_expired {
                60
            } else {
                600
            })));
            let budget = Deadline::after(clock.sample(), CHECK_TIMEOUT).unwrap();
            clock.advance(Duration::ZERO, CHECK_TIMEOUT);
            let (tunnel, mut peer) = tokio::io::duplex(1024);
            let result = ProbeNetwork::start(tunnel, config(), lease, budget);
            assert!(matches!(result, Err(GpError::Authentication)) == login_expired);
            if !login_expired {
                assert!(matches!(result, Err(GpError::Timeout)));
            }
            assert_eq!(
                tokio::io::AsyncReadExt::read(&mut peer, &mut [0])
                    .await
                    .unwrap(),
                0
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn live_probe_wall_budget_closes_and_joins_without_dpd_or_dns() {
        let clock = TestClock::new();
        let lease = clock.lease(Some(Duration::from_secs(600)));
        let budget = Deadline::after(clock.sample(), CHECK_TIMEOUT).unwrap();
        let (tunnel, mut peer) = tokio::io::duplex(1024);
        let mut network = ProbeNetwork::start(tunnel, config(), lease.clone(), budget).unwrap();
        assert_eq!(
            gp::read_frame(&mut peer, 1400).await.unwrap(),
            Frame::Keepalive
        );
        clock.advance(Duration::ZERO, CHECK_TIMEOUT);
        assert_eq!(
            lease
                .run_until(Some(budget), network.verify(Some("private.invalid")))
                .await
                .err(),
            Some(LeaseFailure::Renewal)
        );
        network.close().await;
        assert_eq!(
            tokio::io::AsyncReadExt::read(&mut peer, &mut [0])
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn dpd_reader_reports_complete_frame_and_stops_on_partial_eof() {
        let (mut peer, reader) = tokio::io::duplex(64);
        let (incoming, _receiver) = mpsc::channel(1);
        let (dpd_tx, dpd_rx) = oneshot::channel();
        let reader = tokio::spawn(read_packets(reader, incoming, 1400, dpd_tx));
        peer.write_all(&Frame::Keepalive.encode(1400).unwrap())
            .await
            .unwrap();
        timeout(Duration::from_secs(1), dpd_rx)
            .await
            .unwrap()
            .unwrap();
        peer.write_all(&[0x1a, 0x2b]).await.unwrap();
        drop(peer);
        assert!(reader.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn writer_starts_with_dpd_and_stops_when_stack_closes() {
        let (mut peer, writer) = tokio::io::duplex(64);
        let (sender, outgoing) = mpsc::channel(1);
        let writer = tokio::spawn(write_packets(writer, outgoing, 1400));
        assert_eq!(
            gp::read_frame(&mut peer, 1400).await.unwrap(),
            Frame::Keepalive
        );
        drop(sender);
        assert!(writer.await.unwrap().is_err());
    }
}
