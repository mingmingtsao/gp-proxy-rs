//! Independent synthetic dual-origin Portal → gateway → in-memory business tests.
#![cfg(any(target_os = "macos", target_os = "linux"))]
use super::*;
use crate::session::proxy_lifecycle_tests::echo_peer;
use crate::{
    gp,
    gp::ResumptionPolicy,
    proxy::{ProxyConfig, ProxyServer},
};
#[cfg(all(
    any(target_os = "macos", target_os = "linux"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "portal_ipc.rs"]
mod ipc_tests;
#[path = "portal_origins.rs"]
mod origins;
use origins::{
    answer, wait, DualOrigins, GatewayOutcome, Plan, PolicyOutcome, COMPUTER, CONFIG,
    GATEWAY_LOGIN, HIP, LOGOUT, PASSWORD, PORTAL_LOGIN, PORTAL_PRELOGIN, STEP, TUNNEL, USER,
};
use std::{net::SocketAddr, sync::atomic::Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinHandle,
    time::timeout,
};

fn password(origins: &DualOrigins) -> AuthInput {
    AuthInput::PortalPassword {
        portal: origins.portal.origin.clone(),
        user: USER.into(),
        password: Zeroizing::new(PASSWORD.into()),
        computer: COMPUTER.into(),
    }
}
fn policy() -> ResumptionPolicy {
    ResumptionPolicy::Memory {
        tls12: rustls::client::Tls12Resumption::SessionIdOrTickets,
    }
}
struct Running {
    handle: ServiceHandle,
    connector: Arc<TunnelConnector>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl Running {
    fn setup(
        origins: &DualOrigins,
        swap_ca: Option<bool>,
    ) -> (Self, Service, watch::Receiver<Arc<Policy>>) {
        let config = Config {
            gateway: origins.gateway.origin.clone(),
            portal: Some(origins.portal.origin.clone()),
            domains: vec!["synthetic-portal.invalid".into()],
            networks: vec!["10.77.0.0/24".parse().unwrap()],
            max_connections: 4,
            connect_timeout_secs: 3,
            idle_timeout_secs: 15,
            ..Config::default()
        };
        let portal_ca = if swap_ca == Some(true) {
            &origins.gateway.ca_file
        } else {
            &origins.portal.ca_file
        };
        let gateway_ca = if swap_ca == Some(false) {
            &origins.portal.ca_file
        } else {
            &origins.gateway.ca_file
        };
        let gateway = GatewayClient::new(
            Url::parse(&origins.gateway.origin).unwrap(),
            crate::tls::client_config(Some(gateway_ca)).unwrap(),
            policy(),
        )
        .unwrap();
        let portal = PortalClient::new(
            Url::parse(&origins.portal.origin).unwrap(),
            Url::parse(&origins.gateway.origin).unwrap(),
            crate::tls::client_config(Some(portal_ca)).unwrap(),
            policy(),
        )
        .unwrap();
        let connector = Arc::new(TunnelConnector::default());
        let stop = CancellationToken::new();
        let (pac, receiver) = watch::channel(Arc::new(
            Policy::new(config.domains.clone(), config.networks.clone()).unwrap(),
        ));
        let (handle, service) = new_with_portal(
            config,
            gateway,
            Some(portal),
            connector.clone(),
            pac,
            stop.clone(),
        )
        .unwrap();
        (
            Self {
                handle,
                connector,
                stop,
                task: None,
            },
            service,
            receiver,
        )
    }
    fn start(
        origins: &DualOrigins,
        interactive: bool,
        cancel: CancellationToken,
        clock: Option<&crate::lease::TestClock>,
        swap_ca: Option<bool>,
    ) -> (Self, AuthOperation, watch::Receiver<Arc<Policy>>) {
        let (mut running, mut service, pac) = Self::setup(origins, swap_ca);
        let operation = running
            .handle
            .try_authenticate_bound(
                password(origins),
                &running.handle.binding(),
                cancel,
                interactive,
            )
            .unwrap();
        if let Some(clock) = clock {
            let mut command = service.commands.try_recv().unwrap();
            command.lease = clock.lease(None);
            command.budget = Deadline::after(clock.sample(), AUTH_TIMEOUT).unwrap();
            command.conversation_end =
                Deadline::after(clock.sample(), CONVERSATION_TIMEOUT).unwrap();
            assert!(running.handle.commands.try_send(command).is_ok());
        }
        running.task = Some(tokio::spawn(service.run()));
        (running, operation, pac)
    }
    fn zero(&self) {
        let status = self.connector.status();
        assert!(!status.available);
        assert_eq!(
            status.active_tcp
                + status.pending_tcp
                + status.active_udp
                + status.closing_tcp
                + status.command_queue
                + status.incoming_packets
                + status.outgoing_packets,
            0
        );
    }
    async fn close(mut self) {
        self.stop.cancel();
        timeout(STEP, self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(self.handle.phase(), ServicePhase::Stopped);
        self.zero();
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
async fn challenge(operation: &mut AuthOperation) -> ChallengeRequest {
    match timeout(STEP, operation.next_event()).await.unwrap() {
        Ok(AuthEvent::Challenge(challenge)) => challenge,
        _ => panic!("expected portal challenge"),
    }
}
async fn failure(operation: &mut AuthOperation) -> AuthFailure {
    timeout(STEP, operation.next_event())
        .await
        .unwrap()
        .err()
        .expect("unexpected portal auth progress")
}
async fn prepared(operation: &mut AuthOperation) {
    assert!(matches!(
        timeout(STEP, operation.next_event()).await.unwrap(),
        Ok(AuthEvent::Prepared)
    ));
}
async fn finish(running: Running, operation: AuthOperation, origins: DualOrigins) {
    drop(operation);
    running.close().await;
    origins.close().await;
}
async fn proxy(address: SocketAddr, socks: bool) -> TcpStream {
    timeout(STEP, async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        let name = if socks {
            "socks.synthetic-portal.invalid"
        } else {
            "http.synthetic-portal.invalid"
        };
        if socks {
            stream.write_all(&[5, 1, 0]).await.unwrap();
            let mut greeting = [0; 2];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 0]);
            let mut request = vec![5, 1, 0, 3, name.len() as u8];
            request.extend(name.as_bytes());
            request.extend([1, 187]);
            stream.write_all(&request).await.unwrap();
            let mut reply = [0; 10];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[..2], &[5, 0]);
        } else {
            stream
                .write_all(
                    format!("CONNECT {name}:443 HTTP/1.1\r\nHost: {name}:443\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 4096);
                header.push(stream.read_u8().await.unwrap());
            }
            assert!(header.starts_with(b"HTTP/1.1 200 "));
        }
        let payload: Vec<u8> = (0..8192).map(|index| (index % 251) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        let mut echo = vec![0; payload.len()];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(echo, payload);
        stream
    })
    .await
    .unwrap()
}
async fn successful_flow(rounds: u8) {
    let origins = DualOrigins::start(Plan {
        rounds,
        ..Plan::default()
    })
    .await;
    let (running, mut operation, pac) =
        Running::start(&origins, rounds > 0, CancellationToken::new(), None, None);
    let mut nonces = Vec::new();
    for round in 1..=rounds {
        let request = challenge(&mut operation).await;
        assert_eq!(request.round(), round);
        assert_eq!(request.prompt(), format!("Portal answer {round}"));
        assert!(!nonces.contains(&request.nonce()));
        nonces.push(request.nonce());
        assert_eq!(origins.gateway.state.accepted.load(Ordering::SeqCst), 0);
        running.zero();
        request.respond(Zeroizing::new(answer(round))).unwrap();
    }
    prepared(&mut operation).await;
    running.zero();
    assert_eq!(origins.gateway.state.count(CONFIG), 1);
    assert_eq!(origins.gateway.state.count(TUNNEL), 0);
    operation.commit().unwrap();
    wait(|| running.connector.status().available).await;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let mut generation =
        crate::session::proxy_lifecycle_tests::GenerationProbe::capture(&running.connector);
    let server = ProxyServer::bind(ProxyConfig {
        http_addr: "127.0.0.1:0".parse().unwrap(),
        socks_addr: "127.0.0.1:0".parse().unwrap(),
        max_connections: 4,
        handshake_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(15),
    })
    .await
    .unwrap();
    let addresses = server.local_addrs();
    let (stop, stopping) = watch::channel(false);
    let task = tokio::spawn(server.serve(running.connector.clone(), pac, stopping));
    let (mut http, mut socks) = tokio::join!(proxy(addresses.0, false), proxy(addresses.1, true));
    assert_eq!(origins.gateway.state.dns_queries.load(Ordering::SeqCst), 2);
    assert!(origins.gateway.state.tcp_packets.load(Ordering::SeqCst) > 0);
    assert_eq!(origins.portal.state.count(PORTAL_PRELOGIN), 1);
    assert_eq!(
        origins.portal.state.count(PORTAL_LOGIN),
        usize::from(rounds) + 1
    );
    assert_eq!(origins.gateway.state.count(GATEWAY_LOGIN), 1);
    assert_eq!(origins.gateway.state.count(HIP), 1);
    assert_eq!(origins.gateway.state.count(TUNNEL), 1);
    running.close().await;
    for stream in [&mut http, &mut socks] {
        assert!(matches!(
            timeout(STEP, stream.read(&mut [0; 1])).await.unwrap(),
            Ok(0) | Err(_)
        ));
    }
    drop((http, socks));
    stop.send(true).unwrap();
    timeout(STEP, task).await.unwrap().unwrap().unwrap();
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        assert!(generation.is_closed());
        generation.release_stack();
        wait(|| !generation.generation_alive()).await;
    }
    assert_eq!(origins.gateway.state.count(LOGOUT), 1);
    assert_eq!(
        origins
            .portal
            .state
            .trace()
            .iter()
            .filter(|request| request.path == LOGOUT)
            .count(),
        0
    );
    let portal_requests = origins.portal.state.requests(PORTAL_LOGIN);
    assert_eq!(portal_requests[0].fields["passwd"], PASSWORD);
    origins.close().await;
    let _http = tokio::net::TcpListener::bind(addresses.0).await.unwrap();
    let _socks = tokio::net::TcpListener::bind(addresses.1).await.unwrap();
}
#[tokio::test]
async fn portal_password_handoff_reaches_both_proxies_and_real_memory_dns() {
    successful_flow(0).await;
}
#[tokio::test]
async fn portal_four_rounds_handoff_reaches_both_proxies_and_releases_generation() {
    successful_flow(4).await;
}

#[tokio::test]
async fn portal_service_admission_rejects_role_and_both_origin_mismatches_before_traffic() {
    let origins = DualOrigins::start(Plan::default()).await;
    let (mut running, service, _) = Running::setup(&origins, None);
    running.task = Some(tokio::spawn(service.run()));
    let binding = running.handle.binding();
    let direct = AuthBinding::direct(&origins.gateway.origin).unwrap();
    let other_portal =
        AuthBinding::via_portal("https://other.invalid:8443", &origins.gateway.origin).unwrap();
    let other_gateway =
        AuthBinding::via_portal(&origins.portal.origin, "https://other.invalid:9443").unwrap();
    for supplied in [direct, other_portal, other_gateway] {
        assert!(matches!(
            running.handle.try_authenticate_bound(
                password(&origins),
                &supplied,
                CancellationToken::new(),
                true
            ),
            Err(StartError::GatewayMismatch)
        ));
    }
    let direct_password = AuthInput::Password {
        user: USER.into(),
        password: Zeroizing::new(PASSWORD.into()),
        computer: COMPUTER.into(),
    };
    assert!(matches!(
        running.handle.try_authenticate_bound(
            direct_password,
            &binding,
            CancellationToken::new(),
            true
        ),
        Err(StartError::GatewayMismatch)
    ));
    let imported = AuthInput::Session(
        Session::new(
            USER.into(),
            "public-unsubmitted-session-cookie".into(),
            "synthetic-portal".into(),
            "domain".into(),
            COMPUTER.into(),
            None,
        )
        .unwrap(),
    );
    assert!(matches!(
        running
            .handle
            .try_authenticate_bound(imported, &binding, CancellationToken::new(), true),
        Err(StartError::GatewayMismatch)
    ));
    let wrong = AuthInput::PortalPassword {
        portal: origins.gateway.origin.clone(),
        user: USER.into(),
        password: Zeroizing::new(PASSWORD.into()),
        computer: COMPUTER.into(),
    };
    assert!(matches!(
        running
            .handle
            .try_authenticate_bound(wrong, &binding, CancellationToken::new(), true),
        Err(StartError::GatewayMismatch)
    ));
    assert_eq!(running.handle.phase(), ServicePhase::Waiting);
    assert_eq!(origins.portal.state.accepted.load(Ordering::SeqCst), 0);
    assert_eq!(origins.gateway.state.accepted.load(Ordering::SeqCst), 0);
    running.close().await;
    origins.close().await;
}
#[tokio::test]
async fn portal_and_gateway_require_their_independent_ca_trust() {
    for portal_wrong in [true, false] {
        let origins = DualOrigins::start(Plan::default()).await;
        let (running, mut operation, _) = Running::start(
            &origins,
            false,
            CancellationToken::new(),
            None,
            Some(portal_wrong),
        );
        assert_eq!(
            failure(&mut operation).await,
            AuthFailure::TransportUnavailable
        );
        assert_eq!(origins.gateway.state.count(GATEWAY_LOGIN), 0);
        assert_eq!(
            origins.portal.state.count(PORTAL_LOGIN),
            usize::from(!portal_wrong)
        );
        if portal_wrong {
            assert_eq!(origins.gateway.state.accepted.load(Ordering::SeqCst), 0);
        }
        finish(running, operation, origins).await;
    }
}
#[tokio::test]
async fn cancelled_admitted_portal_input_opens_no_connection() {
    let origins = DualOrigins::start(Plan::default()).await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let (running, mut operation, _) = Running::start(&origins, false, cancel, None, None);
    assert_eq!(failure(&mut operation).await, AuthFailure::Cancelled);
    assert_eq!(origins.portal.state.accepted.load(Ordering::SeqCst), 0);
    assert_eq!(origins.gateway.state.accepted.load(Ordering::SeqCst), 0);
    finish(running, operation, origins).await;
}
#[tokio::test]
async fn portal_prelogin_cancel_is_prompt_and_never_posts_password() {
    let origins = DualOrigins::start(Plan::default()).await;
    origins
        .portal
        .state
        .hold_prelogin
        .store(true, Ordering::SeqCst);
    let cancel = CancellationToken::new();
    let (running, mut operation, _) = Running::start(&origins, false, cancel.clone(), None, None);
    wait(|| origins.portal.state.count(PORTAL_PRELOGIN) == 1).await;
    cancel.cancel();
    assert_eq!(
        timeout(Duration::from_secs(1), failure(&mut operation))
            .await
            .unwrap(),
        AuthFailure::Cancelled
    );
    assert_eq!(origins.portal.state.count(PORTAL_LOGIN), 0);
    assert_eq!(origins.gateway.state.accepted.load(Ordering::SeqCst), 0);
    origins.portal.state.release_prelogin.add_permits(1);
    finish(running, operation, origins).await;
}
#[tokio::test]
async fn cancel_during_each_credential_tls_setup_prevents_that_first_post() {
    for stage in 0..3 {
        let origins = DualOrigins::start(Plan {
            rounds: u8::from(stage == 1),
            ..Plan::default()
        })
        .await;
        let endpoint = if stage == 2 {
            &origins.gateway
        } else {
            &origins.portal
        };
        endpoint.state.hold_tls_at.store(
            if stage == 2 {
                1
            } else if stage == 1 {
                3
            } else {
                2
            },
            Ordering::SeqCst,
        );
        let cancel = CancellationToken::new();
        let (running, mut operation, _) =
            Running::start(&origins, stage == 1, cancel.clone(), None, None);
        if stage == 1 {
            challenge(&mut operation)
                .await
                .respond(Zeroizing::new(answer(1)))
                .unwrap();
        }
        wait(|| endpoint.state.tls_waiting.load(Ordering::SeqCst)).await;
        cancel.cancel();
        endpoint.state.release_tls.add_permits(1);
        assert_eq!(failure(&mut operation).await, AuthFailure::Cancelled);
        assert_eq!(
            origins.portal.state.count(PORTAL_LOGIN),
            usize::from(stage != 0)
        );
        assert_eq!(origins.gateway.state.count(GATEWAY_LOGIN), 0);
        assert_eq!(origins.gateway.state.count(LOGOUT), 0);
        finish(running, operation, origins).await;
    }
}
#[tokio::test]
async fn cancellation_before_policy_arrives_drops_handoff_without_gateway_dial() {
    let origins = DualOrigins::start(Plan::default()).await;
    origins
        .portal
        .state
        .hold_response
        .store(true, Ordering::SeqCst);
    let cancel = CancellationToken::new();
    let (running, mut operation, _) = Running::start(&origins, false, cancel.clone(), None, None);
    wait(|| origins.portal.state.response_waiting.load(Ordering::SeqCst)).await;
    cancel.cancel();
    origins.portal.state.release_response.add_permits(1);
    assert_eq!(failure(&mut operation).await, AuthFailure::Cancelled);
    assert_eq!(origins.gateway.state.accepted.load(Ordering::SeqCst), 0);
    finish(running, operation, origins).await;
}
#[tokio::test]
async fn issued_gateway_cookie_post_retains_late_session_for_exactly_one_logout() {
    let origins = DualOrigins::start(Plan::default()).await;
    origins
        .gateway
        .state
        .hold_response
        .store(true, Ordering::SeqCst);
    origins
        .gateway
        .state
        .hold_logout
        .store(true, Ordering::SeqCst);
    let cancel = CancellationToken::new();
    let (running, mut operation, _) = Running::start(&origins, false, cancel.clone(), None, None);
    wait(|| {
        origins
            .gateway
            .state
            .response_waiting
            .load(Ordering::SeqCst)
    })
    .await;
    cancel.cancel();
    origins.gateway.state.release_response.add_permits(1);
    wait(|| origins.gateway.state.count(LOGOUT) == 1).await;
    running.zero();
    assert_ne!(running.handle.phase(), ServicePhase::Waiting);
    assert!(matches!(
        running.handle.try_authenticate_bound(
            password(&origins),
            &running.handle.binding(),
            CancellationToken::new(),
            false
        ),
        Err(StartError::Busy)
    ));
    assert_eq!(origins.gateway.state.count(CONFIG), 0);
    assert_eq!(origins.gateway.state.count(TUNNEL), 0);
    origins.gateway.state.release_logout.add_permits(1);
    assert_eq!(failure(&mut operation).await, AuthFailure::Cancelled);
    assert_eq!(running.handle.phase(), ServicePhase::Waiting);
    finish(running, operation, origins).await;
}
#[tokio::test]
async fn cookie_rejection_or_new_gateway_challenge_never_replays_any_credential() {
    for outcome in [GatewayOutcome::Rejected, GatewayOutcome::Challenge] {
        let origins = DualOrigins::start(Plan {
            gateway: outcome,
            ..Plan::default()
        })
        .await;
        let (running, mut operation, _) =
            Running::start(&origins, true, CancellationToken::new(), None, None);
        assert_eq!(
            failure(&mut operation).await,
            if matches!(outcome, GatewayOutcome::Rejected) {
                AuthFailure::AuthenticationRequired
            } else {
                AuthFailure::UnsupportedAuthentication
            }
        );
        assert_eq!(origins.portal.state.count(PORTAL_LOGIN), 1);
        assert_eq!(origins.gateway.state.count(GATEWAY_LOGIN), 1);
        assert_eq!(origins.gateway.state.count(CONFIG), 0);
        assert_eq!(origins.gateway.state.count(LOGOUT), 0);
        finish(running, operation, origins).await;
    }
}
#[tokio::test]
async fn missing_selected_gateway_or_cookie_fails_before_gateway_connection() {
    for outcome in [PolicyOutcome::MissingGateway, PolicyOutcome::MissingCookie] {
        let origins = DualOrigins::start(Plan {
            policy: outcome,
            ..Plan::default()
        })
        .await;
        let (running, mut operation, _) =
            Running::start(&origins, false, CancellationToken::new(), None, None);
        let failure = failure(&mut operation).await;
        assert!(matches!(
            failure,
            AuthFailure::ProtocolError
                | AuthFailure::UnsupportedAuthentication
                | AuthFailure::ConfigurationRejected
        ));
        assert_eq!(origins.gateway.state.accepted.load(Ordering::SeqCst), 0);
        finish(running, operation, origins).await;
    }
}
#[tokio::test]
async fn original_password_deadline_is_not_restarted_at_portal_handoff() {
    let origins = DualOrigins::start(Plan::default()).await;
    origins
        .portal
        .state
        .hold_response
        .store(true, Ordering::SeqCst);
    let clock = crate::lease::TestClock::new();
    let (running, mut operation, _) = Running::start(
        &origins,
        false,
        CancellationToken::new(),
        Some(&clock),
        None,
    );
    wait(|| origins.portal.state.response_waiting.load(Ordering::SeqCst)).await;
    clock.advance(Duration::ZERO, AUTH_TIMEOUT);
    origins.portal.state.release_response.add_permits(1);
    assert_eq!(failure(&mut operation).await, AuthFailure::TimedOut);
    assert_eq!(origins.gateway.state.accepted.load(Ordering::SeqCst), 0);
    finish(running, operation, origins).await;
}
#[tokio::test]
async fn absolute_conversation_deadline_reaches_the_gateway_tls_first_write_gate() {
    let origins = DualOrigins::start(Plan {
        rounds: 4,
        ..Plan::default()
    })
    .await;
    origins.gateway.state.hold_tls_at.store(1, Ordering::SeqCst);
    let clock = crate::lease::TestClock::new();
    let (running, mut operation, _) =
        Running::start(&origins, true, CancellationToken::new(), Some(&clock), None);
    for round in 1..=4 {
        let request = challenge(&mut operation).await;
        assert_eq!(
            request.remaining().unwrap(),
            Duration::from_secs(if round == 4 { 60 } else { 90 })
        );
        clock.advance(
            Duration::ZERO,
            Duration::from_secs(if round == 4 { 59 } else { 80 }),
        );
        request.respond(Zeroizing::new(answer(round))).unwrap();
    }
    wait(|| origins.gateway.state.tls_waiting.load(Ordering::SeqCst)).await;
    clock.advance(Duration::ZERO, Duration::from_secs(1));
    origins.gateway.state.release_tls.add_permits(1);
    assert_eq!(failure(&mut operation).await, AuthFailure::TimedOut);
    assert_eq!(origins.gateway.state.count(GATEWAY_LOGIN), 0);
    finish(running, operation, origins).await;
}
#[tokio::test]
async fn expired_portal_prompt_cannot_submit_an_answer() {
    let origins = DualOrigins::start(Plan {
        rounds: 1,
        ..Plan::default()
    })
    .await;
    let clock = crate::lease::TestClock::new();
    let (running, mut operation, _) =
        Running::start(&origins, true, CancellationToken::new(), Some(&clock), None);
    let request = challenge(&mut operation).await;
    clock.advance(Duration::ZERO, Duration::from_secs(90));
    assert_eq!(
        request.respond(Zeroizing::new(answer(1))),
        Err(AuthFailure::TimedOut)
    );
    assert!(matches!(
        failure(&mut operation).await,
        AuthFailure::Cancelled | AuthFailure::TimedOut
    ));
    assert_eq!(origins.portal.state.count(PORTAL_LOGIN), 1);
    assert_eq!(origins.gateway.state.accepted.load(Ordering::SeqCst), 0);
    finish(running, operation, origins).await;
}
