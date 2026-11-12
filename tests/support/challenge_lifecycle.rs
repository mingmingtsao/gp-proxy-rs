//! Independent service/IPC challenge lifecycle checks with synthetic TLS only.
use super::*;
#[path = "challenge_gateway.rs"]
pub(crate) mod gateway;
#[cfg(all(
    any(target_os = "macos", target_os = "linux"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "challenge_ipc.rs"]
mod ipc_tests;
use gateway::{wait, Gateway, Outcome, CONFIG, LOGIN, LOGOUT, PRELOGIN, STEP, TUNNEL};
use std::sync::atomic::Ordering;
use tokio::{task::JoinHandle, time::timeout};

fn password() -> AuthInput {
    AuthInput::Password {
        user: "original-user".into(),
        password: Zeroizing::new("initial-secret".into()),
        computer: "fixed-computer".into(),
    }
}

struct Running {
    handle: ServiceHandle,
    connector: Arc<TunnelConnector>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl Running {
    fn setup(gateway: &Gateway) -> (Self, Service) {
        let config = Config {
            gateway: gateway.origin.clone(),
            domains: vec!["synthetic-challenge.invalid".into()],
            ..Config::default()
        };
        let stop = CancellationToken::new();
        let connector = Arc::new(TunnelConnector::default());
        let (pac, _) = watch::channel(Arc::new(Policy::new(vec![], vec![]).unwrap()));
        let (handle, service) = new(
            config,
            gateway.client.clone(),
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
        )
    }
    fn start(
        gateway: &Gateway,
        interactive: bool,
        cancel: CancellationToken,
    ) -> (Self, AuthOperation) {
        Self::clocked(gateway, interactive, cancel, None)
    }
    fn clocked(
        gateway: &Gateway,
        interactive: bool,
        cancel: CancellationToken,
        clock: Option<&crate::lease::TestClock>,
    ) -> (Self, AuthOperation) {
        let (mut running, mut service) = Self::setup(gateway);
        let operation = if interactive {
            running
                .handle
                .try_authenticate_interactive(password(), &gateway.origin, cancel)
        } else {
            running
                .handle
                .try_authenticate(password(), &gateway.origin, cancel)
        }
        .unwrap();
        if let Some(clock) = clock {
            // Replace only this queued command's test clock before the actor
            // polls it. Production admission still creates both deadlines once.
            let mut command = service.commands.try_recv().unwrap();
            command.lease = clock.lease(None);
            command.budget = Deadline::after(clock.sample(), AUTH_TIMEOUT).unwrap();
            command.conversation_end =
                Deadline::after(clock.sample(), CONVERSATION_TIMEOUT).unwrap();
            assert!(running.handle.commands.try_send(command).is_ok());
        }
        running.task = Some(tokio::spawn(service.run()));
        (running, operation)
    }
    async fn close(mut self) {
        self.stop.cancel();
        timeout(STEP, self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(self.handle.phase(), ServicePhase::Stopped);
        assert!(!self.connector.status().available);
    }
    fn closed_egress(&self) {
        assert!(!self.connector.status().available);
        assert_eq!(self.connector.status().active_tcp, 0);
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

async fn challenge(operation: &mut AuthOperation) -> ChallengeRequest {
    match timeout(STEP, operation.next_event()).await.unwrap() {
        Ok(AuthEvent::Challenge(request)) => request,
        Ok(AuthEvent::Prepared) => panic!("session prepared before the expected answer"),
        Err(failure) => panic!("challenge failed: {failure:?}"),
    }
}
async fn failure(operation: &mut AuthOperation) -> AuthFailure {
    match timeout(STEP, operation.next_event()).await.unwrap() {
        Err(failure) => failure,
        Ok(_) => panic!("unexpected authentication progress after cancellation/failure"),
    }
}

#[tokio::test]
async fn two_fresh_answers_preserve_identity_and_prepare_before_egress() {
    let gateway = Gateway::start([
        Outcome::Challenge(1),
        Outcome::Challenge(2),
        Outcome::Session,
    ])
    .await;
    let (running, mut operation) = Running::start(&gateway, true, CancellationToken::new());
    let first = challenge(&mut operation).await;
    assert_eq!(first.prompt(), "Enter answer 1");
    assert_eq!(first.round(), 1);
    assert!(first.remaining().unwrap() <= Duration::from_secs(90));
    let nonce = first.nonce();
    running.closed_egress();
    assert_eq!(gateway.state.count(CONFIG), 0);
    first
        .respond(Zeroizing::new("new-answer-one".into()))
        .unwrap();
    let second = challenge(&mut operation).await;
    assert_eq!(second.round(), 2);
    assert_ne!(second.nonce(), nonce);
    running.closed_egress();
    second
        .respond(Zeroizing::new("new-answer-two".into()))
        .unwrap();
    assert!(matches!(
        timeout(STEP, operation.next_event()).await.unwrap(),
        Ok(AuthEvent::Prepared)
    ));
    running.closed_egress();
    assert_eq!(gateway.state.count(CONFIG), 1);
    assert_eq!(gateway.state.count(TUNNEL), 0);
    let requests = gateway.state.requests(LOGIN);
    assert_eq!(requests.len(), 3);
    assert_eq!(gateway.state.count(PRELOGIN), 1);
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(request.fields["user"], "original-user");
        assert_eq!(request.fields["computer"], "fixed-computer");
        assert_eq!(
            request.fields["passwd"],
            ["initial-secret", "new-answer-one", "new-answer-two"][index]
        );
        if index == 0 {
            assert!(!request.fields.contains_key("inputStr"));
        } else {
            assert_eq!(request.fields["inputStr"], format!("state-{index}&opaque"));
        }
    }
    operation.commit().unwrap();
    wait(|| running.connector.status().available).await;
    assert_eq!(gateway.state.count(TUNNEL), 1);
    running.close().await;
    assert_eq!(gateway.state.count(LOGOUT), 1);
    gateway.close().await;
}

#[tokio::test]
async fn noninteractive_and_legacy_prepared_do_not_replay_the_initial_password() {
    for interactive in [false, true] {
        let gateway = Gateway::start([Outcome::Challenge(1)]).await;
        let (running, mut operation) =
            Running::start(&gateway, interactive, CancellationToken::new());
        assert_eq!(
            timeout(STEP, operation.prepared()).await.unwrap(),
            Err(AuthFailure::InteractiveRequired)
        );
        wait(|| running.handle.phase() == ServicePhase::Waiting).await;
        running.closed_egress();
        assert_eq!(gateway.state.count(LOGIN), 1);
        assert_eq!(gateway.state.count(CONFIG), 0);
        assert_eq!(gateway.state.count(LOGOUT), 0);
        drop(operation);
        running.close().await;
        gateway.close().await;
    }
}

#[tokio::test]
async fn dropped_prompt_operation_and_explicit_cancel_retire_the_answer_capability() {
    for variant in 0..3 {
        let gateway = Gateway::start([Outcome::Challenge(1)]).await;
        let cancel = CancellationToken::new();
        let (running, operation) = Running::start(&gateway, true, cancel.clone());
        let mut operation = Some(operation);
        let request = challenge(operation.as_mut().unwrap()).await;
        let mut request = Some(request);
        match variant {
            0 => cancel.cancel(),
            1 => drop(request.take()),
            _ => drop(operation.take()),
        }
        wait(|| running.handle.phase() == ServicePhase::Waiting).await;
        if let Some(request) = request {
            assert_eq!(
                request.respond(Zeroizing::new("too-late-answer".into())),
                Err(AuthFailure::Cancelled)
            );
        }
        if let Some(mut operation) = operation {
            assert_eq!(failure(&mut operation).await, AuthFailure::Cancelled);
        }
        running.closed_egress();
        assert_eq!(gateway.state.count(LOGIN), 1);
        assert_eq!(gateway.state.count(CONFIG), 0);
        assert_eq!(gateway.state.count(LOGOUT), 0);
        running.close().await;
        gateway.close().await;
    }
}

#[tokio::test]
async fn cancellation_during_answer_post_retains_the_late_cookie_until_logout() {
    let gateway = Gateway::start([Outcome::Challenge(1), Outcome::HeldSession]).await;
    gateway.state.hold_logout.store(true, Ordering::SeqCst);
    let cancel = CancellationToken::new();
    let (running, mut operation) = Running::start(&gateway, true, cancel.clone());
    challenge(&mut operation)
        .await
        .respond(Zeroizing::new("single-answer".into()))
        .unwrap();
    wait(|| gateway.state.count(LOGIN) == 2).await;
    cancel.cancel();
    assert!(matches!(
        running
            .handle
            .try_authenticate(password(), &gateway.origin, CancellationToken::new()),
        Err(StartError::Busy)
    ));
    gateway.state.release_login.add_permits(1);
    wait(|| gateway.state.count(LOGOUT) == 1).await;
    assert_eq!(running.handle.phase(), ServicePhase::Cleaning);
    assert!(matches!(
        running
            .handle
            .try_authenticate(password(), &gateway.origin, CancellationToken::new()),
        Err(StartError::Busy)
    ));
    running.closed_egress();
    gateway.state.release_logout.add_permits(1);
    assert_eq!(failure(&mut operation).await, AuthFailure::Cancelled);
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    assert_eq!(gateway.state.count(LOGIN), 2);
    assert_eq!(gateway.state.count(CONFIG), 0);
    assert_eq!(gateway.state.count(TUNNEL), 0);
    drop(operation);
    running.close().await;
    assert_eq!(gateway.state.count(LOGOUT), 1);
    gateway.close().await;
}

#[tokio::test]
async fn prelogin_cancellation_does_not_wait_for_the_readonly_server_or_post_a_secret() {
    let gateway = Gateway::start([]).await;
    gateway.state.hold_prelogin.store(true, Ordering::SeqCst);
    let cancel = CancellationToken::new();
    let (running, mut operation) = Running::start(&gateway, true, cancel.clone());
    wait(|| gateway.state.count(PRELOGIN) == 1).await;
    cancel.cancel();
    assert_eq!(
        timeout(Duration::from_secs(1), failure(&mut operation))
            .await
            .unwrap(),
        AuthFailure::Cancelled
    );
    assert_eq!(running.handle.phase(), ServicePhase::Waiting);
    assert_eq!(gateway.state.count(LOGIN), 0);
    gateway.state.release_prelogin.add_permits(1);
    drop(operation);
    running.close().await;
    gateway.close().await;
}

#[tokio::test]
async fn each_prompt_is_bounded_and_the_conversation_never_reanchors() {
    let gateway = Gateway::start((1..=4).map(Outcome::Challenge)).await;
    let clock = crate::lease::TestClock::new();
    let (running, mut operation) =
        Running::clocked(&gateway, true, CancellationToken::new(), Some(&clock));
    for round in 1..=4 {
        let request = challenge(&mut operation).await;
        assert_eq!(request.round(), round);
        assert_eq!(
            request.remaining().unwrap(),
            Duration::from_secs(if round == 4 { 60 } else { 90 })
        );
        if round < 4 {
            clock.advance(Duration::ZERO, Duration::from_secs(80));
            request
                .respond(Zeroizing::new(format!("fresh-{round}")))
                .unwrap();
        } else {
            clock.advance(Duration::ZERO, Duration::from_secs(60));
            assert_eq!(
                request.respond(Zeroizing::new("expired-answer".into())),
                Err(AuthFailure::TimedOut)
            );
        }
    }
    assert_eq!(failure(&mut operation).await, AuthFailure::TimedOut);
    assert_eq!(gateway.state.count(LOGIN), 4);
    assert_eq!(gateway.state.count(CONFIG), 0);
    running.closed_egress();
    drop(operation);
    running.close().await;
    gateway.close().await;
}

#[tokio::test]
async fn prompt_wall_expiry_and_rollback_never_submit_buffered_answers() {
    for rollback in [false, true] {
        let gateway = Gateway::start([Outcome::Challenge(1)]).await;
        let clock = crate::lease::TestClock::new();
        let (running, mut operation) =
            Running::clocked(&gateway, true, CancellationToken::new(), Some(&clock));
        let request = challenge(&mut operation).await;
        if rollback {
            clock.rollback(Duration::from_secs(1));
        } else {
            clock.advance(Duration::ZERO, Duration::from_secs(90));
        }
        let expected = if rollback {
            AuthFailure::AuthenticationRequired
        } else {
            AuthFailure::TimedOut
        };
        assert_eq!(
            request.respond(Zeroizing::new("buffered-secret".into())),
            Err(expected)
        );
        assert_eq!(failure(&mut operation).await, expected);
        assert_eq!(gateway.state.count(LOGIN), 1);
        assert_eq!(gateway.state.count(CONFIG), 0);
        drop(operation);
        running.close().await;
        gateway.close().await;
    }
}

#[tokio::test]
async fn fourth_answer_may_finish_but_a_fifth_challenge_never_gets_an_answer() {
    for finish in [false, true] {
        let mut outcomes: Vec<_> = (1..=4).map(Outcome::Challenge).collect();
        outcomes.push(if finish {
            Outcome::Session
        } else {
            Outcome::Challenge(5)
        });
        let gateway = Gateway::start(outcomes).await;
        let (running, mut operation) = Running::start(&gateway, true, CancellationToken::new());
        for round in 1..=4 {
            let request = challenge(&mut operation).await;
            assert_eq!(request.round(), round);
            request
                .respond(Zeroizing::new(format!("fresh-answer-{round}")))
                .unwrap();
        }
        if finish {
            assert!(matches!(
                timeout(STEP, operation.next_event()).await.unwrap(),
                Ok(AuthEvent::Prepared)
            ));
            assert_eq!(gateway.state.count(CONFIG), 1);
        } else {
            assert_eq!(failure(&mut operation).await, AuthFailure::ProtocolError);
            assert_eq!(gateway.state.count(CONFIG), 0);
        }
        assert_eq!(gateway.state.count(LOGIN), 5);
        assert_eq!(gateway.state.count(PRELOGIN), 1);
        running.closed_egress();
        drop(operation);
        wait(|| running.handle.phase() == ServicePhase::Waiting).await;
        assert_eq!(gateway.state.count(LOGOUT), usize::from(finish));
        running.close().await;
        gateway.close().await;
    }
}

#[tokio::test]
async fn dropping_only_a_next_event_future_does_not_lose_progress_or_cancel_authentication() {
    let gateway = Gateway::start([Outcome::Challenge(1), Outcome::Session]).await;
    gateway.state.hold_prelogin.store(true, Ordering::SeqCst);
    let (running, mut operation) = Running::start(&gateway, true, CancellationToken::new());
    wait(|| gateway.state.count(PRELOGIN) == 1).await;
    assert!(timeout(Duration::from_millis(10), operation.next_event())
        .await
        .is_err());
    assert_eq!(running.handle.phase(), ServicePhase::Authenticating);
    gateway.state.release_prelogin.add_permits(1);
    challenge(&mut operation)
        .await
        .respond(Zeroizing::new("fresh-answer".into()))
        .unwrap();
    assert!(matches!(
        timeout(STEP, operation.next_event()).await.unwrap(),
        Ok(AuthEvent::Prepared)
    ));
    assert_eq!(gateway.state.count(LOGIN), 2);
    drop(operation);
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    assert_eq!(gateway.state.count(LOGOUT), 1);
    running.close().await;
    gateway.close().await;
}

async fn cancel_during_tls_setup(during_answer: bool) {
    let outcomes = if during_answer {
        vec![Outcome::Challenge(1), Outcome::Session]
    } else {
        vec![Outcome::Session]
    };
    let gateway = Gateway::start(outcomes).await;
    gateway
        .state
        .hold_tls_at
        .store(if during_answer { 3 } else { 2 }, Ordering::SeqCst);
    let cancel = CancellationToken::new();
    let (running, mut operation) = Running::start(&gateway, true, cancel.clone());
    if during_answer {
        challenge(&mut operation)
            .await
            .respond(Zeroizing::new("fresh-not-submitted-answer".into()))
            .unwrap();
    }
    wait(|| gateway.state.tls_waiting.load(Ordering::SeqCst)).await;
    let before = usize::from(during_answer);
    assert_eq!(gateway.state.count(LOGIN), before);
    cancel.cancel();
    // Finish the TLS handshake after cancellation. It has not carried any
    // credential POST yet, so no Session/remote side effect needs preserving.
    gateway.state.release_tls.add_permits(1);
    let result = failure(&mut operation).await;
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    let requests = gateway.state.count(LOGIN);
    let logouts = gateway.state.count(LOGOUT);
    let configurations = gateway.state.count(CONFIG);
    drop(operation);
    running.close().await;
    gateway.close().await;
    // Assert after all owned tasks/listeners have joined, including in the red
    // run where the undesired POST may have issued a cookie needing logout.
    assert_eq!(result, AuthFailure::Cancelled);
    assert_eq!(
        requests, before,
        "credential POST started after cancellation during TLS setup"
    );
    assert_eq!(
        logouts, 0,
        "TLS-only cancellation should not acquire a Session"
    );
    assert_eq!(configurations, 0);
}

#[tokio::test]
async fn cancellation_during_initial_tls_handshake_never_posts_password() {
    cancel_during_tls_setup(false).await;
}

#[tokio::test]
async fn cancellation_during_answer_tls_handshake_never_posts_answer() {
    cancel_during_tls_setup(true).await;
}
