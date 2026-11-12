//! Stop admission and cleanup evidence; only public synthetic loopback TLS.
use super::challenge_tests::gateway::{wait, Gateway, Outcome, LOGIN, LOGOUT, STEP};
use super::*;
use std::sync::Barrier;
use tokio::{task::JoinHandle, time::timeout};

fn password() -> AuthInput {
    AuthInput::Password {
        user: "original-user".into(),
        password: Zeroizing::new("initial-secret".into()),
        computer: "fixed-computer".into(),
    }
}

fn setup(client: GatewayClient) -> (ServiceHandle, Service, CancellationToken) {
    let config = Config {
        gateway: client.gateway().to_string(),
        ..Config::default()
    };
    let shutdown = CancellationToken::new();
    let connector = Arc::new(TunnelConnector::default());
    let (pac, _) = watch::channel(Arc::new(Policy::new(vec![], vec![]).unwrap()));
    let (handle, service) = new(config, client, connector, pac, shutdown.clone()).unwrap();
    (handle, service, shutdown)
}

async fn joined(task: JoinHandle<()>, handle: &ServiceHandle) -> CleanupSummary {
    timeout(STEP, task)
        .await
        .expect("service cleanup deadline")
        .unwrap();
    assert_eq!(handle.phase(), ServicePhase::Stopped);
    handle.completion().expect("normal service completion")
}

async fn imported(gateway: &Gateway) -> Session {
    timeout(
        STEP,
        gateway
            .client
            .login("original-user", "initial-secret", "fixed-computer"),
    )
    .await
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn stopping_races_admission_without_reopening_or_posting() {
    let client = GatewayClient::new(
        Url::parse("https://127.0.0.1:1").unwrap(),
        crate::tls::client_config(None).unwrap(),
        crate::gp::ResumptionPolicy::Disabled,
    )
    .unwrap();
    for _ in 0..32 {
        let (handle, service, _shutdown) = setup(client.clone());
        let barrier = Barrier::new(2);
        let admitted = std::thread::scope(|scope| {
            let stopping = scope.spawn(|| {
                barrier.wait();
                assert!(handle.request_stop());
            });
            barrier.wait();
            let admitted = handle.try_authenticate(
                password(),
                handle.binding().gateway(),
                CancellationToken::new(),
            );
            stopping.join().unwrap();
            admitted
        });
        assert!(!handle.request_stop());
        assert!(handle.completion().is_none());
        service.run().await;
        if let Ok(mut operation) = admitted {
            assert_eq!(operation.prepared().await, Err(AuthFailure::Stopped));
        } else {
            assert!(matches!(admitted, Err(StartError::Stopped)));
        }
        assert_eq!(handle.completion(), Some(CleanupSummary::default()));
        assert!(matches!(
            handle.try_authenticate(
                password(),
                handle.binding().gateway(),
                CancellationToken::new()
            ),
            Err(StartError::Stopped)
        ));
    }
}

#[tokio::test]
async fn admitted_imported_cookie_is_drained_after_explicit_or_signal_stop() {
    for explicit in [true, false] {
        let gateway = Gateway::start([Outcome::Session]).await;
        let cookie = imported(&gateway).await;
        gateway.state.hold_logout.store(true, Ordering::SeqCst);
        let (handle, service, shutdown) = setup(gateway.client.clone());
        let _cancel = shutdown.clone().drop_guard();
        let mut operation = handle
            .try_authenticate(
                AuthInput::Session(cookie),
                &gateway.origin,
                CancellationToken::new(),
            )
            .unwrap();
        if explicit {
            assert!(handle.request_stop());
        } else {
            shutdown.cancel();
        }
        let task = tokio::spawn(service.run());
        wait(|| gateway.state.count(LOGOUT) == 1).await;
        assert!(
            handle.completion().is_none(),
            "logout must finish before completion"
        );
        assert!(matches!(
            handle.try_authenticate(password(), &gateway.origin, CancellationToken::new()),
            Err(StartError::Stopped)
        ));
        gateway.state.release_logout.add_permits(1);
        assert_eq!(
            joined(task, &handle).await,
            CleanupSummary {
                known_sessions: 1,
                logout_confirmed: 1,
                ..CleanupSummary::default()
            }
        );
        assert_eq!(operation.prepared().await, Err(AuthFailure::Stopped));
        assert_eq!(
            gateway.state.count(LOGIN),
            1,
            "only fixture cookie creation may login"
        );
        assert_eq!(gateway.state.count(LOGOUT), 1);
        gateway.close().await;
    }
}

#[tokio::test]
async fn issued_post_finishes_late_cookie_logout_before_stop_completion() {
    let gateway = Gateway::start([Outcome::HeldSession]).await;
    gateway.state.hold_logout.store(true, Ordering::SeqCst);
    let (handle, service, shutdown) = setup(gateway.client.clone());
    let _cancel = shutdown.drop_guard();
    let mut operation = handle
        .try_authenticate(password(), &gateway.origin, CancellationToken::new())
        .unwrap();
    let task = tokio::spawn(service.run());
    wait(|| gateway.state.count(LOGIN) == 1).await;
    assert!(handle.request_stop());
    assert!(handle.completion().is_none());
    gateway.state.release_login.add_permits(1);
    wait(|| gateway.state.count(LOGOUT) == 1).await;
    assert!(handle.completion().is_none());
    gateway.state.release_logout.add_permits(1);
    assert_eq!(
        joined(task, &handle).await,
        CleanupSummary {
            known_sessions: 1,
            logout_confirmed: 1,
            ..CleanupSummary::default()
        }
    );
    assert_eq!(operation.prepared().await, Err(AuthFailure::Cancelled));
    assert_eq!(gateway.state.count(LOGIN), 1);
    assert_eq!(gateway.state.count(LOGOUT), 1);
    gateway.close().await;
}

#[tokio::test]
async fn valid_challenge_then_stop_does_not_invent_unknown_session() {
    let gateway = Gateway::start([Outcome::Challenge(1)]).await;
    let (handle, service, shutdown) = setup(gateway.client.clone());
    let _cancel = shutdown.drop_guard();
    let mut operation = handle
        .try_authenticate_interactive(password(), &gateway.origin, CancellationToken::new())
        .unwrap();
    let task = tokio::spawn(service.run());
    let request = match timeout(STEP, operation.next_event())
        .await
        .unwrap()
        .unwrap()
    {
        AuthEvent::Challenge(request) => request,
        _ => panic!("expected synthetic challenge"),
    };
    assert!(handle.request_stop());
    drop(request);
    assert_eq!(joined(task, &handle).await, CleanupSummary::default());
    assert_eq!(gateway.state.count(LOGIN), 1);
    assert_eq!(gateway.state.count(LOGOUT), 0);
    gateway.close().await;
}

#[tokio::test]
async fn stop_during_tls_before_credential_gate_has_no_unknown_post() {
    let gateway = Gateway::start([Outcome::Session]).await;
    gateway.state.hold_tls_at.store(2, Ordering::SeqCst);
    let (handle, service, shutdown) = setup(gateway.client.clone());
    let _cancel = shutdown.drop_guard();
    let _operation = handle
        .try_authenticate(password(), &gateway.origin, CancellationToken::new())
        .unwrap();
    let task = tokio::spawn(service.run());
    wait(|| gateway.state.tls_waiting.load(Ordering::SeqCst)).await;
    assert!(handle.request_stop());
    gateway.state.release_tls.add_permits(1);
    assert_eq!(joined(task, &handle).await, CleanupSummary::default());
    assert_eq!(gateway.state.count(LOGIN), 0);
    assert_eq!(gateway.state.count(LOGOUT), 0);
    gateway.close().await;
}

#[tokio::test]
async fn logout_timeout_is_completed_but_explicitly_unconfirmed() {
    let gateway = Gateway::start([Outcome::Session]).await;
    let cookie = imported(&gateway).await;
    gateway.state.hold_logout.store(true, Ordering::SeqCst);
    let (handle, service, shutdown) = setup(gateway.client.clone());
    let _cancel = shutdown.drop_guard();
    let _operation = handle
        .try_authenticate(
            AuthInput::Session(cookie),
            &gateway.origin,
            CancellationToken::new(),
        )
        .unwrap();
    assert!(handle.request_stop());
    let task = tokio::spawn(service.run());
    wait(|| gateway.state.count(LOGOUT) == 1).await;
    assert!(handle.completion().is_none());
    let summary = joined(task, &handle).await;
    // Release the synthetic server even if its later write observes our EOF.
    gateway.state.release_logout.add_permits(1);
    gateway.close().await;
    assert_eq!(
        summary,
        CleanupSummary {
            known_sessions: 1,
            logout_unconfirmed: 1,
            ..CleanupSummary::default()
        }
    );
}

#[tokio::test]
async fn abort_never_publishes_normal_completion() {
    let gateway = Gateway::start([]).await;
    let (handle, service, shutdown) = setup(gateway.client.clone());
    let _cancel = shutdown.drop_guard();
    let task = tokio::spawn(service.run());
    tokio::task::yield_now().await;
    task.abort();
    assert!(timeout(STEP, task)
        .await
        .unwrap()
        .unwrap_err()
        .is_cancelled());
    assert!(handle.completion().is_none());
    assert_eq!(handle.phase(), ServicePhase::Stopped);
    assert_eq!(gateway.state.count(LOGIN), 0);
    gateway.close().await;
}
