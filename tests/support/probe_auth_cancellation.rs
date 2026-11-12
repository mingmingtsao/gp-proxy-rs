//! Probe authentication cancellation on real synthetic TLS, with no real gateway.
use super::*;
use crate::service::challenge_tests::gateway::{
    wait, Gateway, Outcome, CONFIG, LOGIN, LOGOUT, PRELOGIN, STEP, TUNNEL,
};
use std::sync::atomic::Ordering;
use zeroize::Zeroizing;

fn start(gateway: &Gateway) -> (CancellationToken, JoinHandle<Result<(), GpError>>) {
    let shutdown = CancellationToken::new();
    let stopping = shutdown.clone();
    let client = gateway.client.clone();
    let credentials = Credentials {
        user: Zeroizing::new("original-user".into()),
        password: Zeroizing::new("initial-secret".into()),
        gateway: gateway.origin.clone(),
    };
    let task =
        tokio::spawn(
            async move { run(&client, credentials, "fixed-computer", None, stopping).await },
        );
    (shutdown, task)
}
fn cancelled(result: Result<(), GpError>) {
    assert!(
        matches!(result, Err(GpError::Io(error)) if error.kind() == io::ErrorKind::Interrupted)
    );
}

#[tokio::test]
async fn cancelling_prelogin_finishes_without_waiting_or_submitting_a_password() {
    let gateway = Gateway::start([Outcome::Session]).await;
    gateway.state.hold_prelogin.store(true, Ordering::SeqCst);
    let (shutdown, mut task) = start(&gateway);
    wait(|| gateway.state.count(PRELOGIN) == 1).await;
    shutdown.cancel();
    let early = timeout(Duration::from_millis(200), &mut task).await;
    let promptly_cancelled = early.is_ok();
    // Always release and join, including the pre-fix failing path.
    gateway.state.release_prelogin.add_permits(1);
    let result = match early {
        Ok(result) => result.unwrap(),
        Err(_) => timeout(STEP, task).await.unwrap().unwrap(),
    };
    let login_count = gateway.state.count(LOGIN);
    let configuration_count = gateway.state.count(CONFIG);
    let logout_count = gateway.state.count(LOGOUT);
    gateway.close().await;
    assert!(
        promptly_cancelled,
        "probe waited for readonly prelogin after cancellation"
    );
    cancelled(result);
    assert_eq!((login_count, configuration_count, logout_count), (0, 0, 0));
}

#[tokio::test]
async fn cancelling_credential_tls_never_writes_the_password_post() {
    let gateway = Gateway::start([Outcome::Session]).await;
    gateway.state.hold_tls_at.store(2, Ordering::SeqCst);
    let (shutdown, task) = start(&gateway);
    wait(|| gateway.state.tls_waiting.load(Ordering::SeqCst)).await;
    assert_eq!(gateway.state.count(PRELOGIN), 1);
    assert_eq!(gateway.state.count(LOGIN), 0);
    shutdown.cancel();
    gateway.state.release_tls.add_permits(1);
    let result = timeout(STEP, task).await.unwrap().unwrap();
    let login_count = gateway.state.count(LOGIN);
    let configuration_count = gateway.state.count(CONFIG);
    let logout_count = gateway.state.count(LOGOUT);
    let tunnel_count = gateway.state.count(TUNNEL);
    gateway.close().await;
    cancelled(result);
    assert_eq!(
        login_count, 0,
        "probe submitted a password after cancellation during TLS setup"
    );
    assert_eq!((configuration_count, logout_count, tunnel_count), (0, 0, 0));
}

#[tokio::test]
async fn cancellation_after_issued_post_retains_late_cookie_and_only_logs_out() {
    let gateway = Gateway::start([Outcome::HeldSession]).await;
    let (shutdown, mut task) = start(&gateway);
    wait(|| gateway.state.count(LOGIN) == 1).await;
    let request = gateway.state.requests(LOGIN).pop().unwrap();
    assert_eq!(request.fields.get("user").unwrap(), "original-user");
    assert_eq!(request.fields.get("passwd").unwrap(), "initial-secret");
    assert!(!request.fields.contains_key("inputStr"));
    shutdown.cancel();
    let early = timeout(Duration::from_millis(100), &mut task).await;
    let retained_request = early.is_err();
    gateway.state.release_login.add_permits(1);
    let result = match early {
        Ok(result) => result.unwrap(),
        Err(_) => timeout(STEP, task).await.unwrap().unwrap(),
    };
    let counts = (
        gateway.state.count(LOGIN),
        gateway.state.count(CONFIG),
        gateway.state.count(LOGOUT),
        gateway.state.count(TUNNEL),
    );
    gateway.close().await;
    assert!(
        retained_request,
        "probe discarded an issued request and its possible cookie"
    );
    cancelled(result);
    assert_eq!(counts, (1, 0, 1, 0));
}

#[tokio::test]
async fn challenge_is_unsupported_without_answer_replay_or_configuration() {
    let gateway = Gateway::start([Outcome::Challenge(1)]).await;
    let (_shutdown, task) = start(&gateway);
    let result = timeout(STEP, task).await.unwrap().unwrap();
    let counts = (
        gateway.state.count(PRELOGIN),
        gateway.state.count(LOGIN),
        gateway.state.count(CONFIG),
        gateway.state.count(LOGOUT),
    );
    gateway.close().await;
    assert!(matches!(result, Err(GpError::UnsupportedAuthentication)));
    assert_eq!(counts, (1, 1, 0, 0));
}
