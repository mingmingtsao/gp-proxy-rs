//! Real private IPC against the service, with only synthetic gateway state.
#[path = "challenge_soak.rs"]
mod soak_tests;
use super::*;
use crate::{control, control_local};
use serde_json::{json, Value};
use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize},
    time::Instant,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Ipc {
    directory: PathBuf,
    stop: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}
impl Ipc {
    fn start(gateway: &Gateway, running: &Running) -> Self {
        let directory = PathBuf::from(format!(
            "/tmp/gp-challenge-ipc-{:016x}",
            rand::random::<u64>()
        ));
        let listener = control_local::LocalListener::bind(&directory).unwrap();
        let stop = CancellationToken::new();
        let task = tokio::spawn(control::serve(
            listener,
            gateway.origin.clone(),
            running.handle.clone(),
            stop.clone(),
        ));
        Self {
            directory,
            stop,
            task: Some(task),
        }
    }
    async fn close(mut self) {
        self.stop.cancel();
        timeout(STEP, self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut entries: Vec<_> = std::fs::read_dir(&self.directory)
            .unwrap()
            .map(|row| row.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(entries, ["lock", "owner"]);
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}
impl Drop for Ipc {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn running(gateway: &Gateway) -> Running {
    let (mut running, service) = Running::setup(gateway);
    running.task = Some(tokio::spawn(service.run()));
    running
}
fn credentials() -> control::Authentication {
    control::Authentication::Password {
        user: Zeroizing::new("original-user".into()),
        password: Zeroizing::new("initial-secret".into()),
        computer: "fixed-computer".into(),
    }
}
fn encode(value: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(value).unwrap();
    assert!(body.len() < 65_536);
    let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
    bytes.extend(body);
    bytes
}
async fn receive(stream: &mut control_local::LocalStream) -> Value {
    timeout(STEP, async {
        let length = stream.read_u32().await.unwrap() as usize;
        assert!((1..=65_536).contains(&length));
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    })
    .await
    .unwrap()
}
async fn raw_begin(ipc: &Ipc) -> (control_local::LocalStream, Value) {
    let mut connection = control_local::connect(&ipc.directory).await.unwrap();
    let hello = receive(&mut connection.stream).await;
    assert_eq!(hello["version"], control::PROTOCOL_VERSION);
    let submit = json!({
        "version": control::PROTOCOL_VERSION, "instance": hello["instance"], "challenge": hello["challenge"],
        "op": "authenticate", "binding": hello["binding"], "interactive": true,
        "authentication": {"kind":"password", "user":"original-user", "password":"initial-secret", "computer":"fixed-computer"}
    });
    connection.stream.write_all(&encode(&submit)).await.unwrap();
    (connection.stream, hello)
}
async fn raw_challenge(stream: &mut control_local::LocalStream) -> Value {
    let reply = receive(stream).await;
    assert_eq!(reply["result"], "challenge");
    let mut keys: Vec<_> = reply
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        ["prompt", "remaining_ms", "result", "round", "round_nonce"]
    );
    let text = reply.to_string();
    for secret in ["initial-secret", "state-", gateway::COOKIE] {
        assert!(!text.contains(secret));
    }
    assert!((1..=90_000).contains(&reply["remaining_ms"].as_u64().unwrap()));
    reply
}
fn response(hello: &Value, challenge: &Value) -> Value {
    json!({
        "version": control::PROTOCOL_VERSION, "instance": hello["instance"], "challenge": hello["challenge"],
        "round": challenge["round"], "round_nonce": challenge["round_nonce"], "answer": "fresh-ipc-answer"
    })
}
async fn closed(mut stream: control_local::LocalStream) {
    let mut bytes = Vec::new();
    let result = timeout(STEP, (&mut stream).take(4097).read_to_end(&mut bytes))
        .await
        .unwrap();
    assert!(bytes.len() <= 4096);
    if let Err(error) = result {
        assert!(matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof
        ));
    }
    let text = String::from_utf8_lossy(&bytes);
    for secret in [
        "initial-secret",
        "fresh-ipc-answer",
        "state-",
        gateway::COOKIE,
    ] {
        assert!(!text.contains(secret));
    }
}

struct Answers {
    calls: Arc<AtomicUsize>,
}
impl control::ChallengeHandler for Answers {
    fn respond(
        &mut self,
        prompt: control::ChallengePrompt,
    ) -> Pin<Box<dyn Future<Output = io::Result<Zeroizing<String>>> + Send + '_>> {
        let round = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        assert_eq!(usize::from(prompt.round()), round);
        assert_eq!(prompt.prompt(), format!("Enter answer {round}"));
        Box::pin(async move { Ok(Zeroizing::new(format!("ipc-answer-{round}"))) })
    }
}

#[tokio::test]
async fn real_ipc_two_round_handler_accepts_once_and_preserves_the_service() {
    let gateway = Gateway::start([
        Outcome::Challenge(1),
        Outcome::Challenge(2),
        Outcome::Session,
    ])
    .await;
    let running = running(&gateway);
    let ipc = Ipc::start(&gateway, &running);
    let preflight = control::preflight(&ipc.directory).await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handler = Answers {
        calls: calls.clone(),
    };
    timeout(
        STEP,
        control::authenticate_interactive(&ipc.directory, preflight, credentials(), &mut handler),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    wait(|| running.connector.status().available).await;
    let requests = gateway.state.requests(LOGIN);
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1].fields["passwd"], "ipc-answer-1");
    assert_eq!(requests[2].fields["passwd"], "ipc-answer-2");
    ipc.close().await;
    running.close().await;
    assert_eq!(gateway.state.count(LOGOUT), 1);
    gateway.close().await;
}

#[tokio::test]
async fn wrong_round_identity_unknown_fields_and_invalid_answers_never_reach_gateway() {
    for case in 0..9 {
        let gateway = Gateway::start([Outcome::Challenge(1)]).await;
        let running = running(&gateway);
        let ipc = Ipc::start(&gateway, &running);
        let (mut stream, hello) = raw_begin(&ipc).await;
        let challenge = raw_challenge(&mut stream).await;
        let mut answer = response(&hello, &challenge);
        match case {
            0 => answer["version"] = json!(1),
            1 => answer["instance"][0] = json!(answer["instance"][0].as_u64().unwrap() ^ 1),
            2 => answer["challenge"][0] = json!(answer["challenge"][0].as_u64().unwrap() ^ 1),
            3 => answer["round"] = json!(2),
            4 => answer["round_nonce"][0] = json!(answer["round_nonce"][0].as_u64().unwrap() ^ 1),
            5 => answer["gateway"] = json!("https://another.invalid"),
            6 => answer["answer"] = json!(""),
            7 => answer["answer"] = json!("new\nanswer"),
            _ => answer["answer"] = json!("a".repeat(8193)),
        }
        stream.write_all(&encode(&answer)).await.unwrap();
        closed(stream).await;
        wait(|| running.handle.phase() == ServicePhase::Waiting).await;
        running.closed_egress();
        assert_eq!(gateway.state.count(LOGIN), 1, "invalid Respond case {case}");
        assert_eq!(gateway.state.count(CONFIG), 0);
        ipc.close().await;
        running.close().await;
        gateway.close().await;
    }
}

#[tokio::test]
async fn stale_round_and_coalesced_responses_are_not_queued_for_later_questions() {
    for coalesced in [false, true] {
        let gateway = Gateway::start([Outcome::Challenge(1), Outcome::Challenge(2)]).await;
        let running = running(&gateway);
        let ipc = Ipc::start(&gateway, &running);
        let (mut stream, hello) = raw_begin(&ipc).await;
        let challenge = raw_challenge(&mut stream).await;
        let answer = encode(&response(&hello, &challenge));
        if coalesced {
            let mut two = answer.clone();
            two.extend_from_slice(&answer);
            stream.write_all(&two).await.unwrap();
        } else {
            stream.write_all(&answer).await.unwrap();
            let second = raw_challenge(&mut stream).await;
            assert_eq!(second["round"], 2);
            assert_ne!(second["round_nonce"], challenge["round_nonce"]);
            stream.write_all(&answer).await.unwrap();
        }
        closed(stream).await;
        wait(|| running.handle.phase() == ServicePhase::Waiting).await;
        assert_eq!(gateway.state.count(LOGIN), if coalesced { 1 } else { 2 });
        assert_eq!(gateway.state.count(CONFIG), 0);
        ipc.close().await;
        running.close().await;
        gateway.close().await;
    }
}

#[tokio::test]
async fn prompt_eof_and_partial_frame_cancel_without_waiting_for_the_thinking_budget() {
    for partial in [false, true] {
        let gateway = Gateway::start([Outcome::Challenge(1)]).await;
        let running = running(&gateway);
        let ipc = Ipc::start(&gateway, &running);
        let (mut stream, _) = raw_begin(&ipc).await;
        raw_challenge(&mut stream).await;
        let start = Instant::now();
        if partial {
            stream.write_all(&[0]).await.unwrap();
            timeout(Duration::from_secs(5), closed(stream))
                .await
                .unwrap();
            assert!(start.elapsed() >= Duration::from_millis(2700));
        } else {
            drop(stream);
        }
        wait(|| running.handle.phase() == ServicePhase::Waiting).await;
        assert_eq!(gateway.state.count(LOGIN), 1);
        assert_eq!(gateway.state.count(CONFIG), 0);
        ipc.close().await;
        running.close().await;
        gateway.close().await;
    }
}

#[tokio::test]
async fn unsolicited_input_during_prelogin_cancels_before_any_secret_post() {
    let gateway = Gateway::start([]).await;
    gateway.state.hold_prelogin.store(true, Ordering::SeqCst);
    let running = running(&gateway);
    let ipc = Ipc::start(&gateway, &running);
    let (mut stream, _) = raw_begin(&ipc).await;
    wait(|| gateway.state.count(PRELOGIN) == 1).await;
    stream.write_all(b"unsolicited").await.unwrap();
    closed(stream).await;
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    assert_eq!(gateway.state.count(LOGIN), 0);
    gateway.state.release_prelogin.add_permits(1);
    ipc.close().await;
    running.close().await;
    gateway.close().await;
}

struct PendingInput {
    entered: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}
impl control::ChallengeHandler for PendingInput {
    fn respond(
        &mut self,
        _prompt: control::ChallengePrompt,
    ) -> Pin<Box<dyn Future<Output = io::Result<Zeroizing<String>>> + Send + '_>> {
        let entered = self.entered.clone();
        let dropped = self.dropped.clone();
        Box::pin(async move {
            struct Guard(Arc<AtomicBool>);
            impl Drop for Guard {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _guard = Guard(dropped);
            entered.store(true, Ordering::SeqCst);
            std::future::pending().await
        })
    }
}

#[tokio::test]
async fn server_disconnect_drops_the_live_client_input_future_and_joins_it() {
    let gateway = Gateway::start([Outcome::Challenge(1)]).await;
    let running = running(&gateway);
    let ipc = Ipc::start(&gateway, &running);
    let preflight = control::preflight(&ipc.directory).await.unwrap();
    let entered = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let mut handler = PendingInput {
        entered: entered.clone(),
        dropped: dropped.clone(),
    };
    let directory = ipc.directory.clone();
    let client = tokio::spawn(async move {
        control::authenticate_interactive(&directory, preflight, credentials(), &mut handler).await
    });
    wait(|| entered.load(Ordering::SeqCst)).await;
    ipc.close().await;
    assert!(timeout(Duration::from_secs(1), client)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert!(dropped.load(Ordering::SeqCst));
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    assert_eq!(gateway.state.count(LOGIN), 1);
    assert_eq!(gateway.state.count(LOGOUT), 0);
    running.close().await;
    gateway.close().await;
}

#[tokio::test]
async fn client_partial_reply_has_a_frame_deadline_separate_from_user_thinking() {
    let directory = PathBuf::from(format!(
        "/tmp/gp-challenge-framing-{:016x}",
        rand::random::<u64>()
    ));
    let listener = control_local::LocalListener::bind(&directory).unwrap();
    let instance = listener.instance_id();
    let stop = CancellationToken::new();
    let stopping = stop.clone();
    let task = tokio::spawn(async move {
        for connection in 0..2 {
            let mut stream = tokio::select! {
                _ = stopping.cancelled() => return Ok(()),
                stream = listener.accept() => stream?,
            };
            let connection_nonce = [connection + 1; 16];
            let hello = json!({
                "version": control::PROTOCOL_VERSION, "instance": instance, "challenge": connection_nonce,
                "binding": {"mode": "direct", "gateway": "https://synthetic-framing.invalid"}, "phase": "waiting", "supports_stop": false, "managed": null
            });
            stream.write_all(&encode(&hello)).await?;
            if connection == 1 {
                let submit = receive(&mut stream).await;
                assert_eq!(submit["interactive"], true);
                stream.write_all(&[0]).await?;
                // No rest of the header. Client must not wait 310 seconds.
                assert_eq!(timeout(STEP, stream.read(&mut [0; 1])).await.unwrap()?, 0);
            }
        }
        Ok(())
    });
    let ipc = Ipc {
        directory,
        stop,
        task: Some(task),
    };
    let preflight = control::preflight(&ipc.directory).await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handler = Answers {
        calls: calls.clone(),
    };
    let start = Instant::now();
    let error = timeout(
        Duration::from_secs(5),
        control::authenticate_interactive(&ipc.directory, preflight, credentials(), &mut handler),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(start.elapsed() >= Duration::from_millis(2700));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    ipc.close().await;
}
