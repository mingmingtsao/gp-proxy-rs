//! V3 IPC binding and single-round capability checks for the Portal service.
use super::*;
use crate::{control, control_local};
use serde_json::{json, Value};
use std::path::PathBuf;
struct Ipc {
    directory: PathBuf,
    stop: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}
impl Ipc {
    fn start(origins: &DualOrigins, running: &Running) -> Self {
        let directory =
            std::env::temp_dir().join(format!("gp-portal-ipc-{:016x}", rand::random::<u64>()));
        let listener = control_local::LocalListener::bind(&directory).unwrap();
        let stop = CancellationToken::new();
        let task = tokio::spawn(control::serve(
            listener,
            origins.gateway.origin.clone(),
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
            .map(|entry| entry.unwrap().file_name())
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
fn running(origins: &DualOrigins) -> Running {
    let (mut running, service, _) = Running::setup(origins, None);
    running.task = Some(tokio::spawn(service.run()));
    running
}
fn encode(value: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(value).unwrap();
    assert!(body.len() < 65536);
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend(body);
    frame
}
async fn receive(stream: &mut control_local::LocalStream) -> Value {
    timeout(STEP, async {
        let length = stream.read_u32().await.unwrap() as usize;
        assert!((1..=65536).contains(&length));
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    })
    .await
    .unwrap()
}
async fn connect(ipc: &Ipc) -> (control_local::LocalStream, Value) {
    let mut connection = control_local::connect(&ipc.directory).await.unwrap();
    let hello = receive(&mut connection.stream).await;
    assert_eq!(hello["version"], control::PROTOCOL_VERSION);
    (connection.stream, hello)
}
fn submit(hello: &Value, origins: &DualOrigins) -> Value {
    json!({"op":"authenticate","version":control::PROTOCOL_VERSION,"instance":hello["instance"],"challenge":hello["challenge"],"binding":hello["binding"],"interactive":true,"authentication":{"kind":"portal_password","portal":origins.portal.origin,"user":USER,"password":PASSWORD,"computer":COMPUTER}})
}
fn response(hello: &Value, prompt: &Value) -> Value {
    json!({"version":control::PROTOCOL_VERSION,"instance":hello["instance"],"challenge":hello["challenge"],"round":prompt["round"],"round_nonce":prompt["round_nonce"],"answer":answer(prompt["round"].as_u64().unwrap()as u8)})
}
async fn closed(mut stream: control_local::LocalStream) {
    let mut bytes = Vec::new();
    let result = timeout(STEP, (&mut stream).take(4097).read_to_end(&mut bytes))
        .await
        .unwrap();
    assert!(
        result.is_ok()
            || matches!(
                result.as_ref().unwrap_err().kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            )
    );
    assert!(bytes.len() <= 4096);
}
async fn prompt(stream: &mut control_local::LocalStream) -> Value {
    let value = receive(stream).await;
    assert_eq!(value["result"], "challenge");
    assert!((1..=90000).contains(&value["remaining_ms"].as_u64().unwrap()));
    let text = value.to_string();
    for secret in [
        PASSWORD,
        origins::PORTAL_COOKIE,
        origins::SESSION_COOKIE,
        "portal-state-",
    ] {
        assert!(!text.contains(secret));
    }
    value
}
#[tokio::test]
async fn portal_ipc_rejects_role_origin_and_connection_binding_changes_before_traffic() {
    let origins = DualOrigins::start(Plan::default()).await;
    let running = running(&origins);
    let ipc = Ipc::start(&origins, &running);
    let preflight = control::preflight(&ipc.directory).await.unwrap();
    assert!(preflight.matches_binding(&running.handle.binding()));
    assert!(!preflight.matches_gateway(&origins.gateway.origin));
    drop(preflight);
    for variant in 0..5 {
        let (mut stream, hello) = connect(&ipc).await;
        let mut frame = submit(&hello, &origins);
        match variant {
            0 => frame["binding"] = json!({"mode":"direct","gateway":origins.gateway.origin}),
            1 => frame["binding"]["portal"] = json!(origins.gateway.origin),
            2 => frame["binding"]["gateway"] = json!(origins.portal.origin),
            3 => {
                frame["authentication"]["kind"] = json!("password");
                frame["authentication"]
                    .as_object_mut()
                    .unwrap()
                    .remove("portal");
            }
            4 => frame["authentication"]["portal"] = json!(origins.gateway.origin),
            _ => unreachable!(),
        }
        stream.write_all(&encode(&frame)).await.unwrap();
        closed(stream).await;
    }
    let (mut first, old_hello) = connect(&ipc).await;
    first.shutdown().await.unwrap();
    closed(first).await;
    let (mut next, hello) = connect(&ipc).await;
    assert_ne!(hello["challenge"], old_hello["challenge"]);
    let mut frame = submit(&hello, &origins);
    frame["challenge"] = old_hello["challenge"].clone();
    next.write_all(&encode(&frame)).await.unwrap();
    closed(next).await;
    assert_eq!(running.handle.phase(), ServicePhase::Waiting);
    assert_eq!(origins.portal.state.accepted.load(Ordering::SeqCst), 0);
    assert_eq!(origins.gateway.state.accepted.load(Ordering::SeqCst), 0);
    ipc.close().await;
    running.close().await;
    origins.close().await;
}
#[tokio::test]
async fn portal_ipc_stale_round_nonce_does_not_post_the_second_answer() {
    let origins = DualOrigins::start(Plan {
        rounds: 2,
        ..Plan::default()
    })
    .await;
    let running = running(&origins);
    let ipc = Ipc::start(&origins, &running);
    let (mut stream, hello) = connect(&ipc).await;
    stream
        .write_all(&encode(&submit(&hello, &origins)))
        .await
        .unwrap();
    let first = prompt(&mut stream).await;
    stream
        .write_all(&encode(&response(&hello, &first)))
        .await
        .unwrap();
    let second = prompt(&mut stream).await;
    assert_ne!(first["round_nonce"], second["round_nonce"]);
    let mut replay = response(&hello, &second);
    replay["round_nonce"] = first["round_nonce"].clone();
    stream.write_all(&encode(&replay)).await.unwrap();
    closed(stream).await;
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    running.zero();
    assert_eq!(origins.portal.state.count(PORTAL_LOGIN), 2);
    assert_eq!(origins.gateway.state.accepted.load(Ordering::SeqCst), 0);
    ipc.close().await;
    running.close().await;
    origins.close().await;
}
#[tokio::test]
async fn portal_ipc_disconnect_cancels_current_prompt_without_cookie_handoff() {
    let origins = DualOrigins::start(Plan {
        rounds: 1,
        ..Plan::default()
    })
    .await;
    let running = running(&origins);
    let ipc = Ipc::start(&origins, &running);
    let (mut stream, hello) = connect(&ipc).await;
    stream
        .write_all(&encode(&submit(&hello, &origins)))
        .await
        .unwrap();
    let _ = prompt(&mut stream).await;
    stream.shutdown().await.unwrap();
    closed(stream).await;
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    assert_eq!(origins.portal.state.count(PORTAL_LOGIN), 1);
    assert_eq!(origins.gateway.state.accepted.load(Ordering::SeqCst), 0);
    ipc.close().await;
    running.close().await;
    origins.close().await;
}
#[tokio::test]
async fn portal_ipc_fresh_answers_commit_one_gateway_session() {
    let origins = DualOrigins::start(Plan {
        rounds: 2,
        ..Plan::default()
    })
    .await;
    let running = running(&origins);
    let ipc = Ipc::start(&origins, &running);
    let (mut stream, hello) = connect(&ipc).await;
    assert_eq!(
        hello["binding"],
        serde_json::to_value(running.handle.binding()).unwrap()
    );
    stream
        .write_all(&encode(&submit(&hello, &origins)))
        .await
        .unwrap();
    for round in 1..=2 {
        let challenge = prompt(&mut stream).await;
        assert_eq!(challenge["round"], round);
        stream
            .write_all(&encode(&response(&hello, &challenge)))
            .await
            .unwrap();
    }
    assert_eq!(receive(&mut stream).await["result"], "accepted");
    closed(stream).await;
    wait(|| running.connector.status().available).await;
    assert_eq!(origins.gateway.state.count(GATEWAY_LOGIN), 1);
    assert_eq!(origins.gateway.state.count(TUNNEL), 1);
    ipc.close().await;
    running.close().await;
    assert_eq!(origins.gateway.state.count(LOGOUT), 1);
    origins.close().await;
}
