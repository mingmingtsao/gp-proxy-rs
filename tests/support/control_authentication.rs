//! Actual private IPC → Rust service → synthetic TLS gateway integration.
use super::*;
use crate::{control, control_local};
use std::path::PathBuf;

struct Ipc {
    directory: PathBuf,
    stop: CancellationToken,
    task: JoinHandle<std::io::Result<()>>,
}

impl Ipc {
    fn start(gateway: &Gateway, running: &Running) -> Self {
        // Keep AF_UNIX path length independent of macOS's long per-user TMPDIR.
        let directory =
            PathBuf::from("/tmp").join(format!("gp-ipc-auth-{:016x}", rand::random::<u64>()));
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
            task,
        }
    }
    async fn close(self) {
        self.stop.cancel();
        timeout(STEP, self.task).await.unwrap().unwrap().unwrap();
        let mut entries: Vec<_> = std::fs::read_dir(&self.directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            ["lock", "owner"],
            "only permanent ownership files may remain"
        );
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn credentials() -> control::Authentication {
    control::Authentication::Password {
        user: Zeroizing::new("synthetic-user".into()),
        password: Zeroizing::new("synthetic-password".into()),
        computer: "synthetic-client".into(),
    }
}

#[tokio::test]
async fn ipc_disconnect_cleans_late_cookie_then_explicit_next_attempt_activates() {
    let gateway = Gateway::new().await;
    gateway.state.hold_login.store(true, Ordering::SeqCst);
    let running = Running::start(&gateway);
    let ipc = Ipc::start(&gateway, &running);
    let preflight = control::preflight(&ipc.directory).await.unwrap();
    let directory = ipc.directory.clone();
    let client =
        tokio::spawn(
            async move { control::authenticate(&directory, preflight, credentials()).await },
        );
    wait(|| gateway.state.has(&Event::Login(1))).await;
    client.abort();
    assert!(client.await.unwrap_err().is_cancelled());
    // Closing IPC must join the worker and thus deliver cancellation before the
    // delayed gateway response is released. The service still owns that login.
    ipc.close().await;
    gateway.state.login_gate.add_permits(1);
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    assert!(gateway.state.has(&Event::LogoutDone(1)));
    assert!(!gateway.state.has(&Event::Config(1)));
    assert!(!gateway.state.has(&Event::TunnelOpen(1)));

    gateway.state.hold_login.store(false, Ordering::SeqCst);
    let ipc = Ipc::start(&gateway, &running);
    let preflight = control::preflight(&ipc.directory).await.unwrap();
    control::authenticate(&ipc.directory, preflight, credentials())
        .await
        .unwrap();
    wait(|| running.connector.status().available).await;
    assert!(gateway.state.has(&Event::TunnelOpen(2)));
    assert_eq!(
        control::preflight(&ipc.directory)
            .await
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 2);
    let events = gateway.state.events.lock().unwrap().clone();
    assert!(
        events
            .iter()
            .position(|e| *e == Event::LogoutDone(1))
            .unwrap()
            < events.iter().position(|e| *e == Event::Login(2)).unwrap()
    );
    ipc.close().await;
    running.close().await;
    assert!(gateway.state.has(&Event::LogoutDone(2)));
    gateway.close().await;
}

async fn raw_submit(directory: &std::path::Path) -> (control_local::LocalStream, Vec<u8>) {
    let mut connection = control_local::connect(directory).await.unwrap();
    let length = connection.stream.read_u32().await.unwrap() as usize;
    assert!(length <= 4096);
    let mut bytes = vec![0; length];
    connection.stream.read_exact(&mut bytes).await.unwrap();
    let hello: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let submit = serde_json::json!({
        "op": "authenticate", "version": control::PROTOCOL_VERSION, "interactive": false, "instance": hello["instance"], "challenge": hello["challenge"],
        "binding": hello["binding"],
        "authentication": {"kind":"password", "user":"synthetic-user", "password":"synthetic-password", "computer":"synthetic-client"}
    });
    let body = serde_json::to_vec(&submit).unwrap();
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    (connection.stream, frame)
}

#[tokio::test]
async fn a_second_frame_during_login_cancels_and_never_replays_authentication() {
    let gateway = Gateway::new().await;
    gateway.state.hold_login.store(true, Ordering::SeqCst);
    let running = Running::start(&gateway);
    let ipc = Ipc::start(&gateway, &running);
    let (mut stream, frame) = raw_submit(&ipc.directory).await;
    stream.write_all(&frame).await.unwrap();
    wait(|| gateway.state.has(&Event::Login(1))).await;
    // Extra bytes are prohibited, including an otherwise valid second frame.
    stream.write_all(&frame).await.unwrap();
    let mut byte = [0; 1];
    let read = timeout(STEP, stream.read(&mut byte)).await.unwrap();
    assert!(matches!(read, Ok(0)) || read.is_err());
    gateway.state.login_gate.add_permits(1);
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
    assert!(gateway.state.has(&Event::LogoutDone(1)));
    assert!(!gateway.state.has(&Event::Config(1)));
    assert!(!gateway.state.has(&Event::TunnelOpen(1)));
    ipc.close().await;
    running.close().await;
    gateway.close().await;
}

#[tokio::test]
async fn queued_duplicate_frames_cannot_start_a_second_login() {
    let gateway = Gateway::new().await;
    gateway.state.hold_login.store(true, Ordering::SeqCst);
    let running = Running::start(&gateway);
    let ipc = Ipc::start(&gateway, &running);
    let (mut stream, frame) = raw_submit(&ipc.directory).await;
    stream
        .write_all(&[frame.as_slice(), frame.as_slice()].concat())
        .await
        .unwrap();
    let mut byte = [0; 1];
    let read = timeout(STEP, stream.read(&mut byte)).await.unwrap();
    assert!(matches!(read, Ok(0)) || read.is_err());
    gateway.state.login_gate.add_permits(1);
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    let logins = gateway.state.logins.load(Ordering::SeqCst);
    assert!(logins <= 1);
    if logins == 1 {
        assert!(gateway.state.has(&Event::LogoutDone(1)));
    }
    assert!(!gateway.state.has(&Event::Config(1)));
    assert!(!gateway.state.has(&Event::TunnelOpen(1)));
    ipc.close().await;
    running.close().await;
    gateway.close().await;
}
