//! Synthetic local IPC tests, compiled as a child of `control` for wire access.
//! No service actor is run and no authentication/gateway request is submitted.
use super::*;
use std::{
    fs::{self, DirBuilder},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::Arc,
};
use tokio::time::timeout;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let directory = Path::new("/tmp").join(format!("gpp-{:016x}", rand::random::<u64>()));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        Self(directory)
    }

    fn endpoint(&self) -> PathBuf {
        self.0.join("control")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // This is exclusively our random synthetic fixture, never a user path.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn assert_idle_endpoint(endpoint: &Path) {
    let mut entries: Vec<_> = fs::read_dir(endpoint)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        ["lock", "owner"],
        "socket and generation marker must be removed"
    );
}

fn service() -> (ServiceHandle, crate::service::Service) {
    let config = crate::config::Config {
        gateway: "https://vpn.example.test".into(),
        domains: vec!["corp.example.test".into()],
        ..Default::default()
    };
    let client = crate::gp::GatewayClient::new(
        url::Url::parse(&config.gateway).unwrap(),
        crate::tls::client_config(None).unwrap(),
        crate::gp::ResumptionPolicy::Memory {
            tls12: rustls::client::Tls12Resumption::SessionIdOrTickets,
        },
    )
    .unwrap();
    let policy = crate::policy::Policy::new(config.domains.clone(), vec![]).unwrap();
    let (pac, _) = tokio::sync::watch::channel(Arc::new(policy));
    crate::service::new(
        config,
        client,
        Arc::new(crate::session::TunnelConnector::default()),
        pac,
        CancellationToken::new(),
    )
    .unwrap()
}

struct Server(tokio::task::JoinHandle<io::Result<()>>);

impl Drop for Server {
    fn drop(&mut self) {
        // Only a test-failure fallback. Passing cases explicitly await all work.
        self.0.abort();
    }
}

async fn stalled_client(endpoint: &Path) -> control_local::LocalConnection {
    let mut client = control_local::connect(endpoint).await.unwrap();
    let hello: Hello = timeout(Duration::from_secs(1), read_frame(&mut client.stream))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hello.phase, ServicePhase::Waiting);
    assert_eq!(hello.instance, client.instance_id);
    // Reading Hello proves the worker has been admitted; withholding Submit
    // keeps that exact worker occupied without needing sleeps or instrumentation.
    client
}

async fn assert_closed(client: &mut control_local::LocalConnection) {
    let mut byte = [0; 1];
    let result = timeout(Duration::from_secs(1), client.stream.read(&mut byte))
        .await
        .expect("server retained a client stream");
    assert!(matches!(result, Ok(0)) || result.is_err());
}

#[tokio::test]
async fn four_slow_clients_reject_fifth_then_real_handshake_timeout_recovers() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint();
    let (service, _dormant_actor) = service();
    let shutdown = CancellationToken::new();
    let listener = LocalListener::bind(&endpoint).unwrap();
    let mut server = Server(tokio::spawn(serve(
        listener,
        "https://vpn.example.test".into(),
        service.clone(),
        shutdown.clone(),
    )));
    let started = std::time::Instant::now();
    let mut clients = Vec::new();
    for _ in 0..MAX_CLIENTS {
        clients.push(stalled_client(&endpoint).await);
    }
    let mut fifth = control_local::connect(&endpoint).await.unwrap();
    assert_closed(&mut fifth).await;
    assert!(
        started.elapsed() < HANDSHAKE,
        "capacity rejection waited for a timeout"
    );
    assert_eq!(service.phase(), ServicePhase::Waiting);

    // This is an actual 3-second deadline on real Unix streams, not a mocked
    // clock. Start the margin after all clients have received their Hello.
    tokio::time::sleep(HANDSHAKE + Duration::from_millis(100)).await;
    for client in &mut clients {
        assert_closed(client).await;
    }
    let ready = timeout(Duration::from_secs(1), preflight(&endpoint))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ready.gateway(), "https://vpn.example.test");
    assert_eq!(service.phase(), ServicePhase::Waiting);
    shutdown.cancel();
    timeout(Duration::from_secs(1), &mut server.0)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_idle_endpoint(&endpoint);
}

#[tokio::test]
async fn shutdown_joins_all_four_waiting_workers_and_removes_endpoint() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint();
    let (service, _dormant_actor) = service();
    let shutdown = CancellationToken::new();
    let listener = LocalListener::bind(&endpoint).unwrap();
    let mut server = Server(tokio::spawn(serve(
        listener,
        "https://vpn.example.test".into(),
        service.clone(),
        shutdown.clone(),
    )));
    let mut clients = Vec::new();
    for _ in 0..MAX_CLIENTS {
        clients.push(stalled_client(&endpoint).await);
    }
    shutdown.cancel();
    timeout(Duration::from_secs(1), &mut server.0)
        .await
        .expect("worker shutdown waited for the full handshake deadline")
        .unwrap()
        .unwrap();
    for client in &mut clients {
        assert_closed(client).await;
    }
    assert_idle_endpoint(&endpoint);
    assert_eq!(service.phase(), ServicePhase::Waiting);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn damaged_listener_returns_error_without_hot_loop_and_joins_workers() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint();
    let (service, _dormant_actor) = service();
    let shutdown = CancellationToken::new();
    let listener = LocalListener::bind(&endpoint).unwrap();
    let mut server = Server(tokio::spawn(serve(
        listener,
        "https://vpn.example.test".into(),
        service,
        shutdown.clone(),
    )));
    let mut clients = Vec::new();
    for _ in 0..MAX_CLIENTS {
        clients.push(stalled_client(&endpoint).await);
    }
    fs::set_permissions(endpoint.join("instance"), fs::Permissions::from_mode(0o640)).unwrap();

    // A raw local connection wakes an accept already waiting in the kernel. No
    // protocol data is sent and no production client identity check is bypassed
    // to transmit credentials. It triggers the listener's post-accept check.
    let trigger = tokio::net::UnixStream::connect(endpoint.join("control.sock")).await;
    // A broken implementation that loops on InvalidData can starve Tokio timers.
    // This independent bounded watchdog cancels that loop, making the test fail
    // by its Ok result rather than hanging the test process indefinitely.
    let (finished, wait) = std::sync::mpsc::channel();
    let watchdog_shutdown = shutdown.clone();
    let watchdog = std::thread::spawn(move || {
        if wait.recv_timeout(Duration::from_millis(500)).is_err() {
            watchdog_shutdown.cancel();
        }
    });
    let result = timeout(Duration::from_secs(2), &mut server.0).await;
    let _ = finished.send(());
    watchdog.join().unwrap();
    let error = result.unwrap().unwrap().unwrap_err();
    assert_eq!(error.to_string(), "local control listener failed");
    assert!(shutdown.is_cancelled());
    for client in &mut clients {
        assert_closed(client).await;
    }
    drop(trigger);
    assert_idle_endpoint(&endpoint);
}

#[tokio::test]
async fn shutdown_interrupts_backpressured_duplex_hello_before_admission() {
    let (service, _dormant_actor) = service();
    let (mut client, server) = tokio::io::duplex(1);
    let shutdown = CancellationToken::new();
    let hello = Hello {
        version: VERSION,
        instance: [1; 16],
        challenge: [2; 16],
        binding: crate::auth::AuthBinding::direct("https://vpn.example.test").unwrap(),
        phase: ServicePhase::Waiting,
        supports_stop: false,
        managed: None,
    };
    let mut worker = Server(tokio::spawn(handle(
        server,
        hello,
        service.clone(),
        shutdown.clone(),
        None,
    )));
    let mut first_byte = [0; 1];
    timeout(Duration::from_secs(1), client.read_exact(&mut first_byte))
        .await
        .unwrap()
        .unwrap();
    shutdown.cancel();
    timeout(Duration::from_secs(1), &mut worker.0)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut remaining = Vec::new();
    timeout(Duration::from_secs(1), client.read_to_end(&mut remaining))
        .await
        .unwrap()
        .unwrap();
    assert!(remaining.len() <= 1);
    assert_eq!(service.phase(), ServicePhase::Waiting);
}
