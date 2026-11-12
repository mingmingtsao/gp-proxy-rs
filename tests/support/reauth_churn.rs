//! Bounded repeated explicit authentication through actual Unix IPC and TLS.
//! Only the parent fixture's public synthetic identities and loopback are used.
use super::*;
use crate::{control, control_local};
use std::path::{Path, PathBuf};

const CYCLES: usize = 16;

struct Ipc {
    directory: PathBuf,
    stop: CancellationToken,
    task: JoinHandle<io::Result<()>>,
}

impl Ipc {
    fn start(gateway: &Gateway, running: &Running) -> Self {
        let directory = Path::new("/tmp").join(format!("gp-churn-{:016x}", rand::random::<u64>()));
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

async fn authenticate(ipc: &Ipc) -> io::Result<()> {
    let ready = control::preflight(&ipc.directory).await?;
    timeout(
        STEP,
        control::authenticate(&ipc.directory, ready, credentials()),
    )
    .await
    .unwrap()
}

async fn submit_for_half_close(ipc: &Ipc) -> control_local::LocalStream {
    let mut connection = control_local::connect(&ipc.directory).await.unwrap();
    let length = connection.stream.read_u32().await.unwrap() as usize;
    assert!(length <= 4096);
    let mut bytes = vec![0; length];
    connection.stream.read_exact(&mut bytes).await.unwrap();
    let hello: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(hello["phase"], "waiting");
    assert_eq!(hello["instance"], serde_json::json!(connection.instance_id));
    let frame = serde_json::to_vec(&serde_json::json!({
        "op": "authenticate", "version": control::PROTOCOL_VERSION, "interactive": false,
        "instance": hello["instance"],
        "challenge": hello["challenge"],
        "binding": hello["binding"],
        "authentication": {
            "kind": "password", "user": "synthetic-user",
            "password": "synthetic-password", "computer": "synthetic-client"
        }
    }))
    .unwrap();
    connection
        .stream
        .write_u32(frame.len() as u32)
        .await
        .unwrap();
    connection.stream.write_all(&frame).await.unwrap();
    connection.stream
}

fn assert_zero_gauges(snapshot: &crate::status::Snapshot) {
    assert!(!snapshot.available);
    assert_eq!(
        [
            snapshot.active_tcp,
            snapshot.pending_tcp,
            snapshot.active_udp,
            snapshot.closing_tcp,
            snapshot.command_queue,
            snapshot.incoming_packets,
            snapshot.outgoing_packets,
        ],
        [0; 7],
    );
}

fn descriptor_count() -> Option<usize> {
    // Counts only. Do not resolve/read descriptor targets or process secrets.
    // Full-suite tests share this process, so these are diagnostic observations,
    // never assertions that unrelated tests have released their descriptors.
    let directory = if cfg!(target_os = "macos") {
        "/dev/fd"
    } else {
        "/proc/self/fd"
    };
    std::fs::read_dir(directory)
        .ok()
        .map(|entries| entries.count())
}

async fn assert_busy(ipc: &Ipc, running: &Running, gateway: &Gateway) {
    assert_ne!(running.handle.phase(), ServicePhase::Waiting);
    assert_eq!(
        control::preflight(&ipc.directory)
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WouldBlock,
    );
    assert_eq!(
        running
            .handle
            .try_authenticate(password(), &gateway.origin, CancellationToken::new())
            .err(),
        Some(StartError::Busy),
    );
}

async fn release_logout(gateway: &Gateway, running: &Running, ipc: &Ipc, index: usize) {
    wait(|| gateway.state.has(&Event::LogoutStart(index))).await;
    assert_eq!(running.handle.phase(), ServicePhase::Cleaning);
    assert_busy(ipc, running, gateway).await;
    assert_eq!(gateway.state.active_tunnels.load(Ordering::SeqCst), 0);
    gateway.state.hold_logout.store(false, Ordering::SeqCst);
    gateway.state.logout_gate.add_permits(1);
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    assert!(gateway.state.has(&Event::LogoutDone(index)));
}

#[tokio::test]
async fn sixteen_explicit_ipc_lifecycles_reclaim_resources_without_password_replay() {
    timeout(Duration::from_secs(60), async {
        let started = std::time::Instant::now();
        let initial_fd = descriptor_count();
        // The synthetic TLS fixture already resolves localhost. Observe that
        // same one-time OS resolver/thread-pool setup separately from repeated
        // authentication; neither result targets nor descriptor targets are read.
        let local_addresses = timeout(STEP, tokio::net::lookup_host(("localhost", 0)))
            .await
            .unwrap()
            .unwrap()
            .collect::<Vec<_>>();
        assert!(!local_addresses.is_empty());
        assert!(local_addresses
            .iter()
            .all(|address| address.ip().is_loopback()));
        let resolved_fd = descriptor_count();
        let gateway = Gateway::new().await;
        gateway.state.lifetime.store(2, Ordering::SeqCst);
        let running = Running::start(&gateway);
        let ipc = Ipc::start(&gateway, &running);
        let server = ProxyServer::bind(ProxyConfig {
            http_addr: "127.0.0.1:0".parse().unwrap(),
            socks_addr: "127.0.0.1:0".parse().unwrap(),
            max_connections: 4,
            handshake_timeout: Duration::from_secs(3),
            idle_timeout: Duration::from_secs(15),
        })
        .await
        .unwrap();
        let addresses = server.local_addrs();
        let (proxy_stop, proxy_stopping) = watch::channel(false);
        let proxy = tokio::spawn(server.serve(
            running.connector.clone(),
            running.pac.clone(),
            proxy_stopping,
        ));
        let bound_fd = descriptor_count();
        let mut idle_fds = Vec::with_capacity(CYCLES);
        let mut cookies = Vec::with_capacity(12);
        let mut successful = 0;
        let mut rejected = 0;
        let mut cancelled = 0;
        for index in 1..=CYCLES {
            assert_eq!(running.handle.phase(), ServicePhase::Waiting);
            assert_eq!(gateway.state.logins.load(Ordering::SeqCst), index - 1);
            assert_zero_gauges(&crate::status::query(addresses.0).await.unwrap());
            assert!(pac_document(addresses.0)
                .await
                .contains("remembered.corp.example"));
            let scenario = match index % 4 {
                1 | 3 => {
                    gateway.state.hold_logout.store(true, Ordering::SeqCst);
                    authenticate(&ipc).await.unwrap();
                    wait(|| running.connector.status().available).await;
                    assert_busy(&ipc, &running, &gateway).await;
                    let mut http = http_stream(addresses.0).await;
                    let mut socks = socks_stream(addresses.1).await;
                    proxy_echo(&mut http).await;
                    proxy_echo(&mut socks).await;
                    wait(|| gateway.state.has(&Event::LogoutStart(index))).await;
                    for stream in [&mut http, &mut socks] {
                        let mut byte = [0; 1];
                        assert!(matches!(
                            timeout(STEP, stream.read(&mut byte)).await.unwrap(),
                            Ok(0) | Err(_)
                        ));
                    }
                    drop((http, socks));
                    assert!(!crate::status::query(addresses.0).await.unwrap().available);
                    assert!(pac_document(addresses.0)
                        .await
                        .contains("remembered.corp.example"));
                    release_logout(&gateway, &running, &ipc, index).await;
                    cookies.push(index);
                    successful += 1;
                    "success_then_expiry"
                }
                2 => {
                    // The synthetic gateway explicitly rejects the submitted
                    // password. The client must not retry or produce a cookie.
                    gateway.state.reject_login.store(true, Ordering::SeqCst);
                    assert!(authenticate(&ipc).await.is_err());
                    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
                    gateway.state.reject_login.store(false, Ordering::SeqCst);
                    assert!(!gateway.state.has(&Event::Config(index)));
                    assert!(!gateway.state.has(&Event::LogoutStart(index)));
                    assert!(!gateway.state.has(&Event::TunnelOpen(index)));
                    rejected += 1;
                    "password_rejected"
                }
                _ => {
                    gateway.state.hold_login.store(true, Ordering::SeqCst);
                    gateway.state.hold_logout.store(true, Ordering::SeqCst);
                    let mut client = timeout(STEP, submit_for_half_close(&ipc)).await.unwrap();
                    wait(|| gateway.state.has(&Event::Login(index))).await;
                    assert_busy(&ipc, &running, &gateway).await;
                    assert!(!crate::status::query(addresses.0).await.unwrap().available);
                    assert!(pac_document(addresses.0)
                        .await
                        .contains("remembered.corp.example"));
                    // Half-close preserves our read half. Observed server EOF
                    // proves its IPC worker dropped/cancelled the operation
                    // before the late successful login response is released.
                    client.shutdown().await.unwrap();
                    let mut byte = [0; 1];
                    assert!(matches!(
                        timeout(STEP, client.read(&mut byte)).await.unwrap(),
                        Ok(0) | Err(_)
                    ));
                    drop(client);
                    gateway.state.hold_login.store(false, Ordering::SeqCst);
                    gateway.state.login_gate.add_permits(1);
                    release_logout(&gateway, &running, &ipc, index).await;
                    assert!(!gateway.state.has(&Event::Config(index)));
                    assert!(!gateway.state.has(&Event::TunnelOpen(index)));
                    cookies.push(index);
                    cancelled += 1;
                    "cancelled_late_cookie"
                }
            };
            wait(|| gateway.state.active_workers.load(Ordering::SeqCst) == 0).await;
            assert_eq!(gateway.state.active_tunnels.load(Ordering::SeqCst), 0);
            assert!(gateway.state.tunnel.lock().unwrap().is_none());
            assert_eq!(running.handle.phase(), ServicePhase::Waiting);
            assert_zero_gauges(&running.connector.status());
            assert_eq!(gateway.state.logins.load(Ordering::SeqCst), index);
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(gateway.state.logins.load(Ordering::SeqCst), index);
            idle_fds.push(descriptor_count());
            eprintln!(
                "REAUTH_CHURN {}",
                serde_json::json!({
                    "cycle": index, "scenario": scenario,
                    "logins": index, "workers": 0, "tunnels": 0,
                    "gauges": ([0; 7]), "fd_observation": idle_fds.last().unwrap(),
                })
            );
        }
        // Explicitly leave the service idle across the first transport-retry
        // interval. No timer is allowed to resubmit any stored password.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(gateway.state.logins.load(Ordering::SeqCst), CYCLES);
        assert_eq!(running.handle.phase(), ServicePhase::Waiting);
        let events = gateway.state.events.lock().unwrap().clone();
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::Prelogin))
                .count(),
            CYCLES
        );
        for &index in &cookies {
            assert_eq!(
                events
                    .iter()
                    .filter(|e| **e == Event::LogoutStart(index))
                    .count(),
                1
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|e| **e == Event::LogoutDone(index))
                    .count(),
                1
            );
            if index < CYCLES {
                let done = events
                    .iter()
                    .position(|e| *e == Event::LogoutDone(index))
                    .unwrap();
                let next = events
                    .iter()
                    .position(|e| *e == Event::Login(index + 1))
                    .unwrap();
                assert!(done < next, "old cookie cleanup crossed the next login");
                assert!(!events[next..].contains(&Event::LogoutStart(index)));
            }
        }
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::TunnelOpen(_)))
                .count(),
            8
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::TunnelClosed(_)))
                .count(),
            8
        );
        assert_eq!(
            (successful, rejected, cancelled, cookies.len()),
            (8, 4, 4, 12)
        );
        let connector = running.connector.clone();
        let state = gateway.state.clone();
        ipc.close().await;
        running.close().await;
        proxy_stop.send_replace(true);
        timeout(STEP, proxy).await.unwrap().unwrap().unwrap();
        gateway.close().await;
        assert_zero_gauges(&connector.status());
        assert_eq!(state.active_workers.load(Ordering::SeqCst), 0);
        assert_eq!(state.active_tunnels.load(Ordering::SeqCst), 0);
        let final_fd = descriptor_count();
        // Rebinding proves both original public proxy listeners were released.
        let _http = TcpListener::bind(addresses.0).await.unwrap();
        let _socks = TcpListener::bind(addresses.1).await.unwrap();
        eprintln!(
            "REAUTH_CHURN_FINAL {}",
            serde_json::json!({
                "cycles": CYCLES, "success_expiry": successful, "password_rejected": rejected,
                "client_cancel_late_cookie": cancelled, "logins": CYCLES,
                "cookie_logouts": cookies.len(), "tunnels_opened": 8, "tunnels_closed": 8,
                "http_echoes": 8, "socks_echoes": 8, "workers": 0, "tunnels": 0,
                "gauges": ([0; 7]), "elapsed_ms": started.elapsed().as_millis(),
                "fd_before": initial_fd, "fd_after_localhost_resolution": resolved_fd,
                "fd_endpoints_bound": bound_fd, "fd_idle_samples": idle_fds, "fd_after": final_fd,
                "fd_counts_are_process_wide_observations": true,
                "all_owned_tasks_joined": true, "proxy_ports_rebound": true,
            })
        );
    })
    .await
    .expect("bounded reauthentication churn exceeded 60 seconds");
}
