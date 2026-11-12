#![cfg(target_os = "macos")]
//! Production manager library + typed fake service backend + actual CLI daemon.
//! No test calls launchctl. Backend effects are synthetic; runtime admission,
//! candidate execution, persisted files, control IPC and VPN IP echo are real.
#[path = "support/managed_backend.rs"]
mod backend;
#[path = "support/wait_auth_gateway.rs"]
mod gateway;

use backend::{ActionKind, Backend, Fault};
use gp_proxy::{
    control,
    deployment::{
        self,
        backend::{Action, Outcome},
        ManageAction, Plan,
    },
    deployment_store::Store,
    managed_protocol::ManagedIdentity,
    managed_release::{hexadecimal, Source},
    managed_runtime::{self, Gate},
    status,
};
use rustix::{
    fs::{Mode, OFlags},
    process,
};
use std::{
    fs::{self, DirBuilder},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::Ordering,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

const STEP: Duration = Duration::from_secs(8);
// Several independently bounded manager operations and debug-binary SHA-256
// passes occur in one scenario. This fixture ceiling is not an operation SLA.
const CASE: Duration = Duration::from_secs(180);

#[test]
fn backend_owned_session() {
    if std::env::var(backend::CHILD_MODE).as_deref() != Ok("exec") {
        return;
    }
    process::setsid().unwrap();
    assert_eq!(process::getsid(None).unwrap(), process::getpid());
    assert_eq!(io::stdin().read(&mut [0; 1]).unwrap(), 0);
    assert!(rustix::fs::open(
        "/dev/tty",
        OFlags::RDONLY | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty()
    )
    .is_err());
    let args: Vec<String> =
        serde_json::from_str(&std::env::var("GP_DEPLOYMENT_ARGUMENTS").unwrap()).unwrap();
    assert_eq!(args.len(), 10);
    let error = Command::new(&args[0]).args(&args[1..]).env_clear().exec();
    panic!("owned deployment child exec failed: {error}");
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

struct Fixture {
    directory: PathBuf,
    plan: Plan,
    http: SocketAddr,
    socks: SocketAddr,
    reservations: Option<[TcpListener; 2]>,
}
impl Fixture {
    fn new(gateway: &gateway::Gateway) -> Self {
        let directory = PathBuf::from(format!("/tmp/gp-deploy-{:016x}", rand::random::<u64>()));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let directory = directory.canonicalize().unwrap();
        fs::create_dir(directory.join("cwd")).unwrap();
        fs::create_dir(directory.join("LaunchAgents")).unwrap();
        fs::write(
            directory.join("cwd/gp-proxy.toml"),
            b"invalid default configuration {{{",
        )
        .unwrap();
        fs::write(
            directory.join("cwd/.env"),
            b"\xffsynthetic-not-a-credentials-file",
        )
        .unwrap();
        let binary = directory.join("source-gp-proxy");
        fs::copy(env!("CARGO_BIN_EXE_gp-proxy"), &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let source = Source::open(&binary).unwrap();
        let installation: [u8; 16] = rand::random();
        let identity = ManagedIdentity {
            installation,
            generation: 1,
            release: source.digest(),
        };
        let state = directory.join("state");
        let http = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks = TcpListener::bind("127.0.0.1:0").unwrap();
        let addresses = (http.local_addr().unwrap(), socks.local_addr().unwrap());
        let config = directory.join("config.toml");
        let ca = serde_json::to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/gp/testdata/localhost-cert.pem"
        ))
        .unwrap();
        fs::write(&config, format!("gateway = '{}'\nhttp_listen = '{}'\nsocks_listen = '{}'\nca_file = {ca}\nnetworks = ['10.77.0.0/24']\ndomains = ['synthetic-corp.invalid']\nmax_connections = 4\nconnect_timeout_secs = 3\nidle_timeout_secs = 20\n", gateway.origin, addresses.0, addresses.1)).unwrap();
        let label = format!(
            "io.gp-proxy.{}.g0000000000000001",
            hexadecimal(&installation)
        );
        let agents = directory.join("LaunchAgents");
        let plan = Plan {
            schema: 2,
            uid: process::geteuid().as_raw(),
            state_directory: state.clone(),
            launch_agents_directory: agents.clone(),
            source_binary: binary,
            release_bytes: source.len(),
            gate: Gate {
                version: 2,
                identity,
                enabled: false,
                binary: state
                    .join("versions")
                    .join(hexadecimal(&identity.release))
                    .join("gp-proxy"),
                config,
                control: state.join("data/control"),
                logs: state.join("data/logs"),
            },
            label: label.clone(),
            plist: agents.join(format!("{label}.plist")),
        };
        Self {
            directory,
            plan,
            http: addresses.0,
            socks: addresses.1,
            reservations: Some([http, socks]),
        }
    }
    fn backend(&self) -> Backend {
        Backend::new(
            self.plan.state_directory.clone(),
            self.plan.label.clone(),
            self.plan.plist.clone(),
            self.directory.join("cwd"),
        )
    }
    fn allow_listeners(&mut self) {
        self.reservations.take();
    }
    fn gate(&self) -> Gate {
        managed_runtime::read_gate(&self.plan.state_directory.join("runtime")).unwrap()
    }
    async fn ready(&self) -> control::ControlIdentity {
        let observed = control::inspect(&self.plan.gate.control).await.unwrap();
        assert_eq!(observed.managed, Some(self.gate().identity));
        assert!(!status::query(self.http).await.unwrap().available);
        observed
    }
    async fn authenticate(&self) {
        let mut child = OwnedChild(
            Command::new(&self.plan.source_binary)
                .env_clear()
                .current_dir(self.directory.join("cwd"))
                .arg("--config")
                .arg(&self.plan.gate.config)
                .arg("--control-dir")
                .arg(&self.plan.gate.control)
                .args(["reauth", "--username", "synthetic-user", "--password-stdin"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        child
            .0
            .stdin
            .take()
            .unwrap()
            .write_all(b"synthetic-cli-password-29483\n")
            .unwrap();
        let exit = timeout(STEP, async {
            loop {
                if let Some(exit) = child.0.try_wait().unwrap() {
                    return exit;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(exit.success());
        timeout(STEP, async {
            while !status::query(self.http).await.unwrap().available {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    fn released(&self) {
        drop(TcpListener::bind(self.http).unwrap());
        drop(TcpListener::bind(self.socks).unwrap());
        assert!(!self.plan.gate.control.join("control.sock").exists());
        let maintenance =
            managed_runtime::open_maintenance(&self.plan.state_directory.join("runtime")).unwrap();
        assert!(!maintenance.read_gate().unwrap().enabled);
        drop(maintenance.try_runtime().unwrap());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn pending(fixture: &Fixture) -> Option<serde_json::Value> {
    let store = Store::open(&fixture.plan.state_directory).unwrap();
    store.pending().map(|tx| serde_json::to_value(tx).unwrap())
}
fn ledger(fixture: &Fixture) -> serde_json::Value {
    let store = Store::open(&fixture.plan.state_directory).unwrap();
    serde_json::to_value(store.ledger()).unwrap()
}
fn current_label(identity: &ManagedIdentity) -> String {
    format!(
        "io.gp-proxy.{}.g{:016x}",
        hexadecimal(&identity.installation),
        identity.generation
    )
}
async fn closed(stream: &mut TcpStream) {
    match timeout(STEP, stream.read(&mut [0; 1])).await.unwrap() {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) => {}
        result => panic!("retired application capability stayed usable: {result:?}"),
    }
}

async fn echo(f: &Fixture, socks: bool) -> TcpStream {
    timeout(STEP, async {
        let mut stream = TcpStream::connect(if socks { f.socks } else { f.http })
            .await
            .unwrap();
        if socks {
            stream.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            stream.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            stream
                .write_all(&[5, 1, 0, 1, 10, 77, 0, 1, 1, 187])
                .await
                .unwrap();
            let mut reply = [0; 10];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        } else {
            stream
                .write_all(b"CONNECT 10.77.0.1:443 HTTP/1.1\r\nHost: 10.77.0.1:443\r\n\r\n")
                .await
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 4096);
                header.push(stream.read_u8().await.unwrap());
            }
            assert!(header.starts_with(b"HTTP/1.1 200 "));
        }
        let payload: Vec<_> = (0..8192)
            .map(|i| ((i + usize::from(socks)) % 251) as u8)
            .collect();
        let mut received = vec![0; payload.len()];
        stream.write_all(&payload).await.unwrap();
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
        stream
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn production_manager_install_start_stop_upgrade_uninstall_with_actual_daemons() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let backend = fixture.backend();
        fixture.allow_listeners();
        deployment::install_with_backend(fixture.plan.clone(), false, &backend).await.unwrap();
        assert!(!fixture.gate().enabled && !backend.loaded().await);
        deployment::inspect_with_backend(&fixture.plan.state_directory, &backend).await.unwrap();
        assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);
        deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Start, None, &backend).await.unwrap();
        let first = fixture.ready().await;
        assert!(!backend.observations().await.iter().any(|event| matches!(event.action, Action::Enable { .. })), "fresh labels must not create persistent enable overrides");
        assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);
        fixture.authenticate().await;
        tokio::join!(echo(&fixture, false), echo(&fixture, true));
        let stopped = deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Stop, None, &backend).await.unwrap();
        let completion = stopped.cleanup.as_ref().unwrap();
        assert!(completion.local_cleanup_complete);
        assert_eq!((completion.cleanup.known_sessions, completion.cleanup.logout_confirmed, completion.cleanup.logout_unconfirmed, completion.cleanup.remote_outcome_unknown), (1, 1, 0, 0));
        fixture.released();
        assert!(!fixture.plan.plist.exists());
        assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
        assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 1);
        deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Start, None, &backend).await.unwrap();
        let second = fixture.ready().await;
        assert!(!backend.observations().await.iter().any(|event| matches!(event.action, Action::Enable { .. })), "a new generation uses bootstrap without changing OS enable policy");
        assert_ne!(second.instance, first.instance);
        assert!(second.managed.unwrap().generation > first.managed.unwrap().generation);
        // Ordinary application stop leaves the registered job and enabled gate.
        // Explicit service start must kickstart that definition without -k,
        // preserving the release/generation while creating a fresh instance.
        let ordinary = control::stop(&fixture.plan.gate.control, &second.binding, Some(second.instance)).await.unwrap();
        assert!(ordinary.local_cleanup_complete);
        assert_eq!(ordinary.cleanup.known_sessions, 0);
        backend.reap_stopped().await;
        assert!(backend.loaded().await && fixture.gate().enabled);
        deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Start, None, &backend).await.unwrap();
        let resumed = fixture.ready().await;
        assert_ne!(resumed.instance, second.instance);
        assert_eq!(resumed.managed, second.managed);
        assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
        // Identical bytes are a no-op, not evidence of a different release
        // switch. It must preserve the instance and avoid another daemon.
        let spawned_before_upgrade = backend.spawned().await;
        deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Upgrade, Some(&fixture.plan.source_binary), &backend).await.unwrap();
        let upgraded = fixture.ready().await;
        assert_eq!(upgraded.managed.unwrap().release, fixture.plan.gate.identity.release);
        assert_eq!(upgraded.instance, resumed.instance);
        assert_eq!(upgraded.managed, resumed.managed);
        assert_eq!(backend.spawned().await, spawned_before_upgrade);
        deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Uninstall, None, &backend).await.unwrap();
        backend.reap_stopped().await;
        assert!(!backend.loaded().await);
        assert!(!fixture.plan.plist.exists());
        drop(TcpListener::bind(fixture.http).unwrap()); drop(TcpListener::bind(fixture.socks).unwrap());
        let counts = (gateway.state.logins.load(Ordering::SeqCst), gateway.state.logouts.load(Ordering::SeqCst));
        let observations = backend.observations().await;
        let bootstrap_generations: Vec<_> = observations.iter().filter_map(|event| {
            if matches!(event.action, Action::Bootstrap { .. }) { assert_eq!(event.gate_enabled, Some(true)); Some(event.generation.unwrap()) } else { None }
        }).collect();
        let spawned = backend.spawned().await;
        let enabled_labels: Vec<_> = observations.iter().filter_map(|event| match &event.action {
            Action::Enable { label, .. } => Some(label.as_str()),
            _ => None,
        }).collect();
        let resumed_managed = resumed.managed.unwrap();
        let resumed_label = format!("io.gp-proxy.{}.g{:016x}", hexadecimal(&resumed_managed.installation), resumed_managed.generation);
        assert_eq!(enabled_labels, [resumed_label.as_str()], "only explicit same-label Resume may enable an existing job");
        assert_eq!(observations.iter().filter(|event| matches!(event.action, Action::Kickstart { .. })).count(), 1);
        gateway.close().await;
        assert_eq!(counts, (1, 1), "restart/upgrade must not replay credentials");
        assert!(bootstrap_generations.len() >= 2);
        eprintln!("DEPLOY manager_library=true launchd_model=true real_daemons={spawned} bootstrap_generations={bootstrap_generations:?} ordinary_stop_resume_same_generation=true echo_bytes=16384 logins=1 logouts=1 identical_release_upgrade=true all_children_reaped=true");
    }).await.unwrap();
}

#[tokio::test]
async fn unknown_bootstrap_retains_closed_gate_and_journal_without_automatic_retry() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let backend = fixture.backend();
        fixture.allow_listeners();
        backend.fail_once(Fault::BootstrapBefore).await;
        assert!(deployment::install_with_backend(fixture.plan.clone(), true, &backend).await.is_err());
        assert!(!fixture.gate().enabled);
        assert!(!backend.loaded().await);
        let transaction = pending(&fixture).unwrap();
        assert_eq!(transaction["phase"], "new_job_load_requested");
        assert_eq!(transaction["outcome"]["reason"], "operation_failed");
        let before: Vec<_> = backend.observations().await.into_iter().filter(|o| matches!(o.action, Action::Bootstrap { .. })).collect();
        assert_eq!(before.len(), 1);
        assert!(deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Start, None, &backend).await.is_err());
        let after = backend.observations().await.into_iter().filter(|o| matches!(o.action, Action::Bootstrap { .. })).count();
        assert_eq!(after, 1);
        assert_eq!(pending(&fixture).unwrap(), transaction);
        fixture.released();
        let accepted = gateway.state.accepted.load(Ordering::SeqCst);
        gateway.close().await;
        assert_eq!(accepted, 0);
        eprintln!("DEPLOY injected_bootstrap_unknown=true automatic_retry=false gate_closed=true gateway_connections=0");
    }).await.unwrap();
}

#[tokio::test]
async fn unknown_after_real_admission_does_not_kill_or_replay_the_new_instance() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let backend = fixture.backend();
        fixture.allow_listeners();
        backend.fail_once(Fault::BootstrapAfter).await;
        assert!(deployment::install_with_backend(fixture.plan.clone(), true, &backend).await.is_err());
        let gate = fixture.gate();
        assert!(!gate.enabled);
        let identity = control::inspect(&gate.control).await.unwrap();
        assert_eq!(identity.managed, Some(gate.identity));
        assert!(!status::query(fixture.http).await.unwrap().available);
        let maintenance = managed_runtime::open_maintenance(&fixture.plan.state_directory.join("runtime")).unwrap();
        assert!(matches!(maintenance.try_runtime(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        drop(maintenance);
        let transaction = pending(&fixture).unwrap();
        assert_eq!(transaction["phase"], "new_job_load_requested");
        assert_eq!(transaction["outcome"]["reason"], "operation_failed");
        assert!(backend.loaded().await);
        assert_eq!(backend.spawned().await, 1);
        let observations = backend.observations().await;
        assert!(!observations.iter().any(|o| matches!(o.action, Action::Bootout { .. } | Action::Kickstart { .. })));
        assert!(deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Start, None, &backend).await.is_err());
        assert_eq!(pending(&fixture).unwrap(), transaction);
        assert_eq!(control::inspect(&gate.control).await.unwrap().instance, identity.instance);
        // Explicit fixture cleanup, not a product transaction-recovery claim.
        let completion = control::stop(&gate.control, &identity.binding, Some(identity.instance)).await.unwrap();
        assert!(completion.local_cleanup_complete);
        assert_eq!(completion.cleanup.known_sessions, 0);
        backend.reap_stopped().await;
        fixture.released();
        let accepted = gateway.state.accepted.load(Ordering::SeqCst);
        gateway.close().await;
        assert_eq!(accepted, 0);
        eprintln!("DEPLOY unknown_after_matching_ipc=true live_runtime_retained=true gate_closed=true blind_bootout=false automatic_retry=false fixture_bound_stop=true gateway_connections=0 child_reaped=true");
    }).await.unwrap();
}

#[tokio::test]
async fn forged_plan_is_rejected_before_deployment_mutation_or_backend_effects() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let fixture = Fixture::new(&gateway);
        let backend = fixture.backend();
        for case in ["uid", "path", "hash"] {
            let mut plan = fixture.plan.clone();
            match case {
                "uid" => plan.uid = 0,
                "path" => plan.gate.control = fixture.directory.join("unowned-alternate-control"),
                "hash" => {
                    plan.gate.identity.release[0] ^= 1;
                    plan.gate.binary = plan.state_directory.join("versions").join(hexadecimal(&plan.gate.identity.release)).join("gp-proxy");
                },
                _ => unreachable!(),
            }
            assert!(deployment::install_with_backend(plan, true, &backend).await.is_err(), "{case}");
            assert!(!fixture.plan.state_directory.exists());
            assert!(!fixture.plan.plist.exists());
            assert!(!fixture.directory.join("unowned-alternate-control").exists());
            assert!(backend.observations().await.is_empty());
        }
        let accepted = gateway.state.accepted.load(Ordering::SeqCst);
        gateway.close().await;
        assert_eq!(accepted, 0);
        eprintln!("DEPLOY forged_plan_cases=3 pre_mutation_rejection=true backend_actions=0 gateway_connections=0");
    }).await.unwrap();
}

#[tokio::test]
#[ignore = "requires explicit GP_TEST_MANAGED_UPGRADE_BINARY pointing at a compatible second actual gp-proxy artifact with a different SHA-256"]
async fn distinct_release_upgrade_retires_old_streams_and_waits_for_explicit_authentication() {
    timeout(CASE, async {
        // Test-only explicit artifact selection, never consulted by production
        // or an ordinary test run. No executable/environment override reaches
        // the product's native launchctl adapter.
        let path = PathBuf::from(std::env::var_os("GP_TEST_MANAGED_UPGRADE_BINARY")
            .expect("explicit second compatible gp-proxy artifact is required"));
        assert!(path.is_absolute());
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let backend = fixture.backend();
        let candidate = fixture.directory.join("different-gp-proxy");
        let mut source = Source::open(&path).unwrap();
        let expected = source.digest();
        assert_ne!(expected, fixture.plan.gate.identity.release, "same bytes do not exercise a release switch");
        let mut copied = fs::File::create(&candidate).unwrap();
        source.copy_into(&mut copied).unwrap();
        copied.sync_all().unwrap();
        drop(copied);
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(Source::open(&candidate).unwrap().digest(), expected);
        fixture.allow_listeners();
        deployment::install_with_backend(fixture.plan.clone(), true, &backend).await.unwrap();
        let before = fixture.ready().await;
        fixture.authenticate().await;
        let (mut http, mut socks) = tokio::join!(echo(&fixture, false), echo(&fixture, true));
        let upgraded = deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Upgrade, Some(&candidate), &backend).await.unwrap();
        let completion = upgraded.cleanup.as_ref().unwrap();
        assert!(completion.local_cleanup_complete);
        assert_eq!((completion.cleanup.known_sessions, completion.cleanup.logout_confirmed, completion.cleanup.logout_unconfirmed, completion.cleanup.remote_outcome_unknown), (1, 1, 0, 0));
        let after = fixture.ready().await;
        assert_ne!(after.instance, before.instance);
        assert_eq!(after.managed.unwrap().installation, before.managed.unwrap().installation);
        assert!(after.managed.unwrap().generation > before.managed.unwrap().generation);
        assert_eq!(after.managed.unwrap().release, expected);
        let ended_http = timeout(STEP, http.read(&mut [0; 1])).await.unwrap();
        let ended_socks = timeout(STEP, socks.read(&mut [0; 1])).await.unwrap();
        assert!(matches!(ended_http, Ok(0) | Err(_)) && matches!(ended_socks, Ok(0) | Err(_)));
        assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1, "upgrade must not replay credentials");
        assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 1);
        fixture.authenticate().await;
        tokio::join!(echo(&fixture, false), echo(&fixture, true));
        let removed = deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Uninstall, None, &backend).await.unwrap();
        assert_eq!(removed.cleanup.as_ref().unwrap().cleanup.logout_confirmed, 1);
        backend.reap_stopped().await;
        assert!(!backend.loaded().await && !fixture.plan.plist.exists());
        drop(TcpListener::bind(fixture.http).unwrap()); drop(TcpListener::bind(fixture.socks).unwrap());
        let counts = (gateway.state.logins.load(Ordering::SeqCst), gateway.state.logouts.load(Ordering::SeqCst));
        gateway.close().await;
        assert_eq!(counts, (2, 2));
        eprintln!("DEPLOY distinct_release={} generation_changed=true instance_changed=true old_streams_closed=true echo_bytes=32768 explicit_logins=2 confirmed_logouts=2 children_reaped=true", hexadecimal(&expected));
    }).await.unwrap();
}

#[tokio::test]
async fn recovery_after_admission_stops_exact_new_instance_and_survives_interruption() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let backend = fixture.backend();
        fixture.allow_listeners();
        backend.fail_once(Fault::BootstrapAfter).await;
        assert!(deployment::install_with_backend(fixture.plan.clone(), true, &backend).await.is_err());
        let admitted = control::inspect(&fixture.plan.gate.control).await.unwrap();
        let original_generation = admitted.managed.unwrap().generation;
        fixture.authenticate().await;
        let (mut http, mut socks) = tokio::join!(echo(&fixture, false), echo(&fixture, true));
        // The cancellation point follows a real stop receipt and runtime
        // retirement but precedes the service-manager effect. Dropping this
        // future models an interrupted manager without a background continuation.
        let pause = backend.pause_once(Fault::BootoutBefore).await;
        let expected = deployment::recovery_plan(&fixture.plan.state_directory).unwrap();
        let mut recovering = Box::pin(deployment::recover_with_backend(&fixture.plan.state_directory, Some(&expected), &backend));
        tokio::select! {
            result = &mut recovering => panic!("recovery did not reach its controlled interruption: {result:?}"),
            _ = pause.wait_entered() => {}
        }
        tokio::join!(closed(&mut http), closed(&mut socks));
        assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 1);
        assert!(!fixture.gate().enabled);
        drop(recovering);
        pause.release();
        let saved = pending(&fixture).unwrap();
        assert_eq!(saved["next_stop"]["instance"], serde_json::to_value(admitted.instance).unwrap());
        assert_eq!(saved["next_stop"]["managed"], serde_json::to_value(admitted.managed.unwrap()).unwrap());
        assert_eq!(saved["next_stop"]["report"]["cleanup"]["logout_confirmed"], 1);
        let resumed_generation = fixture.gate().identity.generation;
        let recovered = deployment::recover_with_backend(&fixture.plan.state_directory, None, &backend).await.unwrap();
        assert!(!recovered.admission_open && recovered.pending_operation.is_none());
        assert!(!recovered.remote_outcome_unknown);
        assert_eq!(recovered.cleanup_unconfirmed_episodes, 0);
        assert_eq!(recovered.retired_jobs, 0);
        assert!(recovered.generation > resumed_generation && resumed_generation > original_generation);
        assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 1, "recovery must not replay a completed stop");
        assert_eq!(ledger(&fixture)["last_next_stop"]["instance"], serde_json::to_value(admitted.instance).unwrap());
        backend.reap_stopped().await;
        assert!(backend.alive_labels().await.is_empty() && !backend.loaded().await);
        fixture.released();
        assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
        // Recovery converges offline; only an explicit later Start admits a
        // fresh daemon and only a separate explicit reauth creates VPN traffic.
        deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Start, None, &backend).await.unwrap();
        let new = fixture.ready().await;
        assert_ne!(new.instance, admitted.instance);
        assert!(new.managed.unwrap().generation > recovered.generation);
        assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
        fixture.authenticate().await;
        tokio::join!(echo(&fixture, false), echo(&fixture, true));
        let final_report = deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Stop, None, &backend).await.unwrap();
        assert_eq!(final_report.cleanup.unwrap().cleanup.logout_confirmed, 1);
        fixture.released();
        gateway.idle().await;
        assert_eq!((gateway.state.logins.load(Ordering::SeqCst), gateway.state.logouts.load(Ordering::SeqCst)), (2,2));
        gateway.close().await;
        eprintln!("RECOVER bootstrap_after=true interrupted_after_bound_receipt=true repeat_logout=false attempted_instance_receipt=true explicit_start_and_auth=true echo_bytes=32768 all_owned_children_reaped=true");
    }).await.unwrap();
}

#[tokio::test]
async fn recovery_without_receipt_stays_unknown_and_stale_plan_has_no_effects() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let backend = fixture.backend();
        fixture.allow_listeners();
        backend.fail_once(Fault::BootstrapBefore).await;
        assert!(deployment::install_with_backend(fixture.plan.clone(), true, &backend).await.is_err());
        assert!(backend.alive_labels().await.is_empty());
        let old_plan = deployment::recovery_plan(&fixture.plan.state_directory).unwrap();
        let recovered = deployment::recover_with_backend(&fixture.plan.state_directory, Some(&old_plan), &backend).await.unwrap();
        assert!(!recovered.admission_open && recovered.pending_operation.is_none());
        assert!(recovered.remote_outcome_unknown);
        assert_eq!(recovered.cleanup_unconfirmed_episodes, 0, "no daemon incarnation ever existed");
        assert_eq!(recovered.runtime_finished_incarnations, 0);
        assert_eq!(recovered.runtime_unfinished_incarnations, 0);
        assert_eq!(recovered.cleanup_totals.known_sessions, 0);
        assert_eq!(recovered.maintenance_unconfirmed_episodes, 1);
        assert!(recovered.maintenance_outcome_unknown);
        assert!(recovered.cleanup.is_none() && recovered.cleanup_evidence_source.is_none());
        assert_eq!(recovered.retired_jobs, 1, "an absent model definition is a nonzero exit, never affirmative removal proof");
        let recorded = ledger(&fixture);
        assert!(recorded["last_next_stop"].is_null());
        assert_eq!(recorded["last_unknown"]["reason"], "runtime_retired_without_receipt");
        let before_actions = backend.observations().await.len();
        let before_gate = fixture.gate();
        let stale = deployment::recover_with_backend(&fixture.plan.state_directory, Some(&old_plan), &backend).await.unwrap_err();
        assert_eq!(stale.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(backend.observations().await.len(), before_actions);
        assert_eq!(fixture.gate(), before_gate);
        assert_eq!(ledger(&fixture), recorded);
        assert!(pending(&fixture).is_none());
        let repeated = deployment::recover_with_backend(&fixture.plan.state_directory, None, &backend).await.unwrap();
        assert!(repeated.remote_outcome_unknown);
        assert_eq!(repeated.cleanup_unconfirmed_episodes, 0, "recovery retries do not invent daemon incarnations");
        assert_eq!(repeated.maintenance_unconfirmed_episodes, 1, "the one unknown manager effect is not counted again");
        assert!(repeated.maintenance_outcome_unknown);
        assert_eq!(repeated.runtime_finished_incarnations, 0);
        assert_eq!(repeated.runtime_unfinished_incarnations, 0);
        assert_eq!(repeated.cleanup_totals.known_sessions, 0);
        assert_eq!(repeated.retired_jobs, 1);
        fixture.released();
        assert!(fixture.plan.gate.binary.exists(), "retained release data must survive uncertain cleanup");
        assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);
        gateway.close().await;
        eprintln!("RECOVER bootstrap_before=true missing_receipt_sticky_unknown=true retired_definition_retained=true stale_expectation_actions=0 gateway_connections=0 no_owned_daemon_created=true");
    }).await.unwrap();
}

#[tokio::test]
async fn delayed_old_bootout_after_recovery_cannot_remove_new_generation() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let backend = fixture.backend();
        fixture.allow_listeners();
        deployment::install_with_backend(fixture.plan.clone(), true, &backend).await.unwrap();
        let old = fixture.ready().await;
        let old_label = current_label(&old.managed.unwrap());
        let unknown_file = fixture.plan.state_directory.join("data/unrecognized-user-data");
        let unknown_stage = fixture.plan.state_directory.join("data/.gp-control-stage-11111111111111111111111111111111");
        fs::write(&unknown_file, b"synthetic-preserve-this-user-data").unwrap();
        DirBuilder::new().mode(0o700).create(&unknown_stage).unwrap();
        fs::write(unknown_stage.join("incomplete"), b"synthetic-unrecognized-initialization").unwrap();
        let unknown_identities = (fs::metadata(&unknown_file).unwrap().ino(), fs::metadata(&unknown_stage).unwrap().ino());
        fixture.authenticate().await;
        let (mut http, mut socks) = tokio::join!(echo(&fixture, false), echo(&fixture, true));
        backend.delay_once(ActionKind::Bootout).await;
        assert!(deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Stop, None, &backend).await.is_err());
        tokio::join!(closed(&mut http), closed(&mut socks));
        assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 1);
        assert_eq!(backend.delayed_count().await, 1);
        backend.delay_once(ActionKind::Bootout).await;
        let recovered = deployment::recover_with_backend(&fixture.plan.state_directory, None, &backend).await.unwrap();
        assert_eq!(recovered.retired_jobs, 1);
        assert!(!recovered.remote_outcome_unknown, "a manager removal failure does not discard the exact remote logout receipt");
        assert_eq!(backend.delayed_count().await, 2);
        assert_eq!(ledger(&fixture)["last_previous_stop"]["instance"], serde_json::to_value(old.instance).unwrap());
        deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Start, None, &backend).await.unwrap();
        let new = fixture.ready().await;
        let new_label = current_label(&new.managed.unwrap());
        assert_ne!(new_label, old_label);
        assert_ne!(new.instance, old.instance);
        assert_eq!(backend.loaded_labels().await.len(), 2);
        assert_eq!(backend.alive_labels().await, std::slice::from_ref(&new_label));
        fixture.authenticate().await;
        let (mut fresh_http, mut fresh_socks) = tokio::join!(echo(&fixture, false), echo(&fixture, true));
        assert_eq!(backend.complete_delayed().await.unwrap(), Outcome::Exited { success:true, code:Some(0) });
        assert!(matches!(backend.complete_delayed().await.unwrap(), Outcome::Exited { success:false, .. }));
        assert_eq!(backend.delayed_count().await, 0);
        assert_eq!(backend.loaded_labels().await, std::slice::from_ref(&new_label));
        assert_eq!(backend.alive_labels().await, [new_label]);
        assert_eq!(control::inspect(&fixture.plan.gate.control).await.unwrap().instance, new.instance);
        for stream in [&mut fresh_http, &mut fresh_socks] {
            stream.write_all(b"late-old-label-cannot-stop-this-flow").await.unwrap();
            let mut reply = [0; 36];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"late-old-label-cannot-stop-this-flow");
        }
        let delivered: Vec<_> = backend.observations().await.into_iter().filter(|event| event.delayed_delivery).collect();
        assert_eq!(delivered.len(), 2);
        assert!(delivered.iter().all(|event| event.gate_enabled == Some(true) && matches!(&event.action, Action::Bootout { label, .. } if label == &old_label)));
        deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Stop, None, &backend).await.unwrap();
        tokio::join!(closed(&mut fresh_http), closed(&mut fresh_socks));
        fixture.released();
        assert!(!backend.loaded().await);
        assert_eq!(fs::read(&unknown_file).unwrap(), b"synthetic-preserve-this-user-data");
        assert_eq!(fs::read(unknown_stage.join("incomplete")).unwrap(), b"synthetic-unrecognized-initialization");
        assert_eq!((fs::metadata(&unknown_file).unwrap().ino(), fs::metadata(&unknown_stage).unwrap().ino()), unknown_identities);
        gateway.idle().await;
        assert_eq!((gateway.state.logins.load(Ordering::SeqCst), gateway.state.logouts.load(Ordering::SeqCst)), (2,2));
        gateway.close().await;
        eprintln!("RECOVER unrelated_data_preserved=true partial_subsystem_recovery_not_claimed=true delayed_old_bootout_deliveries=2 new_managed_and_instance_preserved=true old_receipt_bound=true dual_flow_after_late_action=true logins=2 logouts=2 all_owned_children_reaped=true");
    }).await.unwrap();
}

#[tokio::test]
async fn recovery_resume_same_generation_requires_the_new_instance_receipt() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let backend = fixture.backend();
        fixture.allow_listeners();
        deployment::install_with_backend(fixture.plan.clone(), true, &backend).await.unwrap();
        let previous = fixture.ready().await;
        fixture.authenticate().await;
        let before_kickstart = backend.pause_once(Fault::KickstartBefore).await;
        backend.fail_once(Fault::KickstartAfter).await;
        let mut resume = Box::pin(deployment::change_with_backend(&fixture.plan.state_directory, ManageAction::Start, None, &backend));
        tokio::select! {
            result = &mut resume => panic!("Resume did not reach its controlled observation-to-kickstart window: {result:?}"),
            _ = before_kickstart.wait_entered() => {}
        }
        // The coordinator has already inspected A. Ordinary IPC stops it while
        // the no-k Kickstart is paused; that same label will now create B.
        let old_receipt = control::stop(&fixture.plan.gate.control, &previous.binding, Some(previous.instance)).await.unwrap();
        assert_eq!(old_receipt.cleanup.logout_confirmed, 1);
        backend.reap_label(&current_label(&previous.managed.unwrap())).await;
        before_kickstart.release();
        assert!(resume.await.is_err());
        // Resume owns the maintenance lock until it returns. B's begin keeps
        // A's last_finished proof, so inspect it only after that lock is free
        // and before any authentication or cleanup of B.
        let old_view = managed_runtime::open_maintenance(&fixture.plan.state_directory.join("runtime")).unwrap().lifecycle().unwrap();
        assert_eq!(old_view.finished_for(&previous.managed.unwrap(), &previous.instance), Some(&old_receipt));
        let old_ordinal = old_view.last_finished().unwrap().0.ordinal();
        let next = control::inspect(&fixture.plan.gate.control).await.unwrap();
        assert_eq!(next.managed, previous.managed);
        assert_ne!(next.instance, previous.instance);
        assert_eq!(pending(&fixture).unwrap()["operation"], "resume");
        fixture.authenticate().await;
        let (mut http, mut socks) = tokio::join!(echo(&fixture, false), echo(&fixture, true));
        let report = deployment::recover_with_backend(&fixture.plan.state_directory, None, &backend).await.unwrap();
        tokio::join!(closed(&mut http), closed(&mut socks));
        let recorded = ledger(&fixture);
        assert_eq!(recorded["last_next_stop"]["instance"], serde_json::to_value(next.instance).unwrap());
        assert_ne!(recorded["last_next_stop"]["instance"], serde_json::to_value(previous.instance).unwrap());
        assert_eq!(recorded["last_next_stop"]["managed"], serde_json::to_value(previous.managed.unwrap()).unwrap());
        assert_eq!(recorded["last_next_stop"]["report"]["cleanup"]["logout_confirmed"], 1);
        let previous_proof = &recorded["last_previous_stop"];
        assert_eq!(previous_proof["instance"], serde_json::to_value(previous.instance).unwrap());
        assert_eq!(previous_proof["managed"], serde_json::to_value(previous.managed.unwrap()).unwrap());
        assert_eq!(previous_proof["source"]["kind"], "runtime_terminal");
        assert_eq!(previous_proof["source"]["ordinal"], old_ordinal);
        assert!(previous_proof["source"]["sequence"].as_u64().unwrap() >= old_view.sequence);
        assert_eq!(previous_proof["report"], serde_json::to_value(&old_receipt).unwrap());
        assert_eq!(recorded["last_next_stop"]["source"]["kind"], "ipc");
        let report_source = serde_json::to_value(&report.cleanup_evidence_source).unwrap();
        assert_eq!(report_source["kind"], "runtime_terminal");
        assert_eq!(report_source["ordinal"], previous_proof["source"]["ordinal"]);
        assert_eq!(serde_json::to_value(&report.cleanup).unwrap(), serde_json::to_value(&old_receipt).unwrap());
        assert!(!report.remote_outcome_unknown, "A has its exact durable terminal, distinct from B's IPC receipt");
        assert_eq!(report.cleanup_unconfirmed_episodes, 0);
        assert_eq!(report.maintenance_unconfirmed_episodes, 0);
        assert!(!report.maintenance_outcome_unknown);
        assert_eq!((report.runtime_finished_incarnations, report.runtime_unfinished_incarnations), (2, 0));
        assert_eq!((report.cleanup_totals.known_sessions, report.cleanup_totals.logout_confirmed), (2, 2));
        assert!(!report.admission_open && report.pending_operation.is_none());
        backend.reap_stopped().await;
        fixture.released();
        assert!(!backend.loaded().await);
        gateway.idle().await;
        assert_eq!((gateway.state.logins.load(Ordering::SeqCst), gateway.state.logouts.load(Ordering::SeqCst)), (2,2));
        gateway.close().await;
        eprintln!("RECOVER resume_observed_a_then_created_b=true resume_same_generation=true different_instances=true predecessor_receipt_not_reused=true attempted_bound_receipt=true predecessor_exact_durable_terminal=true current_instance_separate_ipc=true journal_finished=2 journal_unfinished=0 logins=2 logouts=2 all_owned_children_reaped=true");
    }).await.unwrap();
}

#[tokio::test]
async fn synthetic_stop_requested_recovery_keeps_a_proof_while_stopping_same_generation_b() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let backend = fixture.backend();
        fixture.allow_listeners();
        deployment::install_with_backend(fixture.plan.clone(), true, &backend).await.unwrap();
        let first = fixture.ready().await;
        let managed = first.managed.unwrap();
        fixture.authenticate().await;
        let (mut old_http, mut old_socks) = tokio::join!(echo(&fixture, false), echo(&fixture, true));

        // Explicit recovery-input construction, not an alleged natural apply
        // interleaving. Production Stop closes admission before StopRequested;
        // this fixture leaves the original enabled gate untouched while it
        // creates a valid interrupted transaction through public Store APIs.
        // It never reopens a gate closed by the production manager.
        {
            let mut store = Store::open(&fixture.plan.state_directory).unwrap();
            let mut next = serde_json::to_value(store.record()).unwrap();
            next["gate"]["enabled"] = serde_json::Value::Bool(false);
            store.begin(gp_proxy::deployment_store::Operation::Stop, serde_json::from_value(next).unwrap()).unwrap();
            store.observe_previous_instance(first.instance).unwrap();
            store.advance(gp_proxy::deployment_store::Phase::StopRequested, None).unwrap();
        }
        assert!(fixture.gate().enabled);
        let saved = pending(&fixture).unwrap();
        assert_eq!(saved["operation"], "stop");
        assert_eq!(saved["phase"], "stop_requested");
        assert_eq!(saved["previous_instance"], serde_json::to_value(first.instance).unwrap());
        assert_eq!(saved["next"]["gate"]["enabled"], false);
        assert!(saved["stop"].is_null() && saved["next_stop"].is_null());
        let first_receipt = control::stop(&fixture.plan.gate.control, &first.binding, Some(first.instance)).await.unwrap();
        tokio::join!(closed(&mut old_http), closed(&mut old_socks));
        backend.reap_label(&current_label(&managed)).await;
        let first_view = managed_runtime::open_maintenance(&fixture.plan.state_directory.join("runtime")).unwrap().lifecycle().unwrap();
        assert_eq!(first_view.finished_for(&managed, &first.instance), Some(&first_receipt));
        let first_ordinal = first_view.last_finished().unwrap().0.ordinal();
        assert_eq!(first_receipt.cleanup.logout_confirmed, 1);

        // The fake backend models an independently restarted definition using
        // its original immutable arguments. No launchctl runs in this test.
        let outcome = gp_proxy::deployment::backend::Executor::execute(&backend, Action::Kickstart {
            uid:fixture.plan.uid, label:current_label(&managed),
        }).await.unwrap();
        assert_eq!(outcome, Outcome::Exited { success:true, code:Some(0) });
        let second = timeout(STEP, async {
            loop {
                if let Ok(identity) = control::inspect(&fixture.plan.gate.control).await {
                    if identity.instance != first.instance { break identity; }
                }
                sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        assert_eq!(second.managed, Some(managed));
        assert_ne!(second.instance, first.instance);
        assert!(!status::query(fixture.http).await.unwrap().available);
        assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
        fixture.authenticate().await;
        let (mut http, mut socks) = tokio::join!(echo(&fixture, false), echo(&fixture, true));
        let recovered = deployment::recover_with_backend(&fixture.plan.state_directory, None, &backend).await.unwrap();
        tokio::join!(closed(&mut http), closed(&mut socks));
        let recorded = ledger(&fixture);
        let predecessor = &recorded["last_previous_stop"];
        assert_eq!(predecessor["instance"], serde_json::to_value(first.instance).unwrap());
        assert_ne!(predecessor["instance"], serde_json::to_value(second.instance).unwrap());
        assert_eq!(predecessor["source"]["kind"], "runtime_terminal");
        assert_eq!(predecessor["source"]["ordinal"], first_ordinal);
        assert_eq!(predecessor["report"], serde_json::to_value(&first_receipt).unwrap());
        assert!(recorded["last_next_stop"].is_null(), "B must not be fabricated as an attempted new generation");
        let final_view = managed_runtime::open_maintenance(&fixture.plan.state_directory.join("runtime")).unwrap().lifecycle().unwrap();
        let second_terminal = final_view.finished_for(&managed, &second.instance).unwrap();
        assert!(second_terminal.local_cleanup_complete);
        assert_eq!((second_terminal.cleanup.known_sessions, second_terminal.cleanup.logout_confirmed), (1, 1));
        assert!(final_view.last_finished().unwrap().0.ordinal() > first_ordinal);
        assert_eq!(serde_json::to_value(&recovered.cleanup).unwrap(), serde_json::to_value(&first_receipt).unwrap());
        let source = serde_json::to_value(&recovered.cleanup_evidence_source).unwrap();
        assert_eq!(source["kind"], "runtime_terminal");
        assert_eq!(source["ordinal"], first_ordinal);
        assert!(!recovered.remote_outcome_unknown && !recovered.maintenance_outcome_unknown);
        assert_eq!((recovered.cleanup_unconfirmed_episodes, recovered.maintenance_unconfirmed_episodes), (0,0));
        assert_eq!((recovered.runtime_finished_incarnations, recovered.runtime_unfinished_incarnations), (2,0));
        assert_eq!((recovered.cleanup_totals.known_sessions, recovered.cleanup_totals.logout_confirmed), (2,2));
        assert!(!recovered.admission_open && recovered.pending_operation.is_none() && recovered.retired_jobs == 0);
        backend.reap_stopped().await;
        assert!(!backend.loaded().await && backend.alive_labels().await.is_empty());
        fixture.released();
        gateway.idle().await;
        assert_eq!((gateway.state.logins.load(Ordering::SeqCst), gateway.state.logouts.load(Ordering::SeqCst)), (2,2));
        gateway.close().await;
        eprintln!("RECOVER synthetic_persisted_input=true natural_stop_interleaving_claimed=false stop_requested_a=true same_generation_b_stopped=true a_terminal_not_overwritten=true b_terminal_independent=true journal_finished=2 journal_unfinished=0 echo_bytes=32768 logins=2 logouts=2 all_owned_children_reaped=true");
    }).await.unwrap();
}
