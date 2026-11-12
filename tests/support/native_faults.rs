//! Opt-in native faults. This module only signals the exact owned launchd
//! label, never a discovered PID or an entire gui domain.
use super::*;

const KEEPALIVE: Duration = Duration::from_secs(75);

async fn start(f: &mut Fixture, gateway: &gateway::Gateway) -> control::ControlIdentity {
    let installed = deployment::install(f.plan.clone(), false).await.unwrap();
    assert!(installed.installed && !installed.admission_open);
    assert!(installed.pending_operation.is_none());
    assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);
    f.reservations.take();
    f.native_effects_possible = true;
    f.event("fault_first_native_start", serde_json::json!({}));
    deployment::change(&f.plan.state_directory, ManageAction::Start)
        .await
        .unwrap();
    let first = f.ready().await;
    assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);
    first
}

/// Require all the ownership evidence immediately before the one signal. The
/// launchctl API targets a service's current process, not an atomic IPC instance.
/// The post-signal instance and flow checks are therefore separate evidence.
async fn verify_signal_target(f: &Fixture, first: &control::ControlIdentity) -> String {
    f.verify_installation().unwrap();
    assert_eq!(rustix::process::geteuid().as_raw(), f.plan.uid);
    let gate = f.gate();
    assert!(gate.enabled);
    assert_eq!(first.managed, Some(gate.identity));
    let exact_label = label(&gate.identity);
    let store = Store::open(&f.plan.state_directory).unwrap();
    store.verify_current_plist().unwrap();
    let record = serde_json::to_value(store.record()).unwrap();
    assert_eq!(record["label"], exact_label);
    assert_eq!(
        record["plist_path"],
        serde_json::to_value(
            f.plan
                .launch_agents_directory
                .join(format!("{exact_label}.plist"))
        )
        .unwrap()
    );
    assert!(store.pending().is_none());
    drop(store);
    let maintenance =
        managed_runtime::open_maintenance(&f.plan.state_directory.join("runtime")).unwrap();
    assert_eq!(
        maintenance.try_runtime().err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(maintenance);
    let now = control::inspect(&f.plan.gate.control).await.unwrap();
    assert_eq!(now.instance, first.instance);
    assert_eq!(now.managed, first.managed);
    assert!(status::query(f.http).await.unwrap().available);
    format!("gui/{}/{exact_label}", f.plan.uid)
}

pub(super) async fn daemon_crash(f: &mut Fixture, gateway: &gateway::Gateway) {
    let first = start(f, gateway).await;
    f.authenticate().await;
    let (mut first_http, mut first_socks) = tokio::join!(echo(f, false), echo(f, true));
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 0);
    let target = verify_signal_target(f, &first).await;
    // Retain the evidence even if the signal's child outcome is uncertain.
    // No cleanup result from a replacement instance can erase this expectation.
    f.expected_remote_outcome_uncertain = true;
    f.event(
        "owned_service_sigkill_requested",
        serde_json::json!({
            "target":target,"instance":hexadecimal(&first.instance),"managed":first.managed,
            "runtime_busy":true,"login_requests":1,"logout_requests":0,
            "atomic_instance_target_claimed":false
        }),
    );
    assert_eq!(f.service_kills, 0, "only one service fault is permitted");
    f.service_kills += 1;
    let (code, output) = f
        .commands
        .run(
            Path::new("/bin/launchctl"),
            &["kill".into(), "SIGKILL".into(), target],
            &f.root.join("cwd"),
            None,
        )
        .await
        .unwrap();
    f.event(
        "owned_service_sigkill_completed",
        serde_json::json!({
            "exit_code":code,"stdout_bytes":output.len(),"owned_command_reaped":true
        }),
    );
    assert_eq!(code, Some(0));
    tokio::join!(closed(&mut first_http), closed(&mut first_socks));

    // Passive observation only: do not kickstart/enable or submit credentials to
    // compensate for a failed KeepAlive restart. The 75s fixture budget includes
    // the installed 30s throttle and does not alter a production timeout.
    let restarted = timeout(KEEPALIVE, async {
        loop {
            if let Ok(identity) = control::inspect(&f.plan.gate.control).await {
                if identity.instance != first.instance {
                    assert_eq!(identity.managed, first.managed);
                    break identity;
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("launchd KeepAlive did not publish a new owned instance");
    let second = f.ready().await;
    assert_eq!(second.instance, restarted.instance);
    assert_ne!(second.instance, first.instance);
    assert_eq!(second.managed, first.managed);
    // A short explicit waiting interval also checks that local readiness is not
    // followed by an automatic credential replay.
    sleep(Duration::from_millis(250)).await;
    assert!(!status::query(f.http).await.unwrap().available);
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 0);
    f.event("keepalive_restarted_without_authentication", serde_json::json!({
        "old_instance":hexadecimal(&first.instance),"new_instance":hexadecimal(&second.instance),
        "managed":second.managed,"login_requests":1,"logout_requests":0
    }));
    let inspected = deployment::inspect(&f.plan.state_directory).await.unwrap();
    f.report_event(
        "crash_inspect_completed",
        serde_json::to_value(&inspected).unwrap(),
    );

    f.authenticate().await;
    let (mut http, mut socks) = tokio::join!(echo(f, false), echo(f, true));
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 2);
    let stopped = deployment::change(&f.plan.state_directory, ManageAction::Stop)
        .await
        .unwrap();
    f.report_event(
        "crash_stop_completed",
        serde_json::to_value(&stopped).unwrap(),
    );
    let cleanup = stopped.cleanup.as_ref().unwrap();
    assert!(cleanup.local_cleanup_complete);
    assert_eq!(cleanup.cleanup.known_sessions, 1);
    assert_eq!(cleanup.cleanup.logout_confirmed, 1);
    assert_eq!(cleanup.cleanup.logout_unconfirmed, 0);
    tokio::join!(closed(&mut http), closed(&mut socks));
    f.verify_released().unwrap();
    let removed = deployment::change(&f.plan.state_directory, ManageAction::Uninstall)
        .await
        .unwrap();
    f.report_event(
        "crash_uninstall_completed",
        serde_json::to_value(&removed).unwrap(),
    );
    assert!(!removed.installed && !removed.admission_open && removed.pending_operation.is_none());
    assert_eq!(removed.retired_jobs, 0);
    f.completed_uninstall = true;
    f.verify_released().unwrap();
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 2);
    assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 1);
    assert_eq!(f.echo_bytes.load(Ordering::SeqCst), 32768);
    f.event(
        "crash_safety_expectation",
        serde_json::json!({
            "crashed_instance":hexadecimal(&first.instance),
            "replacement_instance":hexadecimal(&second.instance),
            "expected_remote_unknown":true,"expected_minimum_unconfirmed_episodes":1,
            "old_session_logout_observed":false,"local_operations_finished":true
        }),
    );
    // Deliberately checked only after all local operations and their reports
    // have been persisted. Current v2 loses A's accounting and must fail here;
    // neither B's confirmed logout nor destroying the mock gateway proves A's.
    for (phase, report) in [
        ("inspect", &inspected),
        ("stop", &stopped),
        ("uninstall", &removed),
    ] {
        assert!(
            report.remote_outcome_unknown && report.cleanup_unconfirmed_episodes > 0,
            "{phase} erased the crashed old instance's unresolved remote session"
        );
    }
}

pub(super) async fn manager_interrupted(f: &mut Fixture, gateway: &gateway::Gateway) {
    use std::{os::unix::process::ExitStatusExt, sync::Arc, time::Instant};
    use tokio::sync::Semaphore;

    let first = start(f, gateway).await;
    f.authenticate().await;
    let (mut http, mut socks) = tokio::join!(echo(f, false), echo(f, true));
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
    f.verify_installation().unwrap();
    let held = Arc::new(Semaphore::new(0));
    *gateway.state.logout_gate.lock().unwrap() = Some(held.clone());
    f.held_logout = Some(held);
    f.event(
        "owned_manager_stop_requested",
        serde_json::json!({
            "instance":hexadecimal(&first.instance),"managed":first.managed,
            "logout_response_held":true
        }),
    );
    let args = vec![
        "service".into(),
        "--state-dir".into(),
        f.plan.state_directory.to_str().unwrap().into(),
        "stop".into(),
    ];
    let cwd = f.root.join("cwd");
    // Dropping this future does not discard its Child: the outer Commands
    // registry holds it, so the next operation can kill/wait exactly that child.
    let arrived = {
        let mut command = Box::pin(f.commands.run(&f.plan.source_binary, &args, &cwd, None));
        tokio::select! {
            result = &mut command => panic!("manager completed before gated logout: {result:?}"),
            arrived = timeout(STEP, async {
                while gateway.state.logouts.load(Ordering::SeqCst) == 0 {
                    sleep(Duration::from_millis(2)).await;
                }
                let observed = Instant::now();
                assert!(!f.gate().enabled);
                observed
            }) => arrived.expect("owned manager did not reach synthetic logout gate"),
        }
    };
    // No Store open, source hashing or fsync is placed in this critical window.
    // The fixture's 6s gate and the service's 3s logout deadline are unchanged.
    assert_eq!(f.manager_kills, 0);
    let killed = f.commands.kill_pending().await;
    f.release_logout();
    *gateway.state.logout_gate.lock().unwrap() = None;
    let release_millis = arrived.elapsed().as_millis();
    let killed = killed.unwrap();
    f.event(
        "owned_manager_sigkill_completed",
        serde_json::json!({
            "signal":killed.signal(),"owned_child_reaped":true,
            "gate_release_after_arrival_millis":release_millis,
            "logout_requests":gateway.state.logouts.load(Ordering::SeqCst),
            "logout_confirmation_claimed":false
        }),
    );
    assert_eq!(killed.signal(), Some(9));
    f.manager_kills += 1;
    assert!(
        release_millis < 2000,
        "fault orchestration consumed the logout budget"
    );

    // Only now can the parent acquire the manager's former Store lock. A
    // durable StopRequested + absent receipt records the exact cut, while the
    // daemon independently continues cleanup after its IPC client disappeared.
    let store = Store::open(&f.plan.state_directory).unwrap();
    let pending = serde_json::to_value(store.pending().unwrap()).unwrap();
    assert_eq!(pending["operation"], "stop");
    assert_eq!(pending["phase"], "stop_requested");
    assert!(pending["stop"].is_null());
    assert!(pending["next_stop"].is_null());
    assert_eq!(
        pending["previous_instance"],
        serde_json::to_value(first.instance).unwrap()
    );
    assert_eq!(
        pending["previous"]["gate"]["identity"],
        serde_json::to_value(first.managed.unwrap()).unwrap()
    );
    drop(store);
    f.event(
        "interrupted_stop_persisted",
        serde_json::json!({
            "phase":"stop_requested","receipt_present":false,
            "previous_instance":hexadecimal(&first.instance),"gate_enabled":f.gate().enabled
        }),
    );
    tokio::join!(closed(&mut http), closed(&mut socks));

    let managed = first.managed.unwrap();
    let (sequence, ordinal, terminal) = timeout(STEP, async {
        loop {
            let maintenance =
                managed_runtime::open_maintenance(&f.plan.state_directory.join("runtime")).unwrap();
            let view = maintenance.lifecycle();
            drop(maintenance);
            let view = match view {
                Ok(view) => view,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    sleep(Duration::from_millis(10)).await;
                    continue;
                }
                Err(error) => panic!("cannot read exact lifecycle evidence: {error}"),
            };
            if let Some(report) = view.finished_for(&managed, &first.instance) {
                let (stamp, _) = view.last_finished().unwrap();
                assert_eq!(stamp.instance(), first.instance);
                assert_eq!(stamp.managed(), managed);
                break (view.sequence, stamp.ordinal(), report.clone());
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("exact stopped instance did not persist its terminal cleanup");
    assert!(terminal.local_cleanup_complete);
    assert_eq!(terminal.cleanup.known_sessions, 1);
    assert_eq!(terminal.cleanup.logout_confirmed, 1);
    assert_eq!(terminal.cleanup.logout_unconfirmed, 0);
    assert_eq!(terminal.cleanup.remote_outcome_unknown, 0);
    f.event(
        "interrupted_stop_runtime_terminal",
        serde_json::json!({
            "instance":hexadecimal(&first.instance),"managed":managed,
            "ordinal":ordinal,"sequence":sequence,"report":terminal,
            "ipc_receipt_observed":false
        }),
    );

    let recovered = deployment::recover(&f.plan.state_directory).await.unwrap();
    f.report_event(
        "interrupted_manager_recover_completed",
        serde_json::to_value(&recovered).unwrap(),
    );
    confirmed(&recovered, 1);
    assert!(!recovered.admission_open);
    assert!(recovered.generation > managed.generation);
    let source = serde_json::to_value(&recovered.cleanup_evidence_source).unwrap();
    assert_eq!(source["kind"], "runtime_terminal");
    assert_eq!(source["ordinal"], ordinal);
    assert!(source["sequence"].as_u64().unwrap() >= sequence);
    assert_eq!(
        serde_json::to_value(&recovered.cleanup).unwrap(),
        serde_json::to_value(&terminal).unwrap()
    );
    assert_eq!(recovered.cleanup_totals.known_sessions, 1);
    assert_eq!(recovered.cleanup_totals.logout_confirmed, 1);
    f.verify_released().unwrap();
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 1);

    deployment::change(&f.plan.state_directory, ManageAction::Start)
        .await
        .unwrap();
    let second = f.ready().await;
    assert_ne!(first.instance, second.instance);
    assert!(second.managed.unwrap().generation > managed.generation);
    sleep(Duration::from_millis(250)).await;
    assert!(!status::query(f.http).await.unwrap().available);
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
    f.authenticate().await;
    let (mut http, mut socks) = tokio::join!(echo(f, false), echo(f, true));
    let removed = deployment::change(&f.plan.state_directory, ManageAction::Uninstall)
        .await
        .unwrap();
    f.report_event(
        "interrupted_manager_uninstall_completed",
        serde_json::to_value(&removed).unwrap(),
    );
    confirmed(&removed, 1);
    assert!(!removed.installed && !removed.admission_open);
    assert_eq!(removed.runtime_finished_incarnations, 2);
    assert_eq!(removed.runtime_unfinished_incarnations, 0);
    assert_eq!(removed.cleanup_totals.known_sessions, 2);
    assert_eq!(removed.cleanup_totals.logout_confirmed, 2);
    tokio::join!(closed(&mut http), closed(&mut socks));
    f.completed_uninstall = true;
    f.verify_released().unwrap();
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 2);
    assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 2);
    assert_eq!(f.echo_bytes.load(Ordering::SeqCst), 32768);
}
