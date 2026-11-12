//! Tests the bounded synthetic backend itself, not launchd behavior.
use super::*;
use std::{io::Write, os::unix::fs::DirBuilderExt};

struct Fixture {
    directory: PathBuf,
    backend: Backend,
    gate: Gate,
}
impl Fixture {
    fn new() -> Self {
        let directory = PathBuf::from(format!("/tmp/gp-backend-{:016x}", rand::random::<u64>()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let directory = directory.canonicalize().unwrap();
        let identity = ManagedIdentity {
            installation: [0x12; 16],
            generation: 1,
            release: [0x34; 32],
        };
        let gate = Gate {
            version: 2,
            identity,
            enabled: false,
            binary: directory
                .join("versions")
                .join(hexadecimal(&identity.release))
                .join("gp-proxy"),
            config: directory.join("config"),
            control: directory.join("control"),
            logs: directory.join("logs"),
        };
        drop(managed_runtime::initialize(&directory.join("runtime"), &gate).unwrap());
        let label = label_for(&identity);
        let backend = Backend::new(
            directory.clone(),
            label.clone(),
            directory.join(format!("{label}.plist")),
            directory.clone(),
        );
        Self {
            directory,
            backend,
            gate,
        }
    }
    fn program(&self, generation: u64) -> Program {
        let identity = ManagedIdentity {
            generation,
            ..self.gate.identity
        };
        Program {
            label: label_for(&identity),
            identity,
            arguments: vec![],
        }
    }
    fn publish(&mut self, generation: u64, enabled: bool) {
        self.gate.identity.generation = generation;
        self.gate.enabled = enabled;
        managed_runtime::open_maintenance(&self.directory.join("runtime"))
            .unwrap()
            .set_gate(&self.gate)
            .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn owned_waiting_child() {
    if std::env::var("GP_BACKEND_OWNED_WAIT").as_deref() != Ok("1") {
        return;
    }
    // Only this synthetic child holds its own inherited pipe. No user stdin.
    let mut byte = [0];
    let _ = std::io::stdin().read(&mut byte).unwrap();
}
fn waiting_child() -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backend::tests::owned_waiting_child",
            "--test-threads=1",
        ])
        .env_clear()
        .env("GP_BACKEND_OWNED_WAIT", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

#[tokio::test]
async fn delayed_old_removal_preserves_new_owned_child_and_exact_label() {
    let mut f = Fixture::new();
    let old = f.program(1);
    let new = f.program(2);
    {
        let mut state = f.backend.state.lock().await;
        state.jobs.insert(
            old.label.clone(),
            Job {
                program: old.clone(),
                child: None,
            },
        );
        state.jobs.insert(
            new.label.clone(),
            Job {
                program: new.clone(),
                child: Some(waiting_child()),
            },
        );
    }
    f.backend.delay_once(ActionKind::Bootout).await;
    assert_eq!(
        f.backend
            .execute(Action::Bootout {
                uid: f.backend.uid,
                label: old.label.clone()
            })
            .await
            .unwrap(),
        unknown()
    );
    assert_eq!(f.backend.delayed_count().await, 1);
    f.publish(2, true);
    assert_eq!(f.backend.complete_delayed().await.unwrap(), success());
    assert_eq!(f.backend.delayed_count().await, 0);
    assert_eq!(
        f.backend.loaded_labels().await,
        std::slice::from_ref(&new.label)
    );
    assert_eq!(
        f.backend.alive_labels().await,
        std::slice::from_ref(&new.label)
    );
    let before = f.backend.observations().await;
    assert!(!before[0].delayed_delivery && before[1].delayed_delivery);
    assert_eq!(
        (before[0].generation, before[1].generation),
        (Some(1), Some(2))
    );
    assert!(matches!(&before[1].action, Action::Bootout { label, .. } if label == &old.label));
    assert_eq!(
        f.backend
            .execute(Action::Bootout {
                uid: f.backend.uid,
                label: new.label.clone()
            })
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        f.backend.alive_labels().await,
        std::slice::from_ref(&new.label)
    );
    assert!(!f.backend.crash_label(&new.label).await.success());
    f.backend.reap_label(&new.label).await;
    assert!(f.backend.alive_labels().await.is_empty());
    f.publish(3, false);
    assert_eq!(
        f.backend
            .execute(Action::Bootout {
                uid: f.backend.uid,
                label: new.label
            })
            .await
            .unwrap(),
        success()
    );
    assert!(!f.backend.loaded().await);
}

#[tokio::test]
async fn cancelled_paused_action_has_no_detached_effect_and_mutex_is_available() {
    let f = Fixture::new();
    let program = f.program(1);
    f.backend.state.lock().await.jobs.insert(
        program.label.clone(),
        Job {
            program: program.clone(),
            child: None,
        },
    );
    let action = Action::Bootout {
        uid: f.backend.uid,
        label: program.label.clone(),
    };
    let pause = f.backend.pause_once(Fault::BootoutBefore).await;
    let mut pending = Box::pin(f.backend.execute(action.clone()));
    tokio::select! {
        result = &mut pending => panic!("paused effect unexpectedly completed: {result:?}"),
        _ = pause.wait_entered() => {}
    }
    assert_eq!(
        f.backend.loaded_labels().await,
        std::slice::from_ref(&program.label)
    );
    assert_eq!(f.backend.observations().await.len(), 1);
    drop(pending);
    pause.release();
    tokio::task::yield_now().await;
    assert_eq!(
        f.backend.loaded_labels().await,
        std::slice::from_ref(&program.label)
    );
    let pause = f.backend.pause_once(Fault::BootoutAfter).await;
    let mut pending = Box::pin(f.backend.execute(action));
    tokio::select! {
        result = &mut pending => panic!("post-effect pause unexpectedly completed: {result:?}"),
        _ = pause.wait_entered() => {}
    }
    assert!(!f.backend.loaded().await);
    pause.release();
    assert_eq!(pending.await.unwrap(), success());
}

#[tokio::test]
async fn job_capacity_never_spawns_a_fourth_and_completed_children_are_reaped() {
    let f = Fixture::new();
    for generation in 1..=3 {
        let program = f.program(generation);
        f.backend.state.lock().await.jobs.insert(
            program.label.clone(),
            Job {
                program,
                child: None,
            },
        );
    }
    let fourth = f.program(4);
    let prepared = Prepared {
        action: Action::Bootstrap {
            uid: f.backend.uid,
            plist: f.directory.join(format!("{}.plist", fourth.label)),
        },
        program: Some(fourth),
    };
    assert_eq!(
        f.backend.apply(&prepared).await.unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(f.backend.loaded_labels().await.len(), 3);
    assert_eq!(f.backend.spawned().await, 0);
    let program = f.program(1);
    let mut child = waiting_child();
    child.stdin.take().unwrap().write_all(b"x").unwrap();
    f.backend
        .state
        .lock()
        .await
        .jobs
        .get_mut(&program.label)
        .unwrap()
        .child = Some(child);
    f.backend.reap_stopped().await;
    assert!(f.backend.alive_labels().await.is_empty());
}
