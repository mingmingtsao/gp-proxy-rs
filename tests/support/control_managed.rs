//! Synthetic private Unix peers exercise Hello parsing and read-only inspection.
//! A mock identity is not evidence that a real process acquired a runtime lease.
use super::*;
use crate::managed_protocol::ManagedIdentity;
use serde_json::{json, Value};
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(3);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(format!(
            "/tmp/gp-managed-hello-{:016x}",
            rand::random::<u64>()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn valid_identity() -> ManagedIdentity {
    ManagedIdentity {
        installation: [1; 16],
        generation: 7,
        release: [2; 32],
    }
}

async fn inspect_peer(make: impl FnOnce(Value) -> Vec<u8>) -> (io::Result<ControlIdentity>, usize) {
    let directory = Directory::new();
    let path = directory.0.join("control");
    let listener = LocalListener::bind(&path).unwrap();
    let frame = json!({
        "version": PROTOCOL_VERSION,
        "instance": listener.instance_id(),
        "challenge": ([3u8; 16]),
        "binding": {"mode":"direct", "gateway":"https://managed-synthetic.invalid"},
        "phase":"active",
        "supports_stop":true,
        "managed":null,
    });
    let body = make(frame);
    assert!(body.len() <= 4096);
    let peer = tokio::spawn(async move {
        timeout(STEP, async move {
            let mut stream = listener.accept().await.unwrap();
            stream
                .write_u32(body.len().try_into().unwrap())
                .await
                .unwrap();
            stream.write_all(&body).await.unwrap();
            stream.flush().await.unwrap();
            stream.read(&mut [0; 1]).await.unwrap()
        })
        .await
        .unwrap()
    });
    let result = inspect(&path).await;
    // Join even for rejected frames before making behavior assertions.
    let submitted = timeout(STEP, peer).await.unwrap().unwrap();
    (result, submitted)
}

#[tokio::test]
async fn unmanaged_null_inspection_is_readonly_and_available_while_active() {
    let (result, submitted) = inspect_peer(|frame| serde_json::to_vec(&frame).unwrap()).await;
    let observed = result.unwrap();
    assert_eq!(observed.managed, None);
    assert_eq!(observed.phase, ServicePhase::Active);
    assert!(observed.supports_stop);
    assert_eq!(
        observed.binding.gateway(),
        "https://managed-synthetic.invalid"
    );
    assert_eq!(submitted, 0, "inspection must never submit an operation");
}

#[tokio::test]
async fn managed_identity_is_returned_without_submitting_authentication() {
    let expected = valid_identity();
    let (result, submitted) = inspect_peer(|mut frame| {
        frame["managed"] = serde_json::to_value(expected).unwrap();
        serde_json::to_vec(&frame).unwrap()
    })
    .await;
    assert_eq!(result.unwrap().managed, Some(expected));
    assert_eq!(submitted, 0);
}

#[tokio::test]
async fn v4_and_missing_managed_fields_do_not_pass_v5_inspection() {
    for old_version in [false, true] {
        let (result, submitted) = inspect_peer(|mut frame| {
            if old_version {
                frame["version"] = json!(4);
            } else {
                frame.as_object_mut().unwrap().remove("managed");
            }
            serde_json::to_vec(&frame).unwrap()
        })
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(submitted, 0);
    }
}

#[tokio::test]
async fn invalid_managed_identity_is_rejected_without_a_client_frame() {
    for case in 0..7 {
        let (result, submitted) = inspect_peer(|mut frame| {
            let mut identity = serde_json::to_value(valid_identity()).unwrap();
            match case {
                0 => identity["generation"] = json!(0),
                1 => identity["installation"] = json!(([0u8; 16])),
                2 => identity["release"] = json!(([0u8; 32])),
                3 => identity["unexpected"] = json!("synthetic-private-body-must-not-echo"),
                4 => identity["installation"] = json!([1]),
                5 => identity["release"] = json!([2]),
                6 => identity = json!(false),
                _ => unreachable!(),
            }
            frame["managed"] = identity;
            serde_json::to_vec(&frame).unwrap()
        })
        .await;
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!error.to_string().contains("synthetic-private-body"));
        assert_eq!(submitted, 0, "case {case}");
    }
}

#[tokio::test]
async fn duplicate_managed_field_is_not_silently_replaced() {
    let (result, submitted) = inspect_peer(|frame| {
        let mut body = serde_json::to_vec(&frame).unwrap();
        assert_eq!(body.pop(), Some(b'}'));
        body.extend_from_slice(b",\"managed\":null}");
        body
    })
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(submitted, 0);
}
