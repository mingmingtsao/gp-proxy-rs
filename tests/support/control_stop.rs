//! No-network protocol tests. Service tests separately exercise gateway cleanup.
use super::tests::{fixture, input};
use super::*;
use serde_json::{json, Value};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(2);

fn request(hello: &Hello) -> Value {
    json!({"op":"stop", "version":VERSION, "instance":hello.instance,
        "challenge":hello.challenge, "binding":hello.binding})
}

fn managed_hello(service: &ServiceHandle, nonce: u8) -> Hello {
    Hello {
        version: VERSION,
        instance: [1; 16],
        challenge: [nonce; 16],
        binding: service.binding(),
        phase: service.phase(),
        supports_stop: true,
        managed: None,
    }
}

async fn begin(
    service: ServiceHandle,
    sender: StopSender,
    nonce: u8,
) -> (
    tokio::io::DuplexStream,
    Hello,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    let (mut client, server) = tokio::io::duplex(128 * 1024);
    let hello = managed_hello(&service, nonce);
    let worker = tokio::spawn(handle(
        server,
        hello,
        service,
        CancellationToken::new(),
        Some(sender),
    ));
    let observed = timeout(STEP, read_frame(&mut client))
        .await
        .unwrap()
        .unwrap();
    (client, observed, worker)
}

#[tokio::test]
async fn malformed_or_mixed_stop_frames_never_close_admission() {
    for case in 0..16 {
        let (service, _actor, mut hello) = fixture();
        hello.supports_stop = case != 13;
        let (sender, mut receiver) = stop_channel();
        let (mut client, server) = tokio::io::duplex(128 * 1024);
        let worker = tokio::spawn(handle(
            server,
            hello,
            service.clone(),
            CancellationToken::new(),
            Some(sender),
        ));
        let hello: Hello = read_frame(&mut client).await.unwrap();
        let mut frame = request(&hello);
        match case {
            0 => frame["version"] = json!(VERSION - 1),
            1 => frame["instance"] = json!(([8u8; 16])),
            2 => frame["challenge"] = json!(([8u8; 16])),
            3 => {
                frame["binding"] = json!({"mode":"direct", "gateway":"https://other.example.test"})
            }
            4 => frame["authentication"] = serde_json::to_value(input()).unwrap(),
            5 => frame["interactive"] = json!(false),
            6 => frame["interactive"] = Value::Null,
            7 => frame["authentication"] = Value::Null,
            8 => frame["unknown"] = json!("synthetic-secret"),
            9 => {
                frame.as_object_mut().unwrap().remove("op");
            }
            10 => frame["op"] = json!("restart"),
            11 => frame["op"] = json!("authenticate"),
            12 => {
                frame["op"] = json!("authenticate");
                frame["authentication"] = serde_json::to_value(input()).unwrap();
            }
            13..=15 => {}
            _ => unreachable!(),
        }
        let mut body = serde_json::to_vec(&frame).unwrap();
        if case == 14 {
            body.pop();
            body.extend_from_slice(b",\"op\":\"stop\"}");
        }
        let mut wire = (body.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&body);
        if case == 15 {
            wire.push(0);
        }
        client.write_all(&wire).await.unwrap();
        let error = timeout(STEP, worker).await.unwrap().unwrap().unwrap_err();
        assert!(!error.to_string().contains("synthetic-secret"));
        assert_eq!(service.phase(), ServicePhase::Waiting, "case {case}");
        assert!(receiver.try_recv().is_err());
        assert!(service.completion().is_none());
    }
}

#[tokio::test]
async fn valid_stop_hands_off_without_waiting_for_cleanup_or_receipt() {
    let (service, actor, _) = fixture();
    let (sender, mut receiver) = stop_channel();
    let (mut client, hello, worker) = begin(service.clone(), sender, 2).await;
    write_frame(&mut client, &request(&hello)).await.unwrap();
    timeout(STEP, worker).await.unwrap().unwrap().unwrap();
    let responder = timeout(STEP, receiver.recv()).await.unwrap().unwrap();
    assert!(service.completion().is_none());
    assert_eq!(
        service
            .try_authenticate(
                input().into_input(&service.binding()).unwrap(),
                service.binding().gateway(),
                CancellationToken::new()
            )
            .err(),
        Some(StartError::Stopped)
    );
    assert!(timeout(
        Duration::from_millis(20),
        read_frame::<StopReply, _>(&mut client)
    )
    .await
    .is_err());
    timeout(STEP, actor.run()).await.unwrap();
    let cleanup = service.completion().unwrap();
    let report = StopReport {
        local_cleanup_complete: true,
        cleanup,
    };
    timeout(STEP, responder.complete(report))
        .await
        .unwrap()
        .unwrap();
    let StopReply::Stopped {
        version,
        instance,
        challenge,
        binding,
        report,
    } = timeout(STEP, read_frame(&mut client))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(version, VERSION);
    assert_eq!(instance, hello.instance);
    assert_eq!(challenge, hello.challenge);
    assert!(binding.matches(&hello.binding));
    assert!(report.local_cleanup_complete);
    assert_eq!(report.cleanup, CleanupSummary::default());
    let mut byte = [0; 1];
    assert_eq!(
        timeout(STEP, client.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn disconnect_after_stop_admission_does_not_cancel_stopping() {
    let (service, actor, _) = fixture();
    let (sender, mut receiver) = stop_channel();
    let (mut client, hello, worker) = begin(service.clone(), sender, 2).await;
    write_frame(&mut client, &request(&hello)).await.unwrap();
    let responder = timeout(STEP, receiver.recv()).await.unwrap().unwrap();
    drop(client);
    timeout(STEP, worker).await.unwrap().unwrap().unwrap();
    timeout(STEP, actor.run()).await.unwrap();
    assert!(!service.request_stop());
    let cleanup = service.completion().unwrap();
    assert!(responder
        .complete(StopReport {
            local_cleanup_complete: true,
            cleanup
        })
        .await
        .is_err());
    assert_eq!(service.phase(), ServicePhase::Stopped);
}

#[tokio::test]
async fn duplicate_stops_do_not_queue_additional_responders() {
    let (service, actor, _) = fixture();
    let (sender, mut receiver) = stop_channel();
    let (mut first, hello, worker) = begin(service.clone(), sender.clone(), 2).await;
    write_frame(&mut first, &request(&hello)).await.unwrap();
    timeout(STEP, worker).await.unwrap().unwrap().unwrap();
    let (mut second, hello, worker) = begin(service.clone(), sender.clone(), 3).await;
    write_frame(&mut second, &request(&hello)).await.unwrap();
    assert_eq!(
        timeout(STEP, worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let first_reply = receiver.try_recv().unwrap();
    let (mut third, hello, worker) = begin(service.clone(), sender, 4).await;
    write_frame(&mut third, &request(&hello)).await.unwrap();
    assert_eq!(
        timeout(STEP, worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    assert!(receiver.try_recv().is_err());
    drop((first_reply, first, second, third));
    timeout(STEP, actor.run()).await.unwrap();
    assert_eq!(service.completion(), Some(CleanupSummary::default()));
}

#[tokio::test]
async fn unavailable_completion_channel_does_not_accept_stop() {
    let (service, _actor, _) = fixture();
    let (sender, receiver) = stop_channel();
    drop(receiver);
    let (mut client, hello, worker) = begin(service.clone(), sender, 2).await;
    write_frame(&mut client, &request(&hello)).await.unwrap();
    assert_eq!(
        timeout(STEP, worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(service.phase(), ServicePhase::Waiting);
}

#[tokio::test(start_paused = true)]
async fn final_receipt_write_has_its_own_three_second_deadline() {
    let (client, server) = tokio::io::duplex(1);
    let responder = StopResponder {
        stream: Box::new(server),
        instance: [1; 16],
        challenge: [2; 16],
        binding: AuthBinding::direct("https://vpn.example.test").unwrap(),
    };
    let error = responder
        .complete(StopReport {
            local_cleanup_complete: true,
            cleanup: CleanupSummary::default(),
        })
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    drop(client);
}

#[test]
fn identity_inspection_allows_busy_phases_and_cleanup_counts_stay_honest() {
    let (_service, _actor, mut hello) = fixture();
    for phase in [
        ServicePhase::Active,
        ServicePhase::Authenticating,
        ServicePhase::Cleaning,
        ServicePhase::Stopped,
    ] {
        hello.phase = phase;
        assert!(validate_identity(&hello, hello.instance).is_ok());
        assert!(validate_hello(&hello, hello.instance).is_err());
    }
    let report =
        |known_sessions, logout_confirmed, logout_unconfirmed, remote_outcome_unknown| StopReport {
            local_cleanup_complete: true,
            cleanup: CleanupSummary {
                known_sessions,
                logout_confirmed,
                logout_unconfirmed,
                remote_outcome_unknown,
            },
        };
    assert!(
        report(0, 0, 0, 1).valid(),
        "unknown login outcome is independent of known cookies"
    );
    assert!(
        report(2, 1, 1, 0).valid(),
        "completed local cleanup need not confirm remote logout"
    );
    assert!(!report(1, 0, 0, 0).valid());
    assert!(!report(1, 1, 1, 0).valid());
    assert!(!report(u64::MAX, u64::MAX, 1, 0).valid());
}

#[tokio::test]
async fn stop_client_rejects_mismatched_receipts_and_reports_eof_as_unknown() {
    for case in 0..7 {
        let (mut server, client) = tokio::io::duplex(128 * 1024);
        let binding = AuthBinding::direct("https://vpn.example.test").unwrap();
        let server_binding = binding.clone();
        let peer = async move {
            let hello = Hello {
                version: VERSION,
                instance: [1; 16],
                challenge: [2; 16],
                binding: server_binding.clone(),
                phase: ServicePhase::Active,
                supports_stop: true,
                managed: None,
            };
            write_frame(&mut server, &hello).await.unwrap();
            let request: Submit = read_frame(&mut server).await.unwrap();
            assert!(matches!(request.op, Operation::Stop));
            assert!(request.authentication.is_none() && request.interactive.is_none());
            if case == 5 {
                return;
            }
            let mut reply = json!({"result":"stopped", "version":VERSION,
                "instance":([1;16]), "challenge":([2;16]), "binding":server_binding,
                "report":{"local_cleanup_complete":true,"cleanup":{
                    "known_sessions":0,"logout_confirmed":0,"logout_unconfirmed":0,"remote_outcome_unknown":0}}});
            match case {
                0 => reply["version"] = json!(VERSION - 1),
                1 => reply["instance"] = json!(([9u8; 16])),
                2 => reply["challenge"] = json!(([9u8; 16])),
                3 => {
                    reply["binding"] =
                        json!({"mode":"direct", "gateway":"https://other.example.test"})
                }
                4 => reply["report"]["cleanup"]["known_sessions"] = json!(1),
                6 => {
                    reply["report"]["cleanup"]["known_sessions"] = json!(u64::MAX);
                    reply["report"]["cleanup"]["logout_confirmed"] = json!(u64::MAX);
                    reply["report"]["cleanup"]["logout_unconfirmed"] = json!(1);
                }
                _ => unreachable!(),
            }
            write_frame(&mut server, &reply).await.unwrap();
        };
        let connection = control_local::LocalConnection {
            stream: Box::new(client),
            instance_id: [1; 16],
        };
        let work = stop_with_connection(async { Ok(connection) }, &binding, Some([1; 16]));
        let ((), result) = timeout(STEP, async { tokio::join!(peer, work) })
            .await
            .unwrap();
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(error.to_string(), "local stop completion was not observed");
    }
}

#[tokio::test]
async fn stop_client_preserves_unconfirmed_and_unknown_cleanup_results() {
    for local_cleanup_complete in [true, false] {
        let (mut server, client) = tokio::io::duplex(128 * 1024);
        let binding = AuthBinding::direct("https://vpn.example.test").unwrap();
        let server_binding = binding.clone();
        let cleanup = CleanupSummary {
            known_sessions: 2,
            logout_confirmed: 1,
            logout_unconfirmed: 1,
            remote_outcome_unknown: 3,
        };
        let peer = async move {
            write_frame(
                &mut server,
                &Hello {
                    version: VERSION,
                    instance: [1; 16],
                    challenge: [2; 16],
                    binding: server_binding.clone(),
                    phase: ServicePhase::Cleaning,
                    supports_stop: true,
                    managed: None,
                },
            )
            .await
            .unwrap();
            let _: Submit = read_frame(&mut server).await.unwrap();
            write_frame(
                &mut server,
                &StopReply::Stopped {
                    version: VERSION,
                    instance: [1; 16],
                    challenge: [2; 16],
                    binding: server_binding,
                    report: StopReport {
                        local_cleanup_complete,
                        cleanup,
                    },
                },
            )
            .await
            .unwrap();
        };
        let connection = control_local::LocalConnection {
            stream: Box::new(client),
            instance_id: [1; 16],
        };
        let work = stop_with_connection(async { Ok(connection) }, &binding, None);
        let ((), result) = timeout(STEP, async { tokio::join!(peer, work) })
            .await
            .unwrap();
        let report = result.unwrap();
        assert_eq!(report.local_cleanup_complete, local_cleanup_complete);
        assert_eq!(report.cleanup, cleanup);
    }
}

#[tokio::test]
async fn stop_client_validates_identity_and_capability_before_submitting() {
    for case in 0..3 {
        let (mut server, client) = tokio::io::duplex(128 * 1024);
        let binding = AuthBinding::direct("https://vpn.example.test").unwrap();
        let server_binding = if case == 1 {
            AuthBinding::direct("https://other.example.test").unwrap()
        } else {
            binding.clone()
        };
        let peer = async move {
            write_frame(
                &mut server,
                &Hello {
                    version: VERSION,
                    instance: [1; 16],
                    challenge: [2; 16],
                    binding: server_binding,
                    phase: ServicePhase::Active,
                    supports_stop: case != 2,
                    managed: None,
                },
            )
            .await
            .unwrap();
            assert_eq!(
                server.read(&mut [0; 1]).await.unwrap(),
                0,
                "no request may be submitted"
            );
        };
        let connection = control_local::LocalConnection {
            stream: Box::new(client),
            instance_id: [1; 16],
        };
        let work = stop_with_connection(
            async { Ok(connection) },
            &binding,
            Some(if case == 0 { [9; 16] } else { [1; 16] }),
        );
        let ((), result) = timeout(STEP, async { tokio::join!(peer, work) })
            .await
            .unwrap();
        assert_eq!(
            result.unwrap_err().kind(),
            if case == 2 {
                io::ErrorKind::Unsupported
            } else {
                io::ErrorKind::PermissionDenied
            }
        );
    }
}

#[tokio::test(start_paused = true)]
async fn stop_client_partial_receipt_times_out_without_retry() {
    let (mut server, client) = tokio::io::duplex(128 * 1024);
    let binding = AuthBinding::direct("https://vpn.example.test").unwrap();
    let server_binding = binding.clone();
    let peer = async move {
        write_frame(
            &mut server,
            &Hello {
                version: VERSION,
                instance: [1; 16],
                challenge: [2; 16],
                binding: server_binding,
                phase: ServicePhase::Active,
                supports_stop: true,
                managed: None,
            },
        )
        .await
        .unwrap();
        let _: Submit = read_frame(&mut server).await.unwrap();
        server.write_all(&[0]).await.unwrap();
        assert_eq!(server.read(&mut [0; 1]).await.unwrap(), 0);
    };
    let connection = control_local::LocalConnection {
        stream: Box::new(client),
        instance_id: [1; 16],
    };
    let work = stop_with_connection(async { Ok(connection) }, &binding, Some([1; 16]));
    let ((), result) = tokio::join!(peer, work);
    assert_eq!(
        result.unwrap_err().to_string(),
        "local stop completion was not observed"
    );
}

#[tokio::test(start_paused = true)]
async fn stop_client_partial_submission_deadline_reports_unknown() {
    let (mut server, client) = tokio::io::duplex(1);
    let binding = AuthBinding::direct("https://vpn.example.test").unwrap();
    let server_binding = binding.clone();
    let peer = async move {
        write_frame(
            &mut server,
            &Hello {
                version: VERSION,
                instance: [1; 16],
                challenge: [2; 16],
                binding: server_binding,
                phase: ServicePhase::Active,
                supports_stop: true,
                managed: None,
            },
        )
        .await
        .unwrap();
        // Consume one request byte, then hold the connection without reading.
        // The client cannot know whether a peer has accepted a partial write.
        assert_eq!(server.read_u8().await.unwrap(), 0);
        tokio::time::sleep(Duration::from_secs(4)).await;
    };
    let connection = control_local::LocalConnection {
        stream: Box::new(client),
        instance_id: [1; 16],
    };
    let ((), result) = tokio::join!(
        peer,
        stop_with_connection(async { Ok(connection) }, &binding, None)
    );
    let error = result.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(error.to_string(), "local stop completion was not observed");
}
