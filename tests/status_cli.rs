//! Local diagnostic tests only: synthetic JSON on loopback, no gateway/config.
use gp_proxy::status::{Phase, Reason, Snapshot, MAX_RESPONSE};
use std::{net::SocketAddr, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
    time::timeout,
};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gp-proxy"));
    // If status accidentally reads either file, every success test fails.
    let missing = std::env::temp_dir().join(format!("gp-status-absent-{}", std::process::id()));
    command
        .env_clear()
        .args([
            "--config",
            missing.to_str().unwrap(),
            "--env-file",
            missing.to_str().unwrap(),
            "status",
        ])
        .stdin(Stdio::null())
        .kill_on_drop(true);
    // Keep OS socket-provider setup without inheriting application settings.
    #[cfg(windows)]
    command.env(
        "SystemRoot",
        std::env::var_os("SystemRoot").expect("Windows fixture requires SystemRoot"),
    );
    command
}

async fn server(body: Vec<u8>, stall: bool) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 512);
            header.push(client.read_u8().await.unwrap());
        }
        assert!(
            header.starts_with(format!("GET /status HTTP/1.1\r\nHost: {address}\r\n").as_bytes())
        );
        client.write_all(&body).await.unwrap();
        if stall {
            std::future::pending::<()>().await;
        }
    });
    (address, task)
}

fn response(snapshot: &Snapshot) -> Vec<u8> {
    let body = serde_json::to_string(snapshot).unwrap();
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes()
}

#[tokio::test]
async fn status_cli_requires_no_config_or_credentials_and_has_stable_exit_codes() {
    for (phase, reason, available, exit) in [
        (Phase::Connected, Reason::None, true, 0),
        (Phase::RetryWait, Reason::TransportUnavailable, false, 3),
        (Phase::Unknown, Reason::None, false, 3),
        (Phase::Stopped, Reason::SessionExpired, false, 3),
        (Phase::Stopped, Reason::AuthenticationRequired, false, 3),
    ] {
        let snapshot = Snapshot {
            phase,
            reason,
            available,
            retry_count: 4,
            dropped_log_records: 7,
            log_truncations: 3,
            log_write_errors: 1,
            ..Snapshot::default()
        };
        let (address, peer) = server(response(&snapshot), false).await;
        let output = timeout(
            Duration::from_secs(5),
            command().args(["--address", &address.to_string()]).output(),
        )
        .await
        .unwrap()
        .unwrap();
        peer.await.unwrap();
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert_eq!(
            serde_json::from_slice::<Snapshot>(&output.stdout).unwrap(),
            snapshot
        );
    }
    for address in [
        "192.0.2.1:8080",
        "0.0.0.0:8080",
        "[::]:8080",
        "localhost:8080",
        "127.0.0.1:0",
    ] {
        let output = command()
            .args(["--address", address])
            .output()
            .await
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[tokio::test]
async fn status_cli_bounds_responses_and_total_time_without_echoing_server_data() {
    for (body, stall, error) in [
        (vec![b'x'; MAX_RESPONSE + 1], true, "InvalidData"),
        (b"HTTP/1.1 302 Redirect\r\nLocation: https://private.invalid/secret\r\nContent-Length: 0\r\n\r\n".to_vec(), false, "InvalidData"),
        (response(&Snapshot::default()), true, "TimedOut"),
    ] {
        let (address, peer) = server(body, stall).await;
        let output = timeout(Duration::from_secs(6), command().args(["--address", &address.to_string()]).output()).await.unwrap().unwrap();
        peer.abort();
        let _ = peer.await;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error_text = String::from_utf8(output.stderr).unwrap();
        assert!(error_text.contains(error), "{error_text}");
        assert!(!error_text.contains("private.invalid"));
        assert!(!error_text.contains("secret"));
    }
}

#[tokio::test]
async fn status_help_names_http_port_and_exit_codes() {
    let output = command().arg("--help").output().await.unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("127.0.0.1:8080"));
    assert!(help.contains("HTTP proxy port"));
    assert!(help.contains("3 service reached but unavailable"));
}
