//! Synthetic TLS checks of expiry followed by authenticated logout cleanup.
//! No tunnel is accepted: any attempt to create one fails this fixture.
use super::*;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const COOKIE: &str = "synthetic-probe-expiry-cookie";

async fn gateway(request_count: usize) -> (GatewayClient, JoinHandle<Vec<String>>) {
    assert!((1..=3).contains(&request_count));
    let certificates =
        CertificateDer::pem_slice_iter(include_bytes!("../../src/gp/testdata/localhost-cert.pem"))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(include_bytes!("../../src/gp/testdata/localhost-key.pem"))
            .unwrap();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .unwrap();
    let client_tls = crate::tls::client_config(Some(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/gp/testdata/localhost-cert.pem"
    ))))
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = GatewayClient::new(
        url::Url::parse(&format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        ))
        .unwrap(),
        client_tls,
        crate::gp::ResumptionPolicy::Memory {
            tls12: rustls::client::Tls12Resumption::SessionIdOrTickets,
        },
    )
    .unwrap();
    let task = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let mut workers = JoinSet::new();
        // Fixed admission: at most three TLS workers and 8 KiB per request.
        for _ in 0..request_count {
            let (tcp, _) = timeout(Duration::from_secs(4), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let acceptor = acceptor.clone();
            workers.spawn(async move {
                timeout(Duration::from_secs(4), async {
                    let tls = acceptor.accept(tcp).await.unwrap();
                    handle(tls).await
                })
                .await
                .unwrap()
            });
        }
        drop(listener);
        let mut requests = Vec::with_capacity(request_count);
        while let Some(result) = workers.join_next().await {
            requests.push(result.unwrap());
        }
        requests.sort();
        requests
    });
    (client, task)
}

async fn handle(mut tls: tokio_rustls::server::TlsStream<TcpStream>) -> String {
    let mut header = Vec::with_capacity(1024);
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 8192, "synthetic control header too large");
        header.push(tls.read_u8().await.unwrap());
    }
    let header = String::from_utf8(header).unwrap();
    let line = header.lines().next().unwrap();
    assert!(
        line.starts_with("POST "),
        "probe attempted tunnel or other request"
    );
    let path = line.split_whitespace().nth(1).unwrap().to_string();
    let length: usize = header
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(length < 8192);
    let mut body = vec![0; length];
    tls.read_exact(&mut body).await.unwrap();
    let fields: std::collections::HashMap<_, _> = url::form_urlencoded::parse(&body).collect();
    assert_eq!(fields.get("authcookie").map(|v| v.as_ref()), Some(COOKIE));
    assert!(!fields.contains_key("passwd") && !fields.contains_key("password"));
    let delayed = path == "/ssl-vpn/hipreportcheck.esp";
    let response = match path.as_str() {
        "/ssl-vpn/getconfig.esp" => "<response status='success'><need-tunnel>yes</need-tunnel><ip-address>10.77.0.2</ip-address><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><dns><member>10.77.0.53</member></dns><lifetime>1</lifetime></response>",
        "/ssl-vpn/hipreportcheck.esp" => {
            // Force the login lease to expire while a real HTTPS control
            // response is pending. Logout must use a fresh cleanup budget.
            tokio::time::sleep(Duration::from_secs(2)).await;
            "<response status='success'><hip-report-needed>no</hip-report-needed></response>"
        }
        "/ssl-vpn/logout.esp" => "<response status='success'/>",
        _ => panic!("unexpected endpoint; expired authority must not create a tunnel"),
    };
    let sent = tls
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            )
            .as_bytes(),
        )
        .await;
    // The expired HIP connection is allowed to have already been closed.
    if !delayed {
        sent.unwrap();
        tls.flush().await.unwrap();
    }
    path
}

fn session() -> Session {
    Session::new(
        "synthetic-user".into(),
        COOKIE.into(),
        String::new(),
        String::new(),
        "test-computer".into(),
        None,
    )
    .unwrap()
}

#[tokio::test]
async fn hip_crossing_login_expiry_logs_out_without_tunnel_or_dns() {
    timeout(Duration::from_secs(8), async {
        let (client, gateway) = gateway(3).await;
        let budget = Deadline::after(Sample::now(), CHECK_TIMEOUT).unwrap();
        let result = check_authenticated(
            &client,
            &session(),
            Some("synthetic.internal"),
            CancellationToken::new(),
            Lease::new(),
            budget,
        )
        .await;
        assert!(matches!(result, Err(GpError::Authentication)));
        assert_eq!(
            gateway.await.unwrap(),
            [
                "/ssl-vpn/getconfig.esp",
                "/ssl-vpn/hipreportcheck.esp",
                "/ssl-vpn/logout.esp",
            ]
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn exhausted_probe_budget_only_logs_out_retained_session() {
    timeout(Duration::from_secs(8), async {
        let (client, gateway) = gateway(1).await;
        let budget = Deadline::after(Sample::now(), Duration::ZERO).unwrap();
        let result = check_authenticated(
            &client,
            &session(),
            Some("synthetic.internal"),
            CancellationToken::new(),
            Lease::new(),
            budget,
        )
        .await;
        assert!(matches!(result, Err(GpError::Timeout)));
        assert_eq!(gateway.await.unwrap(), ["/ssl-vpn/logout.esp"]);
    })
    .await
    .unwrap();
}
