//! Independent synthetic TLS wire assertions; no real credentials or gateway.
use super::*;
use std::{collections::HashMap, io};
use tokio::{net::TcpListener, task::JoinHandle};
use url::form_urlencoded;

const SESSION: &str = "<jnlp><application-desc><argument/><argument>synthetic-cookie</argument><argument/><argument>gateway</argument><argument>original-user</argument><argument>auth</argument><argument>vsys1</argument><argument>domain</argument><argument/><argument/><argument/><argument/><argument>tunnel</argument><argument>-1</argument><argument>4100</argument></application-desc></jnlp>";
const PRELOGIN: &str = "<prelogin-response><status>Success</status></prelogin-response>";

struct Request {
    first: String,
    body: String,
}

impl Request {
    fn form(&self) -> HashMap<String, String> {
        let pairs = form_urlencoded::parse(self.body.as_bytes()).collect::<Vec<_>>();
        let fields = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>();
        assert_eq!(pairs.len(), fields.len(), "duplicate request fields");
        fields
    }
}

struct Gateway {
    client: GatewayClient,
    worker: Option<JoinHandle<Vec<Request>>>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}

impl Gateway {
    async fn new(responses: Vec<String>) -> Self {
        assert!(responses.len() <= 8);
        let (client_tls, server_tls) = super::tests::mock_tls_configs(&rustls::version::TLS13);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = Url::parse(&format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let worker = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_tls);
            let mut requests = Vec::with_capacity(responses.len());
            for response in responses {
                let (tcp, _) = timeout(Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
                let mut tls = timeout(Duration::from_secs(5), acceptor.accept(tcp))
                    .await
                    .unwrap()
                    .unwrap();
                let first = bounded_line(&mut tls, MAX_HEADERS).await.unwrap();
                let mut headers = first.len();
                let mut length = None;
                loop {
                    let line = bounded_line(&mut tls, MAX_HEADERS).await.unwrap();
                    headers += line.len();
                    assert!(headers <= MAX_HEADERS);
                    if &*line == b"\r\n" {
                        break;
                    }
                    if let Some(value) = std::str::from_utf8(&line)
                        .unwrap()
                        .strip_prefix("Content-Length: ")
                    {
                        assert!(length.is_none());
                        length = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
                let length = length.unwrap();
                assert!(length <= 128 * 1024);
                let mut body = vec![0; length];
                tls.read_exact(&mut body).await.unwrap();
                requests.push(Request {
                    first: std::str::from_utf8(&first).unwrap().to_owned(),
                    body: String::from_utf8(body).unwrap(),
                });
                tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).as_bytes()).await.unwrap();
                tls.shutdown().await.unwrap();
            }
            assert!(
                timeout(Duration::from_millis(150), listener.accept())
                    .await
                    .is_err(),
                "unexpected extra gateway connection"
            );
            requests
        });
        Self {
            client: GatewayClient::new(
                origin,
                client_tls,
                ResumptionPolicy::Memory {
                    tls12: rustls::client::Tls12Resumption::SessionIdOrTickets,
                },
            )
            .unwrap(),
            worker: Some(worker),
        }
    }

    async fn finish(mut self) -> Vec<Request> {
        // Keep the handle owned by the guard across timeout, so a failed join
        // aborts the bounded worker rather than leaving a detached listener.
        let result = timeout(Duration::from_secs(6), self.worker.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap();
        self.worker.take();
        result
    }
}

fn xml_challenge(state: &str) -> String {
    format!("<challenge><user>must-not-replace-original-user</user><inputstr>{state}</inputstr><respmsg>Enter code</respmsg></challenge>")
}

fn require_challenge(progress: LoginProgress, round: u8) -> LoginChallenge {
    let LoginProgress::Challenge(challenge) = progress else {
        panic!("expected challenge")
    };
    assert_eq!(challenge.round(), round);
    challenge
}

#[tokio::test]
async fn challenge_tls_three_envelopes_send_each_fresh_secret_once_with_exact_state() {
    timeout(Duration::from_secs(10), async {
        let gateway = Gateway::new(vec![
            PRELOGIN.into(),
            xml_challenge("  x&amp;+%/雪  "),
            "var respStatus = \"Challenge\"; var respMsg = \"Second\\ncode\"; thisForm.inputStr.value = \"json+state&2\";".into(),
            "<html><head/><body>var respStatus = &quot;Challenge&quot;; var respMsg = &quot;Third code&quot;; thisForm.inputStr.value = &quot;html&amp;state+3&quot;;</body></html>".into(),
            SESSION.into(),
        ]).await;
        gateway.client.prelogin().await.unwrap();
        let first = require_challenge(gateway.client.begin_login("original-user", "ONLY_INITIAL_PASSWORD", "original-computer").await.unwrap(), 1);
        assert_eq!(first.prompt(), "Enter code");
        let second = require_challenge(gateway.client.answer_challenge(first, Zeroizing::new("回答&+% 1".into())).await.unwrap(), 2);
        assert_eq!(second.prompt(), "Second\\u{000a}code");
        let third = require_challenge(gateway.client.answer_challenge(second, Zeroizing::new("fresh-second".into())).await.unwrap(), 3);
        // Clones are the same authentication cache/capability, not a new login.
        let clone = gateway.client.clone();
        let LoginProgress::Session(session) = clone.answer_challenge(third, Zeroizing::new("fresh-third".into())).await.unwrap() else { panic!("expected session") };
        assert_eq!(session.user, "original-user");
        assert_eq!(session.computer, "original-computer");
        let requests = gateway.finish().await;
        assert_eq!(requests.len(), 5);
        assert!(requests[0].first.starts_with("POST /ssl-vpn/prelogin.esp?"));
        assert!(requests[0].body.is_empty());
        for (request, secret, state) in [
            (&requests[1], "ONLY_INITIAL_PASSWORD", None),
            (&requests[2], "回答&+% 1", Some("  x&+%/雪  ")),
            (&requests[3], "fresh-second", Some("json+state&2")),
            (&requests[4], "fresh-third", Some("html&state+3")),
        ] {
            assert_eq!(request.first, "POST /ssl-vpn/login.esp HTTP/1.1\r\n");
            let fields = request.form();
            assert_eq!(fields.len(), if state.is_some() {14} else {13});
            assert_eq!(fields["user"], "original-user");
            assert_eq!(fields["computer"], "original-computer");
            assert_eq!(fields["passwd"], secret);
            assert_eq!(fields.get("inputStr").map(String::as_str), state);
            assert!(!fields.contains_key("inputstr"));
            if state.is_some() { assert!(!request.body.contains("ONLY_INITIAL_PASSWORD")); }
        }
        assert!(requests[2].body.contains("passwd=%E5%9B%9E%E7%AD%94%26%2B%25+1"));
        assert!(requests[2].body.contains("inputStr=++x%26%2B%25%2F%E9%9B%AA++"));
    }).await.unwrap();
}

#[tokio::test]
async fn challenge_wrong_authentication_client_origin_and_bad_answers_never_post() {
    timeout(Duration::from_secs(10), async {
        let gateway = Gateway::new((0..7).map(|_| xml_challenge("state")).collect()).await;
        for case in 0..7 {
            let challenge = require_challenge(
                gateway
                    .client
                    .begin_login("original-user", "initial", "computer")
                    .await
                    .unwrap(),
                1,
            );
            let result = match case {
                0 => {
                    gateway
                        .client
                        .for_authentication()
                        .answer_challenge(challenge, Zeroizing::new("answer".into()))
                        .await
                }
                1 => {
                    GatewayClient::new(
                        gateway.client.gateway.clone(),
                        gateway.client.tls.clone(),
                        gateway.client.resumption,
                    )
                    .unwrap()
                    .answer_challenge(challenge, Zeroizing::new("answer".into()))
                    .await
                }
                2 => {
                    // Closed port is never dialled: mismatch must be diagnosed
                    // locally as Protocol, rather than connection refusal.
                    let other = GatewayClient::new(
                        Url::parse("https://localhost:1").unwrap(),
                        gateway.client.tls.clone(),
                        gateway.client.resumption,
                    )
                    .unwrap();
                    other
                        .answer_challenge(challenge, Zeroizing::new("answer".into()))
                        .await
                }
                3 => {
                    gateway
                        .client
                        .answer_challenge(challenge, Zeroizing::new(String::new()))
                        .await
                }
                4 => {
                    gateway
                        .client
                        .answer_challenge(
                            challenge,
                            Zeroizing::new("a".repeat(challenge::MAX_SECRET + 1)),
                        )
                        .await
                }
                5 => {
                    gateway
                        .client
                        .answer_challenge(challenge, Zeroizing::new("line\nanswer".into()))
                        .await
                }
                _ => {
                    gateway
                        .client
                        .answer_challenge(challenge, Zeroizing::new("null\0answer".into()))
                        .await
                }
            };
            assert!(matches!(result, Err(GpError::Protocol(_))));
        }
        let requests = gateway.finish().await;
        assert_eq!(requests.len(), 7);
        assert!(requests
            .iter()
            .all(|r| r.first.starts_with("POST /ssl-vpn/login.esp ")
                && !r.form().contains_key("inputStr")));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn challenge_four_round_limit_allows_final_answer_but_rejects_fifth_prompt() {
    timeout(Duration::from_secs(10), async {
        for succeed in [true, false] {
            let mut responses = (1..=4)
                .map(|n| xml_challenge(&format!("state-{n}")))
                .collect::<Vec<_>>();
            responses.push(if succeed {
                SESSION.into()
            } else {
                xml_challenge("fifth-state")
            });
            let gateway = Gateway::new(responses).await;
            let mut progress = gateway
                .client
                .begin_login("original-user", "initial", "computer")
                .await
                .unwrap();
            for round in 1..=4 {
                let current = require_challenge(progress, round);
                let result = gateway
                    .client
                    .answer_challenge(
                        current,
                        Zeroizing::new(if round == 4 {
                            "a".repeat(challenge::MAX_SECRET)
                        } else {
                            format!("answer-{round}")
                        }),
                    )
                    .await;
                if round == 4 && !succeed {
                    assert!(matches!(
                        result,
                        Err(GpError::Protocol(
                            "authentication challenge round limit exceeded"
                        ))
                    ));
                    break;
                }
                progress = result.unwrap();
                if round == 4 {
                    assert!(matches!(progress, LoginProgress::Session(_)));
                }
            }
            let requests = gateway.finish().await;
            assert_eq!(requests.len(), 5);
            for (round, request) in requests.iter().skip(1).enumerate() {
                assert_eq!(request.form()["inputStr"], format!("state-{}", round + 1));
            }
            assert_eq!(requests[4].form()["passwd"].len(), challenge::MAX_SECRET);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn challenge_noninteractive_convenience_and_server_error_never_auto_answer() {
    timeout(Duration::from_secs(10), async {
        let gateway = Gateway::new(vec![PRELOGIN.into(), xml_challenge("state")]).await;
        assert!(matches!(gateway.client.login("original-user", "initial", "computer").await, Err(GpError::UnsupportedAuthentication)));
        assert_eq!(gateway.finish().await.len(), 2);

        let gateway = Gateway::new(vec![xml_challenge("state"), "var respStatus = \"Error\"; var respMsg = \"Untrusted rejection\"; thisForm.inputStr.value = \"\";".into()]).await;
        let current = require_challenge(gateway.client.begin_login("original-user", "initial", "computer").await.unwrap(), 1);
        assert!(matches!(gateway.client.answer_challenge(current, Zeroizing::new("fresh-answer".into())).await, Err(GpError::Authentication)));
        assert_eq!(gateway.finish().await.len(), 2);
    }).await.unwrap();
}

#[tokio::test]
async fn credential_write_gate_runs_after_tls_and_denies_all_http_bytes() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    timeout(Duration::from_secs(10), async {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            for cancelled in [true, false] {
                let (client_tls, server_tls) = super::tests::mock_tls_configs(version);
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let client = GatewayClient::new(
                    Url::parse(&format!("https://localhost:{}", listener.local_addr().unwrap().port())).unwrap(),
                    client_tls,
                    ResumptionPolicy::Disabled,
                ).unwrap();
                let gate_calls = AtomicUsize::new(0);
                let login = client.begin_login_guarded("original-user", "must-not-be-sent", "computer", || {
                    gate_calls.fetch_add(1, Ordering::SeqCst);
                    if cancelled { Err(GpError::Cancelled) } else { Err(GpError::Timeout) }
                });
                let server = async {
                    let (tcp, _) = listener.accept().await.unwrap();
                    // A completed handshake distinguishes this gate from an
                    // earlier check that only prevents opening the connection.
                    let mut tls = tokio_rustls::TlsAcceptor::from(server_tls).accept(tcp).await.unwrap();
                    let mut first = [0u8; 1];
                    let end = timeout(Duration::from_secs(1), tls.read(&mut first)).await.unwrap();
                    assert!(matches!(end, Ok(0)) || matches!(end, Err(ref error) if matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset)));
                    assert!(timeout(Duration::from_millis(30), listener.accept()).await.is_err());
                };
                let (result, ()) = tokio::join!(login, server);
                assert_eq!(gate_calls.load(Ordering::SeqCst), 1);
                if cancelled { assert!(matches!(result, Err(GpError::Cancelled))); }
                else { assert!(matches!(result, Err(GpError::Timeout))); }
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn credential_write_gate_is_one_shot_and_allows_late_session_after_submission() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    timeout(Duration::from_secs(10), async {
        let gateway = Gateway::new(vec![xml_challenge("original-state"), SESSION.into()]).await;
        let gate_calls = AtomicUsize::new(0);
        let first = gateway
            .client
            .begin_login_guarded("original-user", "first-secret", "computer", || {
                gate_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .unwrap();
        let first = require_challenge(first, 1);
        let cancelled_after_check = AtomicBool::new(false);
        let result = gateway
            .client
            .answer_challenge_guarded(first, Zeroizing::new("fresh-answer".into()), || {
                assert!(!cancelled_after_check.load(Ordering::SeqCst));
                gate_calls.fetch_add(1, Ordering::SeqCst);
                // A check is not atomic with writing. Once it admits a write, the
                // caller must receive and clean up a late cookie, not discard it.
                cancelled_after_check.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(result, LoginProgress::Session(_)));
        assert!(cancelled_after_check.load(Ordering::SeqCst));
        assert_eq!(gate_calls.load(Ordering::SeqCst), 2);
        let requests = gateway.finish().await;
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].form()["passwd"], "first-secret");
        assert_eq!(requests[1].form()["passwd"], "fresh-answer");
        assert_eq!(requests[1].form()["inputStr"], "original-state");
    })
    .await
    .unwrap();
}
