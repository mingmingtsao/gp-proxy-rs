use super::*;

fn gateway() -> Url {
    Url::parse("https://vpn.example.test:7777").unwrap()
}

fn policy(entries: &str, cookies: &str) -> String {
    format!("<policy><gateways><external><list>{entries}</list></external></gateways>{cookies}</policy>")
}

const ENTRY: &str = "<entry name=\"vpn.example.test:7777\"><description>Corporate gateway</description><priority-rule><entry name=\"Any\"><priority>1</priority></entry></priority-rule></entry>";
const COOKIE: &str = "<portal-userauthcookie>  user&amp;+%雪  </portal-userauthcookie>";

fn rejected_prelogins() -> Vec<String> {
    let base = "<prelogin-response><status>Success</status>{}</prelogin-response>";
    [
        "<saml-request>opaque</saml-request>",
        "<saml-auth-method>REDIRECT</saml-auth-method>",
        "<s:saml-request xmlns:s=\"urn:auth\">opaque</s:saml-request>",
        "<authentication-method>future-flow</authentication-method>",
        "<username-label attribute=\"unexpected\">Username</username-label>",
        "<password-label><nested>Password</nested></password-label>",
        "<status>Success</status>",
        "<ccusername>certificate-user</ccusername>",
        "<autosubmit>true</autosubmit>",
    ]
    .into_iter()
    .map(|field| base.replace("{}", field))
    .collect()
}

#[test]
fn prelogin_rejects_ambiguous_authentication_mode_namespace_and_non_scalar_fields() {
    for source in rejected_prelogins() {
        assert!(parse_prelogin(&source).is_err());
    }
    assert!(parse_prelogin("<prelogin-response><status>Success</status><ccusername/><autosubmit>false</autosubmit><msg/><newmsg/><authentication-message>Password required</authentication-message><username-label>Username</username-label><password-label>Password</password-label><panos-version>1</panos-version><region>Any</region></prelogin-response>").is_ok());
}

#[test]
fn policy_requires_one_fixed_gateway_preserves_cookie_and_optional_prelogon() {
    let parsed = parse_policy(&policy(ENTRY, COOKIE), &gateway()).unwrap();
    assert_eq!(&*parsed.user, "  user&+%雪  ");
    assert!(parsed.prelogon.is_none());
    for prelogon in ["", "empty", " "] {
        let source = policy(
            ENTRY,
            &format!(
                "{COOKIE}<portal-prelogonuserauthcookie>{prelogon}</portal-prelogonuserauthcookie>"
            ),
        );
        assert!(parse_policy(&source, &gateway())
            .unwrap()
            .prelogon
            .is_none());
    }
    let source = policy(
        ENTRY,
        &format!(
            "{COOKIE}<portal-prelogonuserauthcookie>exact+%&amp;</portal-prelogonuserauthcookie>"
        ),
    );
    assert_eq!(
        parse_policy(&source, &gateway())
            .unwrap()
            .prelogon
            .as_deref()
            .map(String::as_str),
        Some("exact+%&")
    );
    let benign = policy(ENTRY, COOKIE).replace("</policy>", "<version>synthetic</version><hip-collection><hip-report-interval>600</hip-report-interval></hip-collection><root-ca><entry name=\"must-not-install\"><cert>untrusted-material</cert></entry></root-ca><internal-host-detection><host>must-not-query.invalid</host></internal-host-detection></policy>");
    assert!(parse_policy(&benign, &gateway()).is_ok());
}

#[test]
fn policy_rejects_missing_sentinel_and_oversized_user_cookie() {
    for cookie in [
        "".to_owned(),
        "empty".into(),
        "(null)".into(),
        "  ".into(),
        "x".repeat(8193),
        "first\nsecond".into(),
    ] {
        assert!(parse_policy(
            &policy(
                ENTRY,
                &format!("<portal-userauthcookie>{cookie}</portal-userauthcookie>")
            ),
            &gateway()
        )
        .is_err());
    }
    assert!(parse_policy(&policy(ENTRY, ""), &gateway()).is_err());
    assert!(parse_policy(
        &policy(
            ENTRY,
            "<portal-prelogonuserauthcookie>not-user-cookie</portal-prelogonuserauthcookie>"
        ),
        &gateway()
    )
    .is_err());
    assert!(parse_policy(&policy(ENTRY, &format!("{COOKIE}{COOKIE}")), &gateway()).is_err());
}

#[test]
fn policy_rejects_ambiguous_unknown_and_malformed_authorization_structure() {
    let source = policy(ENTRY, COOKIE);
    for invalid in [
        source.replace("<policy>", "<policy xmlns=\"urn:other\">"),
        source.replace("<policy>", "<policy unknown=\"yes\">"),
        source.replace("</policy>", "<unknown/></policy>"),
        source.replace("</policy>", "<gateways/></policy>"),
        source.replace("</external>", "<list/></external>"),
        source.replace("</gateways>", "<external/></gateways>"),
        source.replace("</entry></list>", "<unknown/></entry></list>"),
        source.replace("<description>", "<description attribute=\"no\">"),
        source.replace(
            "</description>",
            "</description><description>duplicate</description>",
        ),
        source.replace(
            "<priority>1</priority>",
            "<priority>1</priority><priority>2</priority>",
        ),
        source.replace("<priority>1</priority>", "<priority>invalid</priority>"),
        source.replace("user&amp;", "user<!-- hidden -->&amp;"),
        source.replace("user&amp;", "user<nested/>&amp;"),
        source.replace(
            "<policy>",
            "<!DOCTYPE policy [<!ENTITY injected 'secret'>]><policy>",
        ),
        source.replace("</policy>", "<has-config>no</has-config></policy>"),
        source.replace(
            "</policy>",
            "<has-config>yes</has-config><has-config>yes</has-config></policy>",
        ),
        source.replace("</policy>", "<has-config>maybe</has-config></policy>"),
    ] {
        assert!(
            parse_policy(&invalid, &gateway()).is_err(),
            "malformed policy accepted"
        );
    }
}

#[test]
fn policy_gateway_authority_is_exact_bounded_and_canonical() {
    for authority in [
        "evil.example.test:7777",
        "vpn.example.test",
        "vpn.example.test:443",
        "vpn.example.test:7778",
        "vpn.example.test:0",
        "vpn.example.test:07777",
        "https://vpn.example.test:7777",
        "user@vpn.example.test:7777",
        "vpn.example.test:7777/",
        "vpn.example.test:7777?query",
        "vpn%2eexample.test:7777",
        "vpn.example.test:7777#fragment",
        "vpn.example.test:7777\\other",
    ] {
        assert!(parse_policy(
            &policy(&format!("<entry name=\"{authority}\"/>"), COOKIE),
            &gateway()
        )
        .is_err());
    }
    assert!(parse_policy(
        &policy("<entry name=\"VPN.EXAMPLE.TEST:7777\"/>", COOKIE),
        &gateway()
    )
    .is_ok());
    let default = Url::parse("https://vpn.example.test").unwrap();
    assert!(parse_policy(
        &policy("<entry name=\"vpn.example.test:443\"/>", COOKIE),
        &default
    )
    .is_ok());
    assert!(parse_policy(&policy(&format!("{ENTRY}{ENTRY}"), COOKIE), &gateway()).is_err());
    assert!(parse_policy(&policy("", COOKIE), &gateway()).is_err());
    let many = (0..129)
        .map(|index| format!("<entry name=\"vpn{index}.example.test\"/>"))
        .collect::<String>();
    assert!(parse_policy(&policy(&many, COOKIE), &gateway()).is_err());
    let identity = Url::parse("https://127.0.0.1").unwrap();
    for alternative in ["127.1", "2130706433", "0x7f000001"] {
        assert!(parse_policy(
            &policy(&format!("<entry name=\"{alternative}\"/>"), COOKIE),
            &identity
        )
        .is_err());
    }
}

#[test]
fn policy_bounds_ignored_metadata_and_priority_lists() {
    let oversized = policy(ENTRY, COOKIE).replace(
        "</policy>",
        &format!(
            "<root-ca>{}</root-ca></policy>",
            "x".repeat(MAX_POLICY_BYTES)
        ),
    );
    assert!(parse_policy(&oversized, &gateway()).is_err());
    let many_nodes = policy(ENTRY, COOKIE).replace(
        "</policy>",
        &format!(
            "<root-ca>{}</root-ca></policy>",
            "<cert/>".repeat(MAX_POLICY_NODES)
        ),
    );
    assert!(parse_policy(&many_nodes, &gateway()).is_err());
    let priorities = (0..65)
        .map(|index| format!("<entry name=\"region{index}\"><priority>1</priority></entry>"))
        .collect::<String>();
    assert!(parse_policy(&policy(&format!("<entry name=\"vpn.example.test:7777\"><priority-rule>{priorities}</priority-rule></entry>"), COOKIE), &gateway()).is_err());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod wire {
    use super::*;
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    use std::{collections::HashMap, io, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
        time::timeout,
    };

    const PRELOGIN: &str = "<prelogin-response><status>Success</status></prelogin-response>";
    const SESSION: &str = "<jnlp><application-desc><argument/><argument>synthetic-gateway-cookie</argument><argument/><argument>gateway</argument><argument>Original\\User</argument><argument>auth</argument><argument>vsys1</argument><argument>domain</argument><argument/><argument/><argument/><argument/><argument>tunnel</argument><argument>-1</argument><argument>4100</argument></application-desc></jnlp>";
    const LIMIT: Duration = Duration::from_secs(5);

    enum Reply {
        Body(u16, String),
        NoHttp,
    }
    impl From<&str> for Reply {
        fn from(value: &str) -> Self {
            Self::Body(200, value.into())
        }
    }
    impl From<String> for Reply {
        fn from(value: String) -> Self {
            Self::Body(200, value)
        }
    }

    struct Request {
        path: String,
        body: String,
    }
    impl Request {
        fn fields(&self) -> HashMap<String, String> {
            let pairs: Vec<_> = url::form_urlencoded::parse(self.body.as_bytes()).collect();
            let fields: HashMap<_, _> = pairs
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect();
            assert_eq!(pairs.len(), fields.len(), "duplicate credential form field");
            fields
        }
    }

    struct Peer {
        origin: Url,
        tls: Arc<rustls::ClientConfig>,
        worker: Option<JoinHandle<Vec<Request>>>,
    }
    impl Drop for Peer {
        fn drop(&mut self) {
            if let Some(worker) = &self.worker {
                worker.abort();
            }
        }
    }

    impl Peer {
        async fn new(replies: Vec<Reply>) -> Self {
            assert!(replies.len() <= 8);
            let certificates =
                CertificateDer::pem_slice_iter(include_bytes!("testdata/localhost-cert.pem"))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
            let key = PrivateKeyDer::from_pem_slice(include_bytes!("testdata/localhost-key.pem"))
                .unwrap();
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let mut roots = rustls::RootCertStore::empty();
            roots.add(certificates[0].clone()).unwrap();
            let client = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certificates, key)
                .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = Url::parse(&format!(
                "https://localhost:{}",
                listener.local_addr().unwrap().port()
            ))
            .unwrap();
            let worker = tokio::spawn(async move {
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
                let mut requests = Vec::with_capacity(replies.len());
                for reply in replies {
                    let (tcp, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
                    let mut stream = timeout(LIMIT, acceptor.accept(tcp)).await.unwrap().unwrap();
                    if matches!(reply, Reply::NoHttp) {
                        match timeout(LIMIT, stream.read(&mut [0; 1])).await.unwrap() {
                            Ok(0) => (),
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                                ) => {}
                            other => panic!(
                                "credential byte sent after rejected before-write gate: {other:?}"
                            ),
                        }
                        continue;
                    }
                    let read = async {
                        let mut header = Vec::new();
                        while !header.ends_with(b"\r\n\r\n") {
                            assert!(header.len() < 16384);
                            header.push(stream.read_u8().await.unwrap());
                        }
                        let header = String::from_utf8(header).unwrap();
                        let mut lengths = header
                            .lines()
                            .filter_map(|line| line.strip_prefix("Content-Length: "));
                        let length: usize = lengths.next().unwrap().parse().unwrap();
                        assert!(lengths.next().is_none() && length <= 128 * 1024);
                        assert!(!header
                            .lines()
                            .any(|line| line.to_ascii_lowercase().starts_with("cookie:")));
                        let mut body = vec![0; length];
                        stream.read_exact(&mut body).await.unwrap();
                        Request {
                            path: header.lines().next().unwrap().into(),
                            body: String::from_utf8(body).unwrap(),
                        }
                    };
                    requests.push(timeout(LIMIT, read).await.unwrap());
                    let Reply::Body(status, body) = reply else {
                        unreachable!()
                    };
                    timeout(LIMIT, async {
                        stream.write_all(format!("HTTP/1.1 {status} Synthetic\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
                        stream.shutdown().await.unwrap();
                    }).await.unwrap();
                }
                assert!(
                    timeout(Duration::from_millis(100), listener.accept())
                        .await
                        .is_err(),
                    "unexpected automatic prelogin/retry connection"
                );
                requests
            });
            Self {
                origin,
                tls: Arc::new(client),
                worker: Some(worker),
            }
        }

        fn portal(&self, fixed: &Url) -> PortalClient {
            PortalClient::new(
                self.origin.clone(),
                fixed.clone(),
                self.tls.clone(),
                ResumptionPolicy::Disabled,
            )
            .unwrap()
        }
        fn gateway(&self) -> GatewayClient {
            GatewayClient::new(
                self.origin.clone(),
                self.tls.clone(),
                ResumptionPolicy::Disabled,
            )
            .unwrap()
        }
        async fn finish(mut self) -> Vec<Request> {
            let requests = timeout(Duration::from_secs(10), self.worker.as_mut().unwrap())
                .await
                .unwrap()
                .unwrap();
            self.worker.take();
            requests
        }
    }

    fn response(gateway: &Url) -> String {
        policy(
            &format!(
                "<entry name=\"{}\"/>",
                &gateway[url::Position::BeforeHost..url::Position::AfterPort]
            ),
            COOKIE,
        )
    }
    fn challenge(state: &str) -> String {
        format!("<challenge><user>ignored-replacement</user><inputstr>{state}</inputstr><respmsg>Fresh answer</respmsg></challenge>")
    }
    fn pending(progress: PortalProgress) -> PortalChallenge {
        match progress {
            PortalProgress::Challenge(value) => value,
            _ => panic!("expected portal challenge"),
        }
    }
    fn cookies(progress: PortalProgress) -> PortalCookies {
        match progress {
            PortalProgress::Cookies(value) => value,
            _ => panic!("expected portal cookies"),
        }
    }
    fn local_cookies(portal: &Url, gateway: &Url) -> PortalCookies {
        PortalCookies {
            portal: portal.clone(),
            gateway: gateway.clone(),
            user: "Original\\User".into(),
            computer: "computer".into(),
            user_cookie: Zeroizing::new("  user&+%雪  ".into()),
            prelogon_cookie: None,
        }
    }

    #[tokio::test]
    async fn unsupported_or_malformed_prelogin_sends_no_credential_post() {
        for response in rejected_prelogins() {
            let peer = Peer::new(vec![response.into()]).await;
            let client = peer.portal(&gateway());
            assert!(client.prelogin().await.is_err());
            let requests = peer.finish().await;
            assert_eq!(requests.len(), 1);
            assert!(requests[0]
                .path
                .starts_with("POST /global-protect/prelogin.esp?"));
            assert!(requests[0].body.is_empty());
        }
    }

    #[tokio::test]
    async fn portal_challenge_and_cookie_handoff_use_exact_distinct_forms_once() {
        let gateway = Peer::new(vec![SESSION.into()]).await;
        let portal = Peer::new(vec![
            PRELOGIN.into(),
            challenge("  state&amp;+%雪  ").into(),
            response(&gateway.origin).into(),
        ])
        .await;
        let client = portal.portal(&gateway.origin);
        client.prelogin().await.unwrap();
        let continuation = pending(
            client
                .begin_login("Original\\User", "ONLY_PORTAL_PASSWORD", "computer")
                .await
                .unwrap(),
        );
        assert_eq!(continuation.round(), 1);
        assert_eq!(continuation.prompt(), "Fresh answer");
        let credentials = cookies(
            client
                .clone()
                .answer_challenge(continuation, Zeroizing::new("FRESH+&%回答".into()))
                .await
                .unwrap(),
        );
        let session = gateway
            .gateway()
            .login_with_portal_cookies(credentials, client.origin())
            .await
            .unwrap();
        assert_eq!(session.user, "Original\\User");
        assert_eq!(session.computer, "computer");
        let requests = portal.finish().await;
        assert_eq!(requests.len(), 3);
        assert!(requests[0]
            .path
            .starts_with("POST /global-protect/prelogin.esp?"));
        assert!(requests[0].body.is_empty());
        for request in &requests[1..] {
            assert_eq!(request.path, "POST /global-protect/getconfig.esp HTTP/1.1");
        }
        assert_eq!(requests[1].fields()["passwd"], "ONLY_PORTAL_PASSWORD");
        assert_eq!(requests[1].fields().len(), 13);
        let answered = requests[2].fields();
        assert_eq!(answered.len(), 14);
        assert_eq!(answered["user"], "Original\\User");
        assert_eq!(answered["passwd"], "FRESH+&%回答");
        assert_eq!(answered["inputStr"], "  state&+%雪  ");
        assert!(requests[2]
            .body
            .contains("inputStr=++state%26%2B%25%E9%9B%AA++"));
        assert!(!requests[2].body.contains("ONLY_PORTAL_PASSWORD"));
        let requests = gateway.finish().await;
        assert_eq!(requests.len(), 1);
        let fields = requests[0].fields();
        assert_eq!(requests[0].path, "POST /ssl-vpn/login.esp HTTP/1.1");
        assert_eq!(fields.len(), 17);
        assert_eq!(fields["user"], "Original\\User");
        assert_eq!(fields["passwd"], cookie_password().unwrap());
        assert_eq!(fields["portal-userauthcookie"], "  user&+%雪  ");
        assert_eq!(fields["portal-prelogonuserauthcookie"], "empty");
        assert_eq!(fields["prelogin-cookie"], "");
        assert_eq!(fields["token"], "");
        assert!(!fields.contains_key("inputStr"));
        assert!(
            !requests[0].body.contains("ONLY_PORTAL_PASSWORD")
                && !requests[0].body.contains("FRESH")
        );
    }

    #[tokio::test]
    async fn portal_continuations_reject_new_client_origin_gateway_and_invalid_answers_without_post(
    ) {
        for mismatch in 0..6 {
            let peer = Peer::new(vec![challenge("state").into()]).await;
            let client = peer.portal(&gateway());
            let continuation = pending(
                client
                    .begin_login("user", "password", "computer")
                    .await
                    .unwrap(),
            );
            let target = match mismatch {
                0 => client.for_authentication(),
                1 => peer.portal(&gateway()),
                2 => PortalClient::new(
                    Url::parse("https://other.invalid").unwrap(),
                    gateway(),
                    peer.tls.clone(),
                    ResumptionPolicy::Disabled,
                )
                .unwrap(),
                3 => peer.portal(&Url::parse("https://other.invalid").unwrap()),
                _ => client.clone(),
            };
            let answer = match mismatch {
                4 => "control\nanswer".into(),
                5 => "x".repeat(8193),
                _ => "valid".into(),
            };
            assert!(target
                .answer_challenge(continuation, Zeroizing::new(answer))
                .await
                .is_err());
            assert_eq!(peer.finish().await.len(), 1);
        }
    }

    #[tokio::test]
    async fn cookie_handoff_rejects_both_origin_mismatches_before_any_connection() {
        for wrong_portal in [false, true] {
            let peer = Peer::new(Vec::new()).await;
            let portal = Url::parse("https://portal.example.test").unwrap();
            let mut credential = local_cookies(&portal, &peer.origin);
            if wrong_portal {
                credential.portal = Url::parse("https://other.invalid").unwrap();
            } else {
                credential.gateway = Url::parse("https://other.invalid").unwrap();
            }
            assert!(peer
                .gateway()
                .login_with_portal_cookies(credential, &portal)
                .await
                .is_err());
            assert!(peer.finish().await.is_empty());
        }
    }

    #[tokio::test]
    async fn gateway_cookie_rejection_or_new_challenge_never_retries_or_uses_password() {
        for reply in [
            Reply::Body(512, "rejected".into()),
            challenge("independent-gateway-state").into(),
        ] {
            let peer = Peer::new(vec![reply]).await;
            let portal = Url::parse("https://portal.example.test").unwrap();
            let result = peer
                .gateway()
                .login_with_portal_cookies(local_cookies(&portal, &peer.origin), &portal)
                .await;
            assert!(matches!(
                result,
                Err(GpError::Authentication | GpError::UnsupportedAuthentication)
            ));
            let requests = peer.finish().await;
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].fields()["passwd"], cookie_password().unwrap());
        }
    }

    #[tokio::test]
    async fn each_portal_credential_stage_and_cookie_handoff_apply_gate_after_tls_before_http() {
        let initial = Peer::new(vec![Reply::NoHttp]).await;
        assert!(matches!(
            initial
                .portal(&gateway())
                .begin_login_guarded("user", "password", "computer", || Err(GpError::Cancelled))
                .await,
            Err(GpError::Cancelled)
        ));
        assert!(initial.finish().await.is_empty());
        let answer = Peer::new(vec![challenge("state").into(), Reply::NoHttp]).await;
        let client = answer.portal(&gateway());
        let continuation = pending(
            client
                .begin_login("user", "password", "computer")
                .await
                .unwrap(),
        );
        assert!(matches!(
            client
                .answer_challenge_guarded(continuation, Zeroizing::new("answer".into()), || Err(
                    GpError::Timeout
                ))
                .await,
            Err(GpError::Timeout)
        ));
        assert_eq!(answer.finish().await.len(), 1);
        let handoff = Peer::new(vec![Reply::NoHttp]).await;
        let portal = Url::parse("https://portal.example.test").unwrap();
        assert!(matches!(
            handoff
                .gateway()
                .login_with_portal_cookies_guarded(
                    local_cookies(&portal, &handoff.origin),
                    &portal,
                    || Err(GpError::Cancelled)
                )
                .await,
            Err(GpError::Cancelled)
        ));
        assert!(handoff.finish().await.is_empty());
    }

    #[tokio::test]
    async fn portal_round_limit_accepts_policy_after_four_answers_but_rejects_fifth_challenge() {
        for finish in [true, false] {
            let mut replies: Vec<Reply> = (0..4).map(|_| challenge("state").into()).collect();
            replies.push(if finish {
                response(&gateway()).into()
            } else {
                challenge("state").into()
            });
            let peer = Peer::new(replies).await;
            let client = peer.portal(&gateway());
            let mut progress = client
                .begin_login("user", "password", "computer")
                .await
                .unwrap();
            for round in 1..=4 {
                let continuation = pending(progress);
                assert_eq!(continuation.round(), round);
                let next = client
                    .answer_challenge(continuation, Zeroizing::new("fresh-answer".into()))
                    .await;
                if !finish && round == 4 {
                    assert!(matches!(next, Err(GpError::Protocol(_))));
                    break;
                }
                progress = next.unwrap();
                if round == 4 {
                    assert!(matches!(progress, PortalProgress::Cookies(_)));
                    break;
                }
            }
            assert_eq!(peer.finish().await.len(), 5);
        }
    }
}
