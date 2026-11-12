//! The service, not the test, must discard each authentication's TLS cache.
use super::*;

fn set_policy(gateway: &mut Gateway, policy: crate::gp::ResumptionPolicy) {
    gateway.client = GatewayClient::new(
        Url::parse(&gateway.origin).unwrap(),
        crate::tls::client_config(Some(std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/gp/testdata/localhost-cert.pem"
        ))))
        .unwrap(),
        policy,
    )
    .unwrap();
}

#[tokio::test]
async fn explicit_authentication_uses_a_fresh_tls_cache_after_rejection_and_cleanup() {
    timeout(Duration::from_secs(15), async {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let gateway = Gateway::new_with_versions(&[version]).await;
            gateway.state.record_tls.store(true, Ordering::SeqCst);
            let running = Running::start(&gateway);
            // Even a rejected password must not leave its TLS credentials in a
            // process-wide cache for the next explicit authentication.
            gateway.state.reject_login.store(true, Ordering::SeqCst);
            let mut rejected = running.begin(&gateway, password());
            assert_eq!(
                rejected.prepared().await,
                Err(AuthFailure::AuthenticationRequired)
            );
            assert_eq!(running.handle.phase(), ServicePhase::Waiting);
            gateway.state.reject_login.store(false, Ordering::SeqCst);
            for index in 2..=3 {
                let mut operation = running.begin(&gateway, password());
                operation.prepared().await.unwrap();
                // A prepared operation dropped before commit still logs out
                // and must release the same authentication's transport cache.
                drop(operation);
                wait(|| running.handle.phase() == ServicePhase::Waiting).await;
                assert!(gateway.state.has(&Event::LogoutDone(index)));
            }
            running.close().await;
            let handshakes = gateway.state.tls_handshakes.lock().unwrap().clone();
            assert_eq!(handshakes.len(), 10);
            let mut first = 0;
            let mut resumed = 0;
            for (path, kind) in handshakes {
                if path == "/ssl-vpn/prelogin.esp" {
                    assert_eq!(
                        kind,
                        rustls::HandshakeKind::Full,
                        "new explicit authentication must revalidate the server certificate"
                    );
                    first += 1;
                } else {
                    assert_eq!(
                        kind,
                        rustls::HandshakeKind::Resumed,
                        "same-authentication requests should retain bounded transport reuse"
                    );
                    resumed += 1;
                }
            }
            assert_eq!((first, resumed), (3, 7));
            gateway.close().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn disabled_and_tls12_resumption_policies_survive_authentication_forks() {
    use crate::gp::ResumptionPolicy;
    use rustls::client::Tls12Resumption;
    timeout(Duration::from_secs(15), async {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            for policy in [
                ResumptionPolicy::Disabled,
                ResumptionPolicy::Memory {
                    tls12: Tls12Resumption::Disabled,
                },
                ResumptionPolicy::Memory {
                    tls12: Tls12Resumption::SessionIdOnly,
                },
            ] {
                let mut gateway = Gateway::new_with_versions(&[version]).await;
                set_policy(&mut gateway, policy);
                gateway.state.record_tls.store(true, Ordering::SeqCst);
                let running = Running::start(&gateway);
                for index in 1..=2 {
                    let mut operation = running.begin(&gateway, password());
                    operation.prepared().await.unwrap();
                    drop(operation);
                    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
                    assert!(gateway.state.has(&Event::LogoutDone(index)));
                }
                running.close().await;
                let handshakes = gateway.state.tls_handshakes.lock().unwrap().clone();
                assert_eq!(handshakes.len(), 8);
                let disabled = policy == ResumptionPolicy::Disabled
                    || (version.version == rustls::ProtocolVersion::TLSv1_2
                        && policy
                            == ResumptionPolicy::Memory {
                                tls12: Tls12Resumption::Disabled,
                            });
                for (path, observed) in handshakes {
                    let expected = if disabled || path == "/ssl-vpn/prelogin.esp" {
                        rustls::HandshakeKind::Full
                    } else {
                        rustls::HandshakeKind::Resumed
                    };
                    assert_eq!(
                        observed, expected,
                        "explicit policy {policy:?} must survive each new authentication"
                    );
                }
                gateway.close().await;
            }
        }
    })
    .await
    .unwrap();
}
