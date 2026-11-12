//! Actual CLI processes against synthetic local IPC, never a network gateway.
use super::*;

const PORTAL: &str = "https://synthetic-vpn.invalid:7443";

fn portal_config(fixture: &Fixture) {
    fs::write(
        fixture.0.join("config.toml"),
        format!(
            "gateway = '{GATEWAY}'\nportal = '{PORTAL}'\ndomains = ['synthetic-corp.invalid']\n"
        ),
    )
    .unwrap();
}

fn portal_hello(listener: &LocalListener) -> Value {
    let mut message = hello(listener, "waiting");
    message["binding"] = json!({"mode":"portal", "portal":PORTAL, "gateway":GATEWAY});
    message
}

#[tokio::test]
async fn portal_preflight_mode_and_both_origins_precede_open_stdin() {
    for case in ["direct_role", "portal_port", "gateway_port"] {
        let fixture = Fixture::new();
        portal_config(&fixture);
        let listener = LocalListener::bind(&fixture.endpoint()).unwrap();
        let mut message = portal_hello(&listener);
        match case {
            "direct_role" => message["binding"] = json!({"mode":"direct", "gateway":GATEWAY}),
            "portal_port" => {
                message["binding"]["portal"] = json!("https://synthetic-vpn.invalid:7444")
            }
            "gateway_port" => {
                message["binding"]["gateway"] = json!("https://synthetic-vpn.invalid:8443")
            }
            _ => unreachable!(),
        }
        let (mut child, _stdin_kept_open) = fixture.spawn(STDIN_ARGS, true);
        let peer = async {
            let mut stream = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
            send(&mut stream, &message).await;
            no_submission(&mut stream).await;
        };
        let ((), (status, stdout, stderr)) = tokio::join!(peer, finish(&mut child));
        assert!(!status.success(), "{case}");
        assert!(stdout.is_empty());
        assert!(
            stderr.contains("configured authentication binding differs"),
            "{case}: {stderr}"
        );
    }
}

#[tokio::test]
async fn portal_identity_change_after_password_read_never_submits() {
    for case in ["direct_role", "portal_port", "gateway_port"] {
        let fixture = Fixture::new();
        portal_config(&fixture);
        let listener = LocalListener::bind(&fixture.endpoint()).unwrap();
        let (mut child, mut stdin) = fixture.spawn(STDIN_ARGS, true);
        let peer = async {
            let mut first = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
            send(&mut first, &portal_hello(&listener)).await;
            no_submission(&mut first).await;
            drop(first);
            stdin
                .write_all(format!("{PASSWORD}\n").as_bytes())
                .await
                .unwrap();
            drop(stdin);
            let mut second = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
            let mut changed = portal_hello(&listener);
            match case {
                "direct_role" => changed["binding"] = json!({"mode":"direct", "gateway":GATEWAY}),
                "portal_port" => {
                    changed["binding"]["portal"] = json!("https://synthetic-vpn.invalid:7444")
                }
                "gateway_port" => {
                    changed["binding"]["gateway"] = json!("https://synthetic-vpn.invalid:8443")
                }
                _ => unreachable!(),
            }
            send(&mut second, &changed).await;
            no_submission(&mut second).await;
        };
        let ((), (status, _, stderr)) = tokio::join!(peer, finish(&mut child));
        assert!(!status.success(), "{case}");
        assert!(stderr.contains("local service changed"), "{case}: {stderr}");
        assert!(stderr.contains("Authentication mode: portal"));
    }
}

#[tokio::test]
async fn credential_file_roles_and_portal_session_import_fail_before_open() {
    for (portal_mode, option, expected) in [
        (
            true,
            "--env-file",
            "--env-file cannot authenticate a portal service",
        ),
        (
            true,
            "--session-file",
            "--session-file is not supported in portal mode",
        ),
        (
            false,
            "--portal-env-file",
            "--portal-env-file requires configured portal mode",
        ),
    ] {
        let fixture = Fixture::new();
        if portal_mode {
            portal_config(&fixture);
        }
        let listener = LocalListener::bind(&fixture.endpoint()).unwrap();
        let missing = fixture.0.join("absent.synthetic");
        let (mut child, _stdin_kept_open) =
            fixture.spawn(&["reauth", option, missing.to_str().unwrap()], true);
        let peer = async {
            let mut stream = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
            let message = if portal_mode {
                portal_hello(&listener)
            } else {
                hello(&listener, "waiting")
            };
            send(&mut stream, &message).await;
            no_submission(&mut stream).await;
        };
        let ((), (status, _, stderr)) = tokio::join!(peer, finish(&mut child));
        assert!(!status.success());
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!stderr.contains("secret file"));
    }
}

#[tokio::test]
async fn portal_password_submit_preserves_explicit_role_and_complete_binding() {
    let fixture = Fixture::new();
    portal_config(&fixture);
    let listener = LocalListener::bind(&fixture.endpoint()).unwrap();
    let (mut child, mut stdin) = fixture.spawn(STDIN_ARGS, true);
    let peer = async {
        let mut first = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        send(&mut first, &portal_hello(&listener)).await;
        no_submission(&mut first).await;
        drop(first);
        stdin
            .write_all(format!("{PASSWORD}\n").as_bytes())
            .await
            .unwrap();
        drop(stdin);
        let mut second = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        let message = portal_hello(&listener);
        send(&mut second, &message).await;
        let submitted = timeout(LIMIT, async {
            let length = second.read_u32().await.unwrap() as usize;
            assert!((1..=65536).contains(&length));
            let mut bytes = vec![0; length];
            second.read_exact(&mut bytes).await.unwrap();
            serde_json::from_slice::<Value>(&bytes).unwrap()
        })
        .await
        .unwrap();
        assert_eq!(submitted["version"], gp_proxy::control::PROTOCOL_VERSION);
        assert_eq!(submitted["binding"], message["binding"]);
        assert_eq!(submitted["authentication"]["kind"], "portal_password");
        assert_eq!(submitted["authentication"]["portal"], PORTAL);
        assert_eq!(submitted["authentication"]["password"], PASSWORD);
        assert!(submitted.get("gateway").is_none());
        send(&mut second, &json!({"result":"accepted"})).await;
        no_submission(&mut second).await;
    };
    let ((), (status, stdout, stderr)) = tokio::join!(peer, finish(&mut child));
    assert!(status.success(), "{stderr}");
    assert!(stdout.contains("Authentication accepted"));
    assert!(stderr.contains(PORTAL) && stderr.contains(GATEWAY));
}
