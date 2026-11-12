//! Opt-in independent resumption peer. OpenSSL is only a synthetic development
//! server; no runtime dependency or real gateway/credential access is involved.
use gp_proxy::tls;
use rustls::{
    client::Resumption, pki_types::ServerName, CertificateError, CipherSuite, ClientConfig,
    HandshakeKind, NamedGroup, ProtocolVersion,
};
use std::{fs, io, net::SocketAddr, path::Path, path::PathBuf, process::Stdio, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    process::{Child, Command},
    task::JoinHandle,
    time::{timeout, timeout_at, Duration, Instant},
};
use tokio_rustls::TlsConnector;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/tls-interop");
const CASE_LIMIT: Duration = Duration::from_secs(5);
const CLEANUP_LIMIT: Duration = Duration::from_secs(2);
const TOTAL_LIMIT: Duration = Duration::from_secs(60);
const OUTPUT_LIMIT: u64 = 64 * 1024;

fn error(message: &str) -> io::Error {
    io::Error::other(message)
}

struct Directory(PathBuf);

impl Directory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "gp-public-tls-resumption-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        builder.create(&path)?;
        let owned = Self(path);
        fs::write(owned.0.join("openssl.cnf"), b"")?;
        Ok(owned)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn command(binary: &Path, directory: &Directory) -> Command {
    let mut command = Command::new(binary);
    command
        .current_dir(&directory.0)
        .env_clear()
        .env("LANG", "C")
        .env("OPENSSL_CONF", directory.0.join("openssl.cnf"))
        .env("SSL_CERT_FILE", directory.0.join("unused-ca.pem"))
        .env("SSL_CERT_DIR", &directory.0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

async fn reap(child: &mut Child) -> io::Result<()> {
    if child.try_wait()?.is_none() {
        child.start_kill()?;
    }
    timeout(CLEANUP_LIMIT, child.wait())
        .await
        .map_err(|_| error("OpenSSL cleanup deadline exceeded"))??;
    Ok(())
}

async fn version(binary: &Path, directory: &Directory) -> io::Result<String> {
    let mut child = command(binary, directory).arg("version").spawn()?;
    let mut stdout = child.stdout.take().unwrap().take(1025);
    let mut stderr = child.stderr.take().unwrap().take(1025);
    let (mut output, mut errors) = (Vec::new(), Vec::new());
    let observed = timeout(CASE_LIMIT, async {
        tokio::try_join!(
            stdout.read_to_end(&mut output),
            stderr.read_to_end(&mut errors)
        )?;
        child.wait().await
    })
    .await;
    reap(&mut child).await?;
    let status = observed.map_err(|_| error("OpenSSL version deadline exceeded"))??;
    if !status.success()
        || !output.starts_with(b"OpenSSL 3.")
        || output.len() > 1024
        || !errors.is_empty()
    {
        return Err(error("explicit OpenSSL 3.x executable is required"));
    }
    String::from_utf8(output).map_err(|_| error("invalid OpenSSL version output"))
}

/// Drain diagnostics without storing or logging ticket/session material.
async fn discard_output(input: impl AsyncRead + Unpin) -> io::Result<()> {
    let count = tokio::io::copy(&mut input.take(OUTPUT_LIMIT + 1), &mut tokio::io::sink()).await?;
    if count > OUTPUT_LIMIT {
        return Err(error("OpenSSL output limit exceeded"));
    }
    Ok(())
}

async fn join_output(task: &mut Option<JoinHandle<io::Result<()>>>) -> io::Result<()> {
    let Some(mut task) = task.take() else {
        return Ok(());
    };
    match timeout(CLEANUP_LIMIT, &mut task).await {
        Ok(result) => result.map_err(|_| error("OpenSSL output reader task failed"))?,
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(error("OpenSSL output reader cleanup deadline exceeded"))
        }
    }
}

fn trusted_config() -> io::Result<Arc<ClientConfig>> {
    tls::client_config(Some(&Path::new(FIXTURES).join("ca-ecdsa-cert.pem")))
}

async fn positive(
    address: SocketAddr,
    config: Arc<ClientConfig>,
    protocol: ProtocolVersion,
    expected: HandshakeKind,
    marker: u8,
) -> io::Result<()> {
    if config.enable_early_data {
        return Err(error(
            "production configuration unexpectedly enables early data",
        ));
    }
    let tcp = TcpStream::connect(address).await?;
    let mut stream = TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await?;
    let state = &stream.get_ref().1;
    // TLS 1.2 resumption reuses its master secret without fresh ECDHE. TLS 1.3
    // PSK-DHE resumption does perform the configured ephemeral key exchange.
    let expected_group = match (protocol, expected) {
        (ProtocolVersion::TLSv1_2, HandshakeKind::Resumed) => None,
        (ProtocolVersion::TLSv1_3, _) => Some(NamedGroup::secp384r1),
        _ => Some(NamedGroup::secp256r1),
    };
    if state.handshake_kind() != Some(expected)
        || state.protocol_version() != Some(protocol)
        || state.negotiated_cipher_suite().map(|suite| suite.suite())
            != Some(if protocol == ProtocolVersion::TLSv1_3 {
                CipherSuite::TLS13_AES_128_GCM_SHA256
            } else {
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            })
        || state.negotiated_key_exchange_group().map(|g| g.name()) != expected_group
        || state.is_early_data_accepted()
    {
        return Err(error(&format!(
            "unexpected resumption result: wanted {expected:?}/{protocol:?}/{expected_group:?}, got {:?}/{:?}/{:?}/{:?}",
            state.handshake_kind(), state.protocol_version(),
            state.negotiated_key_exchange_group().map(|g| g.name()),
            state.negotiated_cipher_suite().map(|suite| suite.suite())
        )));
    }
    let mut payload: Vec<u8> = (0..1024)
        .map(|index| b'a' + ((index + marker as usize) % 26) as u8)
        .collect();
    let mut reversed: Vec<u8> = payload.iter().rev().copied().collect();
    payload.push(b'\n');
    reversed.push(b'\n');
    stream.write_all(&payload).await?;
    stream.flush().await?;
    let mut response = vec![0; reversed.len()];
    // Reading the response and clean EOF also processes post-handshake tickets.
    stream.read_exact(&mut response).await?;
    if response != reversed {
        return Err(error(
            "resumed/full connection delivered incorrect synthetic payload",
        ));
    }
    stream.shutdown().await?;
    if stream.read(&mut [0; 1]).await? != 0 {
        return Err(error("application bytes after orderly TLS shutdown"));
    }
    Ok(())
}

async fn negative(
    address: SocketAddr,
    config: Arc<ClientConfig>,
    name: &'static str,
    unknown_issuer: bool,
) -> io::Result<()> {
    let tcp = TcpStream::connect(address).await?;
    let failure = match TlsConnector::from(config)
        .connect(ServerName::try_from(name).unwrap(), tcp)
        .await
    {
        Ok(_) => {
            return Err(error(
                "resumption bypassed certificate identity/trust rejection",
            ))
        }
        Err(failure) => failure,
    };
    let Some(rustls::Error::InvalidCertificate(reason)) = failure
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    else {
        return Err(error("negative case failed outside certificate validation"));
    };
    if if unknown_issuer {
        !matches!(reason, CertificateError::UnknownIssuer)
    } else {
        !matches!(
            reason,
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
        )
    } {
        return Err(error("negative case produced the wrong certificate error"));
    }
    Ok(())
}

async fn cases(address: SocketAddr, protocol: ProtocolVersion) -> io::Result<()> {
    let original = trusted_config()?;
    let full = if protocol == ProtocolVersion::TLSv1_3 {
        HandshakeKind::FullWithHelloRetryRequest
    } else {
        HandshakeKind::Full
    };
    timeout(
        CASE_LIMIT,
        positive(address, original.clone(), protocol, full, 1),
    )
    .await
    .map_err(|_| error("initial full handshake deadline exceeded"))??;
    timeout(
        CASE_LIMIT,
        positive(
            address,
            original.clone(),
            protocol,
            HandshakeKind::Resumed,
            2,
        ),
    )
    .await
    .map_err(|_| error("resumed handshake deadline exceeded"))??;

    // Model per-authentication cache rotation explicitly. Keep exactly the same
    // provider/verifier/roots/client-cert resolver while replacing only storage.
    let mut fresh_store = original.as_ref().clone();
    fresh_store.resumption = Resumption::default();
    timeout(
        CASE_LIMIT,
        positive(address, Arc::new(fresh_store), protocol, full, 3),
    )
    .await
    .map_err(|_| error("fresh store handshake deadline exceeded"))??;
    timeout(
        CASE_LIMIT,
        positive(address, trusted_config()?, protocol, full, 4),
    )
    .await
    .map_err(|_| error("fresh configuration handshake deadline exceeded"))??;

    // Adversarial sharing: new production roots do not trust the synthetic CA.
    // Deliberately share the old cache and client-cert resolver so rejection
    // depends on the changed verifier, not on a changed client-cert identity.
    let mut untrusted = tls::client_config(None)?.as_ref().clone();
    untrusted.resumption = original.resumption.clone();
    untrusted.client_auth_cert_resolver = original.client_auth_cert_resolver.clone();
    timeout(
        CASE_LIMIT,
        negative(address, Arc::new(untrusted), "localhost", true),
    )
    .await
    .map_err(|_| error("changed trust rejection deadline exceeded"))??;
    timeout(
        CASE_LIMIT,
        negative(address, original, "wrong.invalid", false),
    )
    .await
    .map_err(|_| error("changed name rejection deadline exceeded"))??;
    Ok(())
}

async fn run_protocol(
    binary: &Path,
    directory: &Directory,
    protocol: ProtocolVersion,
    deadline: Instant,
) -> io::Result<()> {
    let mut server = command(binary, directory);
    server
        .args([
            "s_server",
            "-accept",
            "127.0.0.1:0",
            "-4",
            "-naccept",
            "6",
            "-rev",
            "-no-CAfile",
            "-no-CApath",
            "-no-CAstore",
            "-num_tickets",
            "2",
        ])
        .arg("-cert")
        .arg(Path::new(FIXTURES).join("ecdsa-cert.pem"))
        .arg("-key")
        .arg(Path::new(FIXTURES).join("ecdsa-key.pem"))
        .arg("-groups")
        .arg(if protocol == ProtocolVersion::TLSv1_3 {
            "P-384"
        } else {
            "P-256"
        })
        .arg(if protocol == ProtocolVersion::TLSv1_3 {
            "-tls1_3"
        } else {
            "-tls1_2"
        })
        .arg(if protocol == ProtocolVersion::TLSv1_3 {
            "-ciphersuites"
        } else {
            "-cipher"
        })
        .arg(if protocol == ProtocolVersion::TLSv1_3 {
            "TLS_AES_128_GCM_SHA256"
        } else {
            "ECDHE-ECDSA-AES128-GCM-SHA256"
        });
    let mut child = server.spawn()?;
    let mut output = BufReader::new(child.stdout.take().unwrap().take(OUTPUT_LIMIT + 1));
    let mut stderr = Some(tokio::spawn(discard_output(child.stderr.take().unwrap())));
    let mut stdout = None;
    let result = timeout_at(deadline - CLEANUP_LIMIT * 3, async {
        let address = timeout(CASE_LIMIT, async {
            loop {
                let mut line = String::new();
                if output.read_line(&mut line).await? == 0 {
                    return Err(error("OpenSSL did not report a listener"));
                }
                if let Some(value) = line.trim().strip_prefix("ACCEPT ") {
                    let address: SocketAddr = value
                        .parse()
                        .map_err(|_| error("invalid listening address"))?;
                    if address.ip() != std::net::Ipv4Addr::LOCALHOST || address.port() == 0 {
                        return Err(error("server was not numeric loopback"));
                    }
                    return Ok(address);
                }
            }
        })
        .await
        .map_err(|_| error("OpenSSL listener deadline exceeded"))??;
        stdout = Some(tokio::spawn(discard_output(output)));
        cases(address, protocol).await
    })
    .await
    .map_err(|_| error("resumption matrix total deadline exceeded"))
    .and_then(|result| result);
    // Retain child/task ownership outside the cancellable interaction. Attempt
    // every cleanup even when one fails, and never print session diagnostics.
    let child_result = reap(&mut child).await;
    let stderr_result = join_output(&mut stderr).await;
    let stdout_result = join_output(&mut stdout).await;
    child_result?;
    stderr_result?;
    stdout_result?;
    result
}

#[tokio::test]
#[ignore = "requires explicit OPENSSL_BIN and synthetic loopback subprocess permission; no product dependency"]
async fn independent_resumption_and_identity_boundaries() -> io::Result<()> {
    let binary = PathBuf::from(
        std::env::var_os("OPENSSL_BIN")
            .ok_or_else(|| error("set OPENSSL_BIN explicitly to OpenSSL 3.x (3.6.3 verified)"))?,
    );
    if !binary.is_absolute() || !binary.is_file() {
        return Err(error(
            "OPENSSL_BIN must be an absolute executable file path",
        ));
    }
    let directory = Directory::new()?;
    let path = directory.0.clone();
    let started = Instant::now();
    let deadline = started + TOTAL_LIMIT;
    eprintln!(
        "independent TLS resumption peer: {}",
        version(&binary, &directory).await?.trim()
    );
    for protocol in [ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3] {
        run_protocol(&binary, &directory, protocol, deadline).await?;
        eprintln!("TLS resumption {protocol:?}: full, resumed, fresh-cache full, fresh-config full; shared-cache changed verifier UnknownIssuer; changed name NotValidForName");
    }
    drop(directory);
    assert!(!path.exists(), "test working directory was not removed");
    assert!(started.elapsed() < TOTAL_LIMIT);
    eprintln!("TLS resumption boundaries: 12 connections, 8 successful payload exchanges, 4 exact certificate rejections; 2 server children and version child reaped; temporary directory removed; {:.3}s", started.elapsed().as_secs_f64());
    Ok(())
}
