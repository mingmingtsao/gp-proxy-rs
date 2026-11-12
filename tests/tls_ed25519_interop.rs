//! Opt-in synthetic TLS evidence. OpenSSL is a development subprocess only.
//! The weak-key experiment deliberately has a public test CA certify an identity
//! key. It is not an attack against an arbitrary legitimate trusted certificate.

use gp_proxy::tls;
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, ServerName},
    sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
    CertificateError, HandshakeKind, ProtocolVersion, SignatureAlgorithm, SignatureScheme,
};
use std::{
    fs, io,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    time::{timeout, Instant},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const STEP: Duration = Duration::from_secs(5);
const CLEANUP: Duration = Duration::from_secs(2);
const TOTAL: Duration = Duration::from_secs(90);
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/tls-interop");
const PAYLOAD: &[u8] = b"synthetic Ed25519 TLS transcript and application data";

fn fail(message: &str) -> io::Error {
    io::Error::other(message)
}

struct Work(PathBuf);

impl Work {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "gp-ed25519-tls-{}-{:016x}",
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
        let work = Self(path);
        fs::write(work.0.join("openssl.cnf"), b"")?;
        fs::write(work.0.join("leaf.cnf"), b"[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")?;
        Ok(work)
    }

    fn command(&self, binary: &Path) -> Command {
        let mut command = Command::new(binary);
        command
            .current_dir(&self.0)
            .env_clear()
            .env("LANG", "C")
            .env("OPENSSL_CONF", self.0.join("openssl.cnf"))
            .env("SSL_CERT_FILE", self.0.join("unused-ca.pem"))
            .env("SSL_CERT_DIR", &self.0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

async fn reap(child: &mut Child) -> io::Result<()> {
    if child.try_wait()?.is_none() {
        child.start_kill()?;
    }
    timeout(CLEANUP, child.wait())
        .await
        .map_err(|_| fail("OpenSSL child reap deadline"))??;
    Ok(())
}

async fn run_command(mut command: Command) -> io::Result<Vec<u8>> {
    let mut child = command.spawn()?;
    let mut stdout = child.stdout.take().unwrap().take(8193);
    let mut stderr = child.stderr.take().unwrap().take(8193);
    let (mut output, mut diagnostic) = (Vec::new(), Vec::new());
    let result = timeout(STEP, async {
        tokio::try_join!(
            stdout.read_to_end(&mut output),
            stderr.read_to_end(&mut diagnostic)
        )?;
        child.wait().await
    })
    .await;
    // Ownership remains outside timeout: every normal Result path reaps.
    reap(&mut child).await?;
    let status = result.map_err(|_| fail("OpenSSL command deadline"))??;
    if output.len() > 8192 || diagnostic.len() > 8192 {
        return Err(fail("OpenSSL command output exceeded bound"));
    }
    if !status.success() {
        eprintln!(
            "synthetic OpenSSL command diagnostic: {}",
            String::from_utf8_lossy(&diagnostic)
        );
        return Err(fail("synthetic OpenSSL command failed"));
    }
    Ok(output)
}

async fn generate(binary: &Path, work: &Work) -> io::Result<()> {
    let mut command = work.command(binary);
    command.arg("version");
    let version = run_command(command).await?;
    if !version.starts_with(b"OpenSSL 3.") {
        return Err(fail("explicit OpenSSL 3.x executable required"));
    }
    eprintln!(
        "Ed25519 independent peer: {}",
        String::from_utf8_lossy(&version).trim()
    );
    for args in [
        vec![
            "req",
            "-new",
            "-x509",
            "-newkey",
            "ed25519",
            "-noenc",
            "-keyout",
            "ca-key.pem",
            "-out",
            "ca-cert.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Temporary Ed25519 Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
        vec![
            "req",
            "-new",
            "-newkey",
            "ed25519",
            "-noenc",
            "-keyout",
            "leaf-key.pem",
            "-out",
            "leaf.csr",
            "-subj",
            "/CN=localhost",
        ],
        vec![
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "ca-cert.pem",
            "-CAkey",
            "ca-key.pem",
            "-set_serial",
            "2026111201",
            "-days",
            "1",
            "-extfile",
            "leaf.cnf",
            "-extensions",
            "leaf",
            "-out",
            "leaf-cert.pem",
        ],
    ] {
        let mut command = work.command(binary);
        command.args(args);
        run_command(command).await?;
    }
    // RFC 8410 SPKI, identity A=(0,1). The malicious signer has no private key.
    let mut identity = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0, 1,
    ];
    identity.resize(44, 0);
    fs::write(work.0.join("identity.der"), identity)?;
    let mut command = work.command(binary);
    command.args([
        "pkey",
        "-pubin",
        "-inform",
        "DER",
        "-in",
        "identity.der",
        "-pubout",
        "-out",
        "identity.pem",
    ]);
    run_command(command).await?;
    let mut command = work.command(binary);
    command
        .args(["x509", "-new", "-force_pubkey", "identity.pem", "-CA"])
        .arg(Path::new(FIXTURES).join("ca-rsa-cert.pem"))
        .arg("-CAkey")
        .arg(Path::new(FIXTURES).join("ca-rsa-key.pem"))
        .args([
            "-set_serial",
            "2026111202",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-extfile",
            "leaf.cnf",
            "-extensions",
            "leaf",
            "-out",
            "identity-cert.pem",
        ]);
    run_command(command).await?;
    Ok(())
}

async fn openssl_positive(binary: &Path, work: &Work, version: ProtocolVersion) -> io::Result<()> {
    let mut command = work.command(binary);
    command
        .args([
            "s_server",
            "-accept",
            "127.0.0.1:0",
            "-4",
            "-naccept",
            "1",
            "-rev",
            "-no-CAfile",
            "-no-CApath",
            "-no-CAstore",
            "-no_cache",
            "-no_ticket",
            "-cert",
            "leaf-cert.pem",
            "-key",
            "leaf-key.pem",
            "-groups",
            "P-256",
            "-sigalgs",
            "ed25519",
        ])
        .arg(if version == ProtocolVersion::TLSv1_2 {
            "-tls1_2"
        } else {
            "-tls1_3"
        });
    let mut child = command.spawn()?;
    let mut stdout = BufReader::new(child.stdout.take().unwrap().take(8193));
    let result = timeout(STEP, async {
        let address = loop {
            let mut line = String::new();
            if stdout.read_line(&mut line).await? == 0 {
                return Err(fail("OpenSSL listener reported no address"));
            }
            if let Some(value) = line.trim().strip_prefix("ACCEPT ") {
                let address: SocketAddr = value
                    .parse()
                    .map_err(|_| fail("invalid listener address"))?;
                if address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
                    return Err(fail("listener is not numeric loopback"));
                }
                break address;
            }
        };
        // Unmodified production config; only the server constrains the version.
        let config = tls::client_config(Some(&work.0.join("ca-cert.pem")))?;
        let mut stream = TlsConnector::from(config)
            .connect(
                ServerName::try_from("localhost").unwrap(),
                TcpStream::connect(address).await?,
            )
            .await?;
        if stream.get_ref().1.protocol_version() != Some(version)
            || stream.get_ref().1.handshake_kind() != Some(HandshakeKind::Full)
        {
            return Err(fail("expected full handshake at selected TLS version"));
        }
        let request = [PAYLOAD, b"\n"].concat();
        let mut expected: Vec<u8> = PAYLOAD.iter().rev().copied().collect();
        expected.push(b'\n');
        stream.write_all(&request).await?;
        stream.flush().await?;
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).await?;
        if received != expected {
            return Err(fail("OpenSSL Ed25519 echo mismatch"));
        }
        stream.shutdown().await?;
        if stream.read(&mut [0; 1]).await? != 0 {
            return Err(fail("data after close_notify"));
        }
        Ok(())
    })
    .await
    .map_err(|_| fail("OpenSSL Ed25519 case deadline"))
    .and_then(|result| result);
    let cleanup = reap(&mut child).await;
    drop(stdout);
    let mut diagnostic = Vec::new();
    let diagnostic_result = timeout(
        CLEANUP,
        child
            .stderr
            .take()
            .unwrap()
            .take(8193)
            .read_to_end(&mut diagnostic),
    )
    .await;
    cleanup?;
    diagnostic_result.map_err(|_| fail("OpenSSL diagnostic pipe deadline"))??;
    if diagnostic.len() > 8192 {
        return Err(fail("OpenSSL server diagnostics exceeded bound"));
    }
    if result.is_err() {
        eprintln!(
            "synthetic Ed25519 server diagnostic: {}",
            String::from_utf8_lossy(&diagnostic)
        );
    }
    result?;
    eprintln!("Ed25519 OpenSSL pass: {version:?}; Ed25519 CA/leaf chain and handshake signature; full reverse echo");
    Ok(())
}

#[derive(Debug)]
struct IdentitySigner(Arc<AtomicUsize>);

impl SigningKey for IdentitySigner {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(Self(self.0.clone())) as Box<dyn Signer>)
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

impl Signer for IdentitySigner {
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let mut signature = vec![0; 64];
        signature[0] = 1;
        Ok(signature)
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

async fn weak_key_case(work: &Work, version: ProtocolVersion) -> io::Result<()> {
    let sign_count = Arc::new(AtomicUsize::new(0));
    let app_bytes = Arc::new(AtomicUsize::new(0));
    let certificate = CertificateDer::from_pem_file(work.0.join("identity-cert.pem"))
        .map_err(|_| fail("weak certificate parse"))?;
    let certified = CertifiedKey::new(
        vec![certificate],
        Arc::new(IdentitySigner(sign_count.clone())),
    );
    let versions = if version == ProtocolVersion::TLSv1_2 {
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(versions)
    .map_err(io::Error::other)?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let observed_bytes = app_bytes.clone();
    let mut peer = tokio::spawn(async move {
        timeout(STEP, async {
            let (tcp, _) = listener.accept().await?;
            let mut stream = TlsAcceptor::from(Arc::new(config)).accept(tcp).await?;
            let mut received = vec![0; PAYLOAD.len()];
            let mut offset = 0;
            while offset < received.len() {
                let read = stream.read(&mut received[offset..]).await?;
                observed_bytes.fetch_add(read, Ordering::SeqCst);
                if read == 0 {
                    return Err(fail("weak peer early application EOF"));
                }
                offset += read;
            }
            if received != PAYLOAD {
                return Err(fail("weak peer application mismatch"));
            }
            stream.write_all(&received).await?;
            stream.flush().await?;
            stream.shutdown().await?;
            if stream.read(&mut [0; 1]).await? != 0 {
                return Err(fail("extra weak peer application data"));
            }
            Ok::<_, io::Error>(())
        })
        .await
        .map_err(|_| fail("weak TLS peer deadline"))?
    });
    let client = timeout(STEP, async {
        let ca = Path::new(FIXTURES).join("ca-rsa-cert.pem");
        let config = tls::client_config(Some(&ca))?;
        let connected = TlsConnector::from(config)
            .connect(
                ServerName::try_from("localhost").unwrap(),
                TcpStream::connect(address).await?,
            )
            .await;
        let failure = connected
            .err()
            .ok_or_else(|| fail("production accepted weak Ed25519 handshake"))?;
        if !matches!(
            failure
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::InvalidCertificate(
                CertificateError::BadSignature
            ))
        ) {
            return Err(fail(&format!(
                "weak key failed outside exact signature validation: {failure}"
            )));
        }
        Ok(())
    })
    .await
    .map_err(|_| fail("weak TLS client deadline"))
    .and_then(|result| result);
    // Join on success/error/timeout. Panics still rely on the test runtime's drop.
    let joined = match timeout(CLEANUP, &mut peer).await {
        Ok(joined) => joined.map_err(io::Error::other),
        Err(_) => {
            peer.abort();
            if timeout(CLEANUP, peer).await.is_err() {
                return Err(fail("weak TLS peer abort/join deadline"));
            }
            Err(fail("weak TLS peer did not join naturally"))
        }
    };
    let server = joined?;
    client?;
    if server.is_ok() {
        return Err(fail("weak peer completed production handshake"));
    }
    if sign_count.load(Ordering::SeqCst) != 1 {
        return Err(fail("weak signer not used exactly once"));
    }
    if app_bytes.load(Ordering::SeqCst) != 0 {
        return Err(fail("unexpected weak peer application byte count"));
    }
    eprintln!("Ed25519 certified identity: {version:?}; signer_calls=1; peer_app_bytes=0; production exact BadSignature rejection; peer joined");
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicit OpenSSL 3 and synthetic loopback subprocess permission; no product dependency"]
async fn openssl_ed25519_and_certified_weak_key_rejection() -> io::Result<()> {
    let binary = PathBuf::from(
        std::env::var_os("OPENSSL_BIN").ok_or_else(|| fail("set explicit OPENSSL_BIN"))?,
    );
    if !binary.is_absolute() || !binary.is_file() {
        return Err(fail("OPENSSL_BIN must be an absolute file path"));
    }
    let work = Work::new()?;
    let path = work.0.clone();
    let started = Instant::now();
    generate(&binary, &work).await?;
    for version in [ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3] {
        // A finite number of bounded steps; no outer cancellation skips reaping.
        if started.elapsed() > TOTAL - Duration::from_secs(28) {
            return Err(fail("Ed25519 matrix total budget"));
        }
        openssl_positive(&binary, &work, version).await?;
        weak_key_case(&work, version).await?;
    }
    drop(work);
    if path.exists() {
        return Err(fail("temporary certificate directory not removed"));
    }
    if started.elapsed() >= TOTAL {
        return Err(fail("Ed25519 matrix exceeded total deadline"));
    }
    eprintln!("Ed25519 TLS evidence: 2 OpenSSL full handshakes, 2 production BadSignature rejections; 8 OpenSSL children reaped; 2 Rust peers joined; temporary keys removed; {:.3}s", started.elapsed().as_secs_f64());
    Ok(())
}
