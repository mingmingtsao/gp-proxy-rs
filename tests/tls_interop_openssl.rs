//! Opt-in independent TLS peer. OpenSSL is a development subprocess only;
//! the client uses the unmodified production AWS-LC-backed rustls configuration.
use gp_proxy::tls;
use rustls::{
    pki_types::ServerName, CertificateError, CipherSuite, HandshakeKind, NamedGroup,
    ProtocolVersion,
};
use std::{
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    process::{Child, ChildStdout, Command},
    time::{timeout, timeout_at, Instant},
};
use tokio_rustls::TlsConnector;

const CASE_LIMIT: Duration = Duration::from_secs(5);
const TOTAL_LIMIT: Duration = Duration::from_secs(120);
const CLEANUP_LIMIT: Duration = Duration::from_secs(2);
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/tls-interop");

fn error(message: &str) -> io::Error {
    io::Error::other(message)
}

struct WorkingDirectory(PathBuf);

impl WorkingDirectory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "gp-public-tls-interop-{}-{:016x}",
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

impl Drop for WorkingDirectory {
    fn drop(&mut self) {
        // Only this fresh test-owned directory, never caller-selected inputs.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn command(binary: &Path, directory: &WorkingDirectory) -> Command {
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
        .map_err(|_| error("OpenSSL child cleanup exceeded its deadline"))??;
    Ok(())
}

async fn version(binary: &Path, directory: &WorkingDirectory) -> io::Result<String> {
    let mut child = command(binary, directory).arg("version").spawn()?;
    let mut stdout = child.stdout.take().unwrap().take(1025);
    let mut stderr = child.stderr.take().unwrap().take(1025);
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let observed = timeout(CASE_LIMIT, async {
        tokio::try_join!(
            stdout.read_to_end(&mut output),
            stderr.read_to_end(&mut errors)
        )?;
        child.wait().await
    })
    .await;
    // Retain ownership outside the timed future, including a stalled version
    // command. Do not rely only on kill_on_drop's eventual runtime reaper.
    reap(&mut child).await?;
    let status = observed.map_err(|_| error("OpenSSL version check timed out"))??;
    if !status.success()
        || !output.starts_with(b"OpenSSL 3.")
        || output.len() > 1024
        || !errors.is_empty()
    {
        return Err(error(
            "explicit OpenSSL 3.x executable required for this opt-in matrix",
        ));
    }
    String::from_utf8(output).map_err(|_| error("invalid OpenSSL version output"))
}

#[derive(Clone, Copy, Debug)]
enum Certificate {
    Rsa,
    Ecdsa,
}

impl Certificate {
    fn name(self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Ecdsa => "ecdsa",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Negative {
    WrongName,
    Untrusted,
    Expired,
    WrongEku,
}

impl Negative {
    fn matches(self, reason: &CertificateError) -> bool {
        match self {
            Self::WrongName => matches!(
                reason,
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
            ),
            Self::Untrusted => matches!(reason, CertificateError::UnknownIssuer),
            Self::Expired => matches!(
                reason,
                CertificateError::Expired | CertificateError::ExpiredContext { .. }
            ),
            Self::WrongEku => matches!(
                reason,
                CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. }
            ),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Case {
    version: ProtocolVersion,
    certificate: Certificate,
    group: NamedGroup,
    aead: usize,
    negative: Option<Negative>,
}

impl Case {
    fn cipher(self) -> (CipherSuite, &'static str) {
        use CipherSuite::*;
        if self.version == ProtocolVersion::TLSv1_3 {
            [
                (TLS13_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"),
                (TLS13_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"),
                (
                    TLS13_CHACHA20_POLY1305_SHA256,
                    "TLS_CHACHA20_POLY1305_SHA256",
                ),
            ][self.aead]
        } else {
            match self.certificate {
                Certificate::Rsa => [
                    (
                        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        "ECDHE-RSA-AES128-GCM-SHA256",
                    ),
                    (
                        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                        "ECDHE-RSA-AES256-GCM-SHA384",
                    ),
                    (
                        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                        "ECDHE-RSA-CHACHA20-POLY1305",
                    ),
                ][self.aead],
                Certificate::Ecdsa => [
                    (
                        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        "ECDHE-ECDSA-AES128-GCM-SHA256",
                    ),
                    (
                        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                        "ECDHE-ECDSA-AES256-GCM-SHA384",
                    ),
                    (
                        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                        "ECDHE-ECDSA-CHACHA20-POLY1305",
                    ),
                ][self.aead],
            }
        }
    }

    fn certificate_path(self) -> PathBuf {
        Path::new(FIXTURES).join(match self.negative {
            Some(Negative::Expired) => "expired-cert.pem".to_string(),
            Some(Negative::WrongEku) => "wrong-eku-cert.pem".to_string(),
            _ => format!("{}-cert.pem", self.certificate.name()),
        })
    }
}

type OutputReader = BufReader<tokio::io::Take<ChildStdout>>;

async fn address(stdout: &mut OutputReader) -> io::Result<SocketAddr> {
    loop {
        let mut line = String::new();
        if stdout.read_line(&mut line).await? == 0 {
            return Err(error("OpenSSL did not report a bounded listening address"));
        }
        if let Some(value) = line.trim().strip_prefix("ACCEPT ") {
            let address: SocketAddr = value
                .parse()
                .map_err(|_| error("invalid OpenSSL listening address"))?;
            if address.ip() != std::net::Ipv4Addr::LOCALHOST || address.port() == 0 {
                return Err(error("OpenSSL listener was not numeric IPv4 loopback"));
            }
            return Ok(address);
        }
    }
}

async fn interact(case: Case, stdout: &mut OutputReader) -> io::Result<usize> {
    let address = address(stdout).await?;
    let ca = Path::new(FIXTURES).join(format!("ca-{}-cert.pem", case.certificate.name()));
    let configured = tls::client_config(if matches!(case.negative, Some(Negative::Untrusted)) {
        None
    } else {
        Some(&ca)
    })?;
    // Never change roots, versions, verifier, groups, suites or provider after
    // obtaining the actual production configuration. Only the server restricts.
    let hostname = if matches!(case.negative, Some(Negative::WrongName)) {
        "wrong.invalid"
    } else {
        "localhost"
    };
    let tcp = TcpStream::connect(address).await?;
    let result = TlsConnector::from(configured)
        .connect(ServerName::try_from(hostname).unwrap(), tcp)
        .await;
    if let Some(expected) = case.negative {
        let failure = match result {
            Ok(_) => {
                return Err(error(
                    "production client accepted a negative certificate fixture",
                ))
            }
            Err(failure) => failure,
        };
        let Some(rustls::Error::InvalidCertificate(reason)) = failure
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        else {
            return Err(error(&format!(
                "negative fixture failed outside certificate validation: {failure}"
            )));
        };
        if !expected.matches(reason) {
            return Err(error(&format!(
                "wrong certificate rejection category: {reason:?}"
            )));
        }
        return Ok(0);
    }
    let mut stream = result?;
    let (_, state) = stream.get_ref();
    if state.protocol_version() != Some(case.version)
        || state.negotiated_cipher_suite().map(|suite| suite.suite()) != Some(case.cipher().0)
        || state
            .negotiated_key_exchange_group()
            .map(|group| group.name())
            != Some(case.group)
    {
        return Err(error(
            "negotiated protocol/cipher/group differs from the intended matrix cell",
        ));
    }
    let expected_kind =
        if case.version == ProtocolVersion::TLSv1_3 && case.group == NamedGroup::secp384r1 {
            HandshakeKind::FullWithHelloRetryRequest
        } else {
            HandshakeKind::Full
        };
    if state.handshake_kind() != Some(expected_kind) {
        return Err(error("unexpected full-handshake/HelloRetryRequest path"));
    }
    for round in 0..2 {
        let mut request: Vec<u8> = (0..1024)
            .map(|index| b'a' + ((index * 7 + round) % 26) as u8)
            .collect();
        let mut expected: Vec<u8> = request.iter().rev().copied().collect();
        request.push(b'\n');
        expected.push(b'\n');
        stream.write_all(&request).await?;
        stream.flush().await?;
        let mut response = vec![0; expected.len()];
        stream.read_exact(&mut response).await?;
        if response != expected {
            return Err(error(
                "independent peer response differs from the complete reversed synthetic input",
            ));
        }
    }
    stream.shutdown().await?;
    if stream.read(&mut [0; 1]).await? != 0 {
        return Err(error("unexpected application data after TLS shutdown"));
    }
    Ok(4096) // Two 1024-byte payloads in each direction, excluding line delimiters.
}

async fn run_case(
    binary: &Path,
    directory: &WorkingDirectory,
    case: Case,
    total_end: Instant,
) -> io::Result<usize> {
    if total_end.saturating_duration_since(Instant::now()) <= CLEANUP_LIMIT {
        return Err(error("TLS interoperability matrix total budget exhausted"));
    }
    let mut server = command(binary, directory);
    server
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
        ])
        .arg("-cert")
        .arg(case.certificate_path())
        .arg("-key")
        .arg(Path::new(FIXTURES).join(format!("{}-key.pem", case.certificate.name())))
        .arg("-groups")
        .arg(if case.group == NamedGroup::secp256r1 {
            "P-256"
        } else {
            "P-384"
        })
        .arg(if case.version == ProtocolVersion::TLSv1_3 {
            "-tls1_3"
        } else {
            "-tls1_2"
        })
        .arg(if case.version == ProtocolVersion::TLSv1_3 {
            "-ciphersuites"
        } else {
            "-cipher"
        })
        .arg(case.cipher().1);
    let mut child = server.spawn()?;
    let mut stdout = BufReader::new(child.stdout.take().unwrap().take(4096));
    let deadline = (Instant::now() + CASE_LIMIT).min(total_end - CLEANUP_LIMIT);
    let result = timeout_at(deadline, interact(case, &mut stdout))
        .await
        .map_err(|_| error("TLS interoperability case exceeded its deadline"))
        .and_then(|result| result);
    // Cleanup occurs outside the cancellable interaction, on success and error.
    let cleaned = reap(&mut child).await;
    drop(stdout);
    let mut diagnostics = Vec::new();
    if let Some(stderr) = child.stderr.take() {
        timeout(
            CLEANUP_LIMIT,
            stderr.take(8193).read_to_end(&mut diagnostics),
        )
        .await
        .map_err(|_| error("OpenSSL diagnostic pipe did not close"))??;
    }
    cleaned?;
    if diagnostics.len() > 8192 {
        return Err(error("OpenSSL diagnostics exceeded the per-case limit"));
    }
    if let Err(failure) = &result {
        eprintln!("independent TLS case {case:?} failed: {failure}; public synthetic server diagnostics: {}", String::from_utf8_lossy(&diagnostics));
    }
    result
}

#[tokio::test]
#[ignore = "requires explicit OPENSSL_BIN and synthetic loopback subprocess permission; no product dependency"]
async fn openssl_production_client_matrix_and_certificate_rejections() -> io::Result<()> {
    let binary = PathBuf::from(
        std::env::var_os("OPENSSL_BIN")
            .ok_or_else(|| error("set OPENSSL_BIN explicitly to OpenSSL 3.x (3.6.3 verified)"))?,
    );
    if !binary.is_absolute() || !binary.is_file() {
        return Err(error(
            "OPENSSL_BIN must be an absolute executable file path",
        ));
    }
    let directory = WorkingDirectory::new()?;
    let working_path = directory.0.clone();
    let started = Instant::now();
    let total_end = started + TOTAL_LIMIT;
    eprintln!(
        "independent TLS peer: {}",
        version(&binary, &directory).await?.trim()
    );
    let mut positive = 0;
    let mut negative = 0;
    let mut payload_bytes = 0;
    for version in [ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3] {
        for certificate in [Certificate::Rsa, Certificate::Ecdsa] {
            for group in [NamedGroup::secp256r1, NamedGroup::secp384r1] {
                for aead in 0..3 {
                    let case = Case {
                        version,
                        certificate,
                        group,
                        aead,
                        negative: None,
                    };
                    payload_bytes += run_case(&binary, &directory, case, total_end).await?;
                    positive += 1;
                    eprintln!(
                        "TLS interoperability pass: {case:?}, cipher={:?}",
                        case.cipher().0
                    );
                }
            }
        }
        for rejection in [
            Negative::WrongName,
            Negative::Untrusted,
            Negative::Expired,
            Negative::WrongEku,
        ] {
            let case = Case {
                version,
                certificate: Certificate::Ecdsa,
                group: NamedGroup::secp256r1,
                aead: 0,
                negative: Some(rejection),
            };
            payload_bytes += run_case(&binary, &directory, case, total_end).await?;
            negative += 1;
            eprintln!("TLS certificate rejection pass: {version:?} {rejection:?}");
        }
    }
    drop(directory);
    assert!(
        !working_path.exists(),
        "test working directory was not removed"
    );
    assert_eq!((positive, negative, payload_bytes), (24, 8, 98_304));
    assert!(started.elapsed() < TOTAL_LIMIT);
    eprintln!("TLS independent matrix: 24 positive, 8 exact certificate rejections; 98304 bidirectional payload bytes; 32 server children reaped; temporary directory removed; {:.3}s", started.elapsed().as_secs_f64());
    Ok(())
}
