use rustls::pki_types::{pem::PemObject, CertificateDer};
use std::{
    io::{self, Read},
    path::Path,
    sync::Arc,
};

mod provider;
use provider::client_provider;

#[cfg(test)]
mod record_limits;

const MAX_CA_FILE_BYTES: usize = crate::local_file::PUBLIC_MAX_BYTES;
const MAX_CA_CERTIFICATES: usize = 256;

/// TLS uses rustls; only the selected AWS-LC cryptographic primitives use C/assembly.
pub fn client_config(extra_ca: Option<&Path>) -> io::Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = extra_ca {
        let encoded =
            crate::local_file::read(path, crate::local_file::Access::Public).map_err(|error| {
                io::Error::new(error.kind(), format!("CA certificate file: {error}"))
            })?;
        let certs = read_ca_certificates(&encoded[..])?;
        for cert in certs {
            roots.add(cert).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid CA certificate")
            })?;
        }
    }
    let provider = Arc::new(client_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn read_ca_certificates(reader: impl Read) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut encoded = Vec::new();
    reader
        .take(MAX_CA_FILE_BYTES as u64 + 1)
        .read_to_end(&mut encoded)
        .map_err(|error| io::Error::new(error.kind(), "could not read CA certificate file"))?;
    if encoded.len() > MAX_CA_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CA certificate file exceeds size limit",
        ));
    }
    let mut certificates = Vec::new();
    for certificate in CertificateDer::pem_slice_iter(&encoded) {
        // PEM errors can contain the original input line. Do not attach them
        // to the public error chain or accidentally print private CA material.
        let certificate = certificate.map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid CA certificate PEM")
        })?;
        if certificates.len() == MAX_CA_CERTIFICATES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many CA certificates",
            ));
        }
        certificates.push(certificate);
    }
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CA file has no PEM certificates",
        ));
    }
    Ok(certificates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{
        pki_types::{PrivateKeyDer, ServerName},
        NamedGroup,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::{timeout, Duration},
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    fn fixture_ca() -> &'static Path {
        Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/gp/testdata/localhost-cert.pem"
        ))
    }

    fn fixture_server(
        version: &'static rustls::SupportedProtocolVersion,
        group: NamedGroup,
    ) -> Arc<rustls::ServerConfig> {
        let certs =
            CertificateDer::pem_slice_iter(include_bytes!("gp/testdata/localhost-cert.pem"))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key =
            PrivateKeyDer::from_pem_slice(include_bytes!("gp/testdata/localhost-key.pem")).unwrap();
        let mut provider = client_provider();
        provider
            .kx_groups
            .retain(|candidate| candidate.name() == group);
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[version])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap(),
        )
    }

    #[test]
    fn production_provider_excludes_unvalidated_key_exchange_groups() {
        let config = client_config(None).unwrap();
        assert!(!config.enable_secret_extraction);
        assert!(!config.enable_early_data);
        let provider = config.crypto_provider();
        let names: Vec<_> = provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect();
        assert_eq!(names, [NamedGroup::secp256r1, NamedGroup::secp384r1]);
        for group in &provider.kx_groups {
            // Invalid, off-curve peer data must return an error without panicking.
            assert!(group.start().unwrap().complete(&[0u8; 32]).is_err());
            assert!(group.start().unwrap().complete(&[0u8; 65]).is_err());
        }
    }

    #[test]
    fn custom_ca_input_is_bounded_and_errors_do_not_include_pem_content() {
        let error =
            read_ca_certificates(&b"-----BEGIN CERTIFICATE secret-marker\n"[..]).unwrap_err();
        assert!(!format!("{error:?}").contains("secret-marker"));
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(read_ca_certificates(&b""[..]).is_err());
        assert!(read_ca_certificates(io::repeat(b'A').take(MAX_CA_FILE_BYTES as u64 + 1)).is_err());
        let fixture = include_bytes!("gp/testdata/localhost-cert.pem");
        assert_eq!(read_ca_certificates(&fixture[..]).unwrap().len(), 1);
        assert!(read_ca_certificates(&fixture.repeat(MAX_CA_CERTIFICATES + 1)[..]).is_err());
    }

    #[tokio::test]
    async fn production_client_completes_tls12_and_tls13_with_both_groups() {
        timeout(Duration::from_secs(10), async {
            for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
                for group in [NamedGroup::secp256r1, NamedGroup::secp384r1] {
                    let server_config = fixture_server(version, group);
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let address = listener.local_addr().unwrap();
                    let server = tokio::spawn(async move {
                        let (tcp, _) = listener.accept().await.unwrap();
                        let mut tls = TlsAcceptor::from(server_config).accept(tcp).await.unwrap();
                        let mut request = [0; 4];
                        tls.read_exact(&mut request).await.unwrap();
                        assert_eq!(&request, b"ping");
                        tls.write_all(b"pong").await.unwrap();
                        tls.shutdown().await.unwrap();
                    });
                    let config = client_config(Some(fixture_ca())).unwrap();
                    let tcp = TcpStream::connect(address).await.unwrap();
                    let name = ServerName::try_from("localhost".to_owned()).unwrap();
                    let mut tls = TlsConnector::from(config).connect(name, tcp).await.unwrap();
                    assert_eq!(tls.get_ref().1.protocol_version(), Some(version.version));
                    tls.write_all(b"ping").await.unwrap();
                    let mut response = [0; 4];
                    tls.read_exact(&mut response).await.unwrap();
                    assert_eq!(&response, b"pong");
                    server.await.unwrap();
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn production_client_rejects_untrusted_certificate_and_wrong_hostname() {
        timeout(Duration::from_secs(10), async {
            for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
                for (ca, hostname) in [(None, "localhost"), (Some(fixture_ca()), "wrong.invalid")] {
                    let server_config = fixture_server(version, NamedGroup::secp256r1);
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let address = listener.local_addr().unwrap();
                    let server = tokio::spawn(async move {
                        let (tcp, _) = listener.accept().await.unwrap();
                        assert!(TlsAcceptor::from(server_config).accept(tcp).await.is_err());
                    });
                    let tcp = TcpStream::connect(address).await.unwrap();
                    let name = ServerName::try_from(hostname.to_owned()).unwrap();
                    let result = TlsConnector::from(client_config(ca).unwrap())
                        .connect(name, tcp)
                        .await;
                    assert!(result.is_err());
                    server.await.unwrap();
                }
            }
        })
        .await
        .unwrap();
    }
}
