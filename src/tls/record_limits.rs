//! Exercise rustls's record-limit handling with the production primitives.
//! All traffic and public synthetic credentials stay in memory.

use std::{
    io::{Cursor, Read, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, LazyLock,
    },
};

use rustls::{
    crypto::{
        cipher::{
            AeadKey, Iv, MessageDecrypter, MessageEncrypter, Tls13AeadAlgorithm,
            UnsupportedOperationError,
        },
        CipherSuiteCommon,
    },
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
    CipherSuite, ClientConfig, ClientConnection, Connection, ConnectionTrafficSecrets,
    RootCertStore, ServerConfig, ServerConnection, SupportedCipherSuite, SupportedProtocolVersion,
    Tls12CipherSuite, Tls13CipherSuite,
};

const TEST_RECORD_LIMIT: u64 = 8;

fn production_suite(name: CipherSuite) -> SupportedCipherSuite {
    super::client_provider()
        .cipher_suites
        .into_iter()
        .find(|suite| suite.suite() == name)
        .expect("production suite must remain available")
}

static PRODUCTION_TLS13: LazyLock<&'static Tls13CipherSuite> = LazyLock::new(|| {
    let SupportedCipherSuite::Tls13(suite) =
        production_suite(CipherSuite::TLS13_AES_128_GCM_SHA256)
    else {
        panic!("TLS 1.3 suite expected");
    };
    suite
});

// Count encryption-key installations, without storing or logging key material.
// Merely completing many transfers would also pass if a record limit were ignored.
static TLS13_KEY_INSTALLATIONS: AtomicUsize = AtomicUsize::new(0);
struct CountKeyInstallations;

impl Tls13AeadAlgorithm for CountKeyInstallations {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        TLS13_KEY_INSTALLATIONS.fetch_add(1, Ordering::Relaxed);
        PRODUCTION_TLS13.aead_alg.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        PRODUCTION_TLS13.aead_alg.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        PRODUCTION_TLS13.aead_alg.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        PRODUCTION_TLS13.aead_alg.extract_keys(key, iv)
    }
}

fn low_limit_common(common: &CipherSuiteCommon) -> CipherSuiteCommon {
    assert_eq!(common.confidentiality_limit, 1 << 24);
    CipherSuiteCommon {
        suite: common.suite,
        hash_provider: common.hash_provider,
        confidentiality_limit: TEST_RECORD_LIMIT,
    }
}

static LOW_LIMIT_TLS13: LazyLock<Tls13CipherSuite> = LazyLock::new(|| Tls13CipherSuite {
    common: low_limit_common(&PRODUCTION_TLS13.common),
    hkdf_provider: PRODUCTION_TLS13.hkdf_provider,
    aead_alg: &CountKeyInstallations,
    quic: None,
});

static LOW_LIMIT_TLS12: LazyLock<Tls12CipherSuite> = LazyLock::new(|| {
    let SupportedCipherSuite::Tls12(suite) =
        production_suite(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
    else {
        panic!("TLS 1.2 suite expected");
    };
    Tls12CipherSuite {
        common: low_limit_common(&suite.common),
        prf_provider: suite.prf_provider,
        kx: suite.kx,
        sign: suite.sign,
        aead_alg: suite.aead_alg,
    }
});

fn connection_pair(version: &'static SupportedProtocolVersion) -> (Connection, Connection) {
    let mut provider = super::client_provider();
    provider.cipher_suites = vec![if version == &rustls::version::TLS13 {
        SupportedCipherSuite::Tls13(&LOW_LIMIT_TLS13)
    } else {
        SupportedCipherSuite::Tls12(&LOW_LIMIT_TLS12)
    }];
    let provider = Arc::new(provider);
    let certs = CertificateDer::pem_slice_iter(include_bytes!("../gp/testdata/localhost-cert.pem"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(include_bytes!("../gp/testdata/localhost-key.pem")).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let client_config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let server = ServerConnection::new(Arc::new(server_config)).unwrap();
    let (mut client, mut server) = (Connection::Client(client), Connection::Server(server));
    assert_eq!(pump(&mut client, &mut server), (false, false));
    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
    assert_eq!(client.protocol_version(), Some(version.version));
    (client, server)
}

fn transfer(sender: &mut Connection, receiver: &mut Connection) -> bool {
    let mut encrypted = Vec::new();
    while sender.wants_write() {
        assert!(sender.write_tls(&mut encrypted).unwrap() > 0);
    }
    let mut incoming = Cursor::new(encrypted.as_slice());
    let mut peer_closed = false;
    while (incoming.position() as usize) < encrypted.len() {
        assert!(receiver.read_tls(&mut incoming).unwrap() > 0);
        peer_closed |= receiver.process_new_packets().unwrap().peer_has_closed();
    }
    peer_closed
}

/// Returns whether client/server respectively received a clean close_notify.
fn pump(client: &mut Connection, server: &mut Connection) -> (bool, bool) {
    let mut closed = (false, false);
    for _ in 0..32 {
        if !client.wants_write() && !server.wants_write() {
            return closed;
        }
        closed.1 |= transfer(client, server);
        closed.0 |= transfer(server, client);
    }
    panic!("bounded in-memory TLS exchange failed to settle");
}

#[test]
fn tls13_updates_keys_at_record_limit_and_preserves_bidirectional_data() {
    let (mut client, mut server) = connection_pair(&rustls::version::TLS13);
    let initial_keys = TLS13_KEY_INSTALLATIONS.load(Ordering::Relaxed);
    // Each write is pumped separately, so these are independent TLS records.
    for round in 0..32u8 {
        client.writer().write_all(&[round, 0xc1]).unwrap();
        assert_eq!(pump(&mut client, &mut server), (false, false));
        let mut received = [0; 2];
        server.reader().read_exact(&mut received).unwrap();
        assert_eq!(received, [round, 0xc1]);

        server.writer().write_all(&[round, 0x51]).unwrap();
        assert_eq!(pump(&mut client, &mut server), (false, false));
        client.reader().read_exact(&mut received).unwrap();
        assert_eq!(received, [round, 0x51]);
    }
    assert!(
        TLS13_KEY_INSTALLATIONS.load(Ordering::Relaxed) >= initial_keys + 4,
        "traffic must install fresh encryption keys after the handshake"
    );
}

#[test]
fn tls12_closes_at_record_limit_instead_of_continuing_application_data() {
    let (mut client, mut server) = connection_pair(&rustls::version::TLS12);
    let mut delivered = 0;
    let mut closed = false;
    for round in 0..32u8 {
        let written = client.writer().write(&[round]).unwrap();
        let (_, server_closed) = pump(&mut client, &mut server);
        if server_closed {
            closed = true;
            // The record which exhausted the limit must not reach the peer.
            // rustls's buffered Writer may report consumed bytes even when its
            // record layer closes; assert the observed wire behavior instead.
            assert_eq!(server.reader().read(&mut [0]).unwrap(), 0);
            break;
        }
        assert_eq!(written, 1);
        let mut received = [0];
        server.reader().read_exact(&mut received).unwrap();
        assert_eq!(received, [round]);
        delivered += 1;
    }
    assert!(closed, "TLS 1.2 must send close_notify at its key limit");
    assert!((1..=TEST_RECORD_LIMIT).contains(&delivered));
    client.writer().write_all(b"after close").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(server.reader().read(&mut [0]).unwrap(), 0);
}
