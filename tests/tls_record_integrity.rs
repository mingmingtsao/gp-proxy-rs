//! Record rejection through the production client configuration, entirely in
//! memory. The synthetic server uses the same provider: this is not independent
//! crypto interoperability evidence (see tls_interop_openssl for that).
use gp_proxy::tls;
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
    CipherSuite, ClientConnection, Connection, ServerConfig, ServerConnection,
    SupportedProtocolVersion,
};
use std::{
    io::{self, Cursor, Read, Write},
    path::Path,
    sync::Arc,
};

const MAX_WIRE_BYTES: usize = 64 * 1024;
const MAX_IO_STEPS: usize = MAX_WIRE_BYTES;
const PREFIX: &[u8] = b"previously authenticated application record";
const PAYLOAD: &[u8] = b"this record must be authenticated in full before any of its bytes are delivered; split transport reads must not expose a prefix of unauthenticated plaintext";

#[derive(Clone, Copy, Debug)]
struct Cell {
    version: &'static SupportedProtocolVersion,
    suite: CipherSuite,
    from_client: bool,
}

fn cells() -> impl Iterator<Item = Cell> {
    [
        (
            &rustls::version::TLS12,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ),
        (
            &rustls::version::TLS12,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ),
        (
            &rustls::version::TLS12,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ),
        (
            &rustls::version::TLS13,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
        ),
        (
            &rustls::version::TLS13,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ),
        (
            &rustls::version::TLS13,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        ),
    ]
    .into_iter()
    .flat_map(|(version, suite)| {
        [true, false].map(|from_client| Cell {
            version,
            suite,
            from_client,
        })
    })
}

/// Deliberately exercise short writes, including TLS header/record boundaries.
#[derive(Default)]
struct Wire(Vec<u8>);

impl Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(127);
        if self.0.len() + count > MAX_WIRE_BYTES {
            return Err(io::Error::other("synthetic TLS wire limit exceeded"));
        }
        self.0.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn take_wire(sender: &mut Connection) -> Vec<u8> {
    let mut wire = Wire::default();
    for _ in 0..MAX_IO_STEPS {
        if !sender.wants_write() {
            return wire.0;
        }
        assert!(sender.write_tls(&mut wire).unwrap() > 0);
    }
    panic!("bounded TLS writer did not settle");
}

fn drain_plaintext(receiver: &mut Connection, plaintext: &mut Vec<u8>) {
    let mut buffer = [0; 29];
    for _ in 0..MAX_IO_STEPS {
        match receiver.reader().read(&mut buffer) {
            Ok(0) => return,
            Ok(count) => {
                assert!(plaintext.len() + count <= MAX_WIRE_BYTES);
                plaintext.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
            Err(error) => panic!("unexpected plaintext error before transport EOF: {error}"),
        }
    }
    panic!("bounded TLS plaintext reader did not settle");
}

/// Process every nonempty transport fragment, then drain even after a TLS error:
/// valid earlier records can remain buffered when a subsequent record is bad.
fn feed(
    receiver: &mut Connection,
    wire: &[u8],
    plaintext: &mut Vec<u8>,
    fragmented: bool,
) -> Result<(), rustls::Error> {
    assert!(wire.len() <= MAX_WIRE_BYTES);
    let mut offset = 0;
    for step in 0..MAX_IO_STEPS {
        if offset == wire.len() {
            return Ok(());
        }
        let count = if fragmented {
            [1, 2, 7, 3, 31][step % 5].min(wire.len() - offset)
        } else {
            wire.len() - offset
        };
        let mut input = Cursor::new(&wire[offset..offset + count]);
        let read = receiver.read_tls(&mut input).unwrap();
        assert!(read > 0 && read <= count, "TLS input must make progress");
        offset += read;
        let processed = receiver.process_new_packets();
        drain_plaintext(receiver, plaintext);
        processed?;
    }
    panic!("bounded TLS reader did not settle");
}

fn pair(cell: Cell) -> (Connection, Connection) {
    let client_config = tls::client_config(Some(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/support/tls-interop/ca-ecdsa-cert.pem"
    ))))
    .unwrap();
    // Preserve all production client settings and primitives. Restriction is
    // server-side only, making each negotiated matrix cell observable.
    let mut provider = client_config.crypto_provider().as_ref().clone();
    provider
        .cipher_suites
        .retain(|suite| suite.suite() == cell.suite);
    assert_eq!(provider.cipher_suites.len(), 1);
    let certs =
        CertificateDer::pem_slice_iter(include_bytes!("support/tls-interop/ecdsa-cert.pem"))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(include_bytes!("support/tls-interop/ecdsa-key.pem")).unwrap();
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[cell.version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    // Avoid unrelated post-handshake tickets in captured application records.
    server_config.send_tls13_tickets = 0;
    let mut client = Connection::Client(
        ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap()).unwrap(),
    );
    let mut server = Connection::Server(ServerConnection::new(Arc::new(server_config)).unwrap());
    let mut plaintext = Vec::new();
    let mut settled = false;
    for _ in 0..32 {
        let incoming = take_wire(&mut client);
        feed(&mut server, &incoming, &mut plaintext, true).unwrap();
        let incoming = take_wire(&mut server);
        feed(&mut client, &incoming, &mut plaintext, true).unwrap();
        if !client.wants_write() && !server.wants_write() {
            settled = true;
            break;
        }
    }
    assert!(settled && plaintext.is_empty());
    for endpoint in [&client, &server] {
        assert!(!endpoint.is_handshaking());
        assert_eq!(endpoint.protocol_version(), Some(cell.version.version));
        assert_eq!(
            endpoint
                .negotiated_cipher_suite()
                .map(|suite| suite.suite()),
            Some(cell.suite)
        );
    }
    if cell.from_client {
        (client, server)
    } else {
        (server, client)
    }
}

fn record(sender: &mut Connection, plaintext: &[u8]) -> Vec<u8> {
    assert!(plaintext.len() < 1024);
    sender.writer().write_all(plaintext).unwrap();
    let wire = take_wire(sender);
    // Exactly one complete application-data record; never mutate a handshake,
    // ticket, explicit nonce, or a guessed offset spanning multiple records.
    assert!(wire.len() >= 5 + plaintext.len() + 16);
    assert_eq!(&wire[..3], &[23, 3, 3]);
    let body = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
    assert_eq!(wire.len(), 5 + body);
    wire
}

fn assert_rejected(
    receiver: &mut Connection,
    wire: &[u8],
    expected_plaintext: &[u8],
    fragmented: bool,
) {
    let mut delivered = Vec::new();
    assert_eq!(
        feed(receiver, wire, &mut delivered, fragmented).unwrap_err(),
        rustls::Error::DecryptError
    );
    assert_eq!(delivered, expected_plaintext);
    // The first authenticated-decryption failure remains terminal.
    assert_eq!(
        receiver.process_new_packets().unwrap_err(),
        rustls::Error::DecryptError
    );
    drain_plaintext(receiver, &mut delivered);
    assert_eq!(delivered, expected_plaintext);
}

#[test]
fn ciphertext_and_tag_tampering_never_deliver_the_bad_record() {
    let mut cases = 0;
    for cell in cells() {
        for tamper_tag in [false, true] {
            for fragmented in [false, true] {
                let (mut sender, mut receiver) = pair(cell);
                let mut wire = record(&mut sender, PREFIX);
                let mut bad = record(&mut sender, PAYLOAD);
                // Mid-body is past the TLS 1.2 AES-GCM explicit 8-byte nonce,
                // inside ciphertext for every tested suite. Last byte is tag.
                let offset = if tamper_tag {
                    bad.len() - 1
                } else {
                    5 + (bad.len() - 5) / 2
                };
                assert!(offset > 5 + 8);
                if !tamper_tag {
                    assert!(offset < bad.len() - 16);
                }
                bad[offset] ^= 1;
                wire.extend_from_slice(&bad);
                assert_rejected(&mut receiver, &wire, PREFIX, fragmented);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 48);
    eprintln!("TLS record integrity: 48 ciphertext/tag mutations rejected as DecryptError; valid prefix preserved; zero bad-record plaintext");
}

#[test]
fn replayed_record_is_not_delivered_twice() {
    let mut cases = 0;
    for cell in cells() {
        for fragmented in [false, true] {
            let (mut sender, mut receiver) = pair(cell);
            let wire = record(&mut sender, PAYLOAD);
            let mut delivered = Vec::new();
            feed(&mut receiver, &wire, &mut delivered, fragmented).unwrap();
            assert_eq!(delivered, PAYLOAD);
            assert_rejected(&mut receiver, &wire, b"", fragmented);
            cases += 1;
        }
    }
    assert_eq!(cases, 24);
    eprintln!("TLS record integrity: 24 replays rejected as DecryptError after exactly one original delivery");
}

#[test]
fn incomplete_record_or_missing_close_notify_is_unclean_eof() {
    let mut cases = 0;
    for cell in cells() {
        for cut in 0..4 {
            let (mut sender, mut receiver) = pair(cell);
            let mut wire = record(&mut sender, PREFIX);
            let incomplete = record(&mut sender, PAYLOAD);
            let length = match cut {
                0 => 0,                    // EOF at a complete record boundary.
                1 => 2,                    // Partial TLS header.
                2 => incomplete.len() / 2, // Partial encrypted body.
                3 => incomplete.len() - 1, // Missing final authentication-tag byte.
                _ => unreachable!(),
            };
            wire.extend_from_slice(&incomplete[..length]);
            let mut delivered = Vec::new();
            feed(&mut receiver, &wire, &mut delivered, true).unwrap();
            assert_eq!(delivered, PREFIX);
            assert_eq!(receiver.read_tls(&mut io::empty()).unwrap(), 0);
            // An incomplete record cannot yet be decrypted. The failure is
            // transport truncation, not a failed authentication tag.
            let state = receiver.process_new_packets().unwrap();
            assert!(!state.peer_has_closed());
            assert_eq!(state.plaintext_bytes_to_read(), 0);
            assert_eq!(
                receiver.reader().read(&mut [0; 1]).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert_eq!(delivered, PREFIX);
            cases += 1;
        }
    }
    assert_eq!(cases, 48);
    eprintln!("TLS record integrity: 48 record-boundary/header/body/tag truncations yield UnexpectedEof; zero incomplete-record plaintext");
}

#[test]
fn complete_records_and_close_notify_are_clean_eof() {
    let mut cases = 0;
    for cell in cells() {
        let (mut sender, mut receiver) = pair(cell);
        let mut wire = record(&mut sender, PREFIX);
        wire.extend_from_slice(&record(&mut sender, PAYLOAD));
        sender.send_close_notify();
        wire.extend_from_slice(&take_wire(&mut sender));
        let mut delivered = Vec::new();
        feed(&mut receiver, &wire, &mut delivered, true).unwrap();
        let mut expected = PREFIX.to_vec();
        expected.extend_from_slice(PAYLOAD);
        assert_eq!(delivered, expected);
        assert!(receiver.process_new_packets().unwrap().peer_has_closed());
        assert_eq!(receiver.reader().read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(receiver.read_tls(&mut io::empty()).unwrap(), 0);
        assert_eq!(receiver.reader().read(&mut [0; 1]).unwrap(), 0);
        cases += 1;
    }
    assert_eq!(cases, 12);
    eprintln!("TLS record integrity: 12 controls deliver both records and recognize clean close_notify EOF");
}
