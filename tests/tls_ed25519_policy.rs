//! Public synthetic Ed25519 policy regressions through the production provider.
//! Primitive acceptance is not evidence of a complete TLS or PKI bypass.

use rustls::{
    pki_types::{alg_id, SignatureVerificationAlgorithm},
    SignatureScheme,
};

fn production_algorithms() -> [&'static dyn SignatureVerificationAlgorithm; 2] {
    let config = gp_proxy::tls::client_config(None).unwrap();
    let algorithms = &config.crypto_provider().signature_verification_algorithms;
    let certificates: Vec<_> = algorithms
        .all
        .iter()
        .copied()
        .filter(|algorithm| {
            algorithm.public_key_alg_id() == alg_id::ED25519
                && algorithm.signature_alg_id() == alg_id::ED25519
        })
        .collect();
    assert_eq!(certificates.len(), 1);
    let handshakes: Vec<_> = algorithms
        .mapping
        .iter()
        .filter(|(scheme, _)| *scheme == SignatureScheme::ED25519)
        .collect();
    assert_eq!(handshakes.len(), 1);
    assert_eq!(handshakes[0].1.len(), 1);
    [certificates[0], handshakes[0].1[0]]
}

#[test]
fn weak_ed25519_identity_key_is_rejected_in_both_production_tables() {
    // Compressed Edwards identity A = R = (0, 1), scalar S = 0. The ordinary
    // equation accepts this same signature for arbitrary messages; strict
    // verification additionally rejects the small-order public key and R.
    let mut key = [0u8; 32];
    key[0] = 1;
    let mut signature = [0u8; 64];
    signature[0] = 1;
    let messages: [&[u8]; 2] = [b"synthetic certificate bytes", b"different TLS transcript"];

    // The former backend's acceptance was historical failure evidence. The
    // current provider must satisfy the policy without depending on that
    // backend or assuming another provider accepts the same invalid input.
    let mut accepted = 0;
    for (index, algorithm) in production_algorithms().into_iter().enumerate() {
        for (message_index, message) in messages.into_iter().enumerate() {
            let result = algorithm.verify_signature(&key, message, &signature);
            eprintln!(
                "public synthetic Ed25519 identity: table={index} message={message_index} accepted={}",
                result.is_ok()
            );
            accepted += usize::from(result.is_ok());
        }
    }
    assert_eq!(
        accepted, 0,
        "production must reject all four weak-key cases"
    );
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(digits, 16).unwrap()
        })
        .collect()
}

// RFC 8032 section 7.1, tests 1, 2 and 3. Public fixed test data, no real keys.
// https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1
const RFC8032: [(&str, &str, &str); 3] = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
    ),
    (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        concat!(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ),
    ),
];

#[test]
fn rfc8032_signatures_remain_valid_and_tampering_is_rejected() {
    for algorithm in production_algorithms() {
        for (key, message, signature) in RFC8032 {
            let key = hex(key);
            let message = hex(message);
            let signature = hex(signature);
            assert!(algorithm
                .verify_signature(&key, &message, &signature)
                .is_ok());
            let mut wrong_message = message.clone();
            wrong_message.push(0);
            assert!(algorithm
                .verify_signature(&key, &wrong_message, &signature)
                .is_err());
            for index in [0, 31, 32, 63] {
                let mut bad = signature.clone();
                bad[index] ^= 1;
                assert!(algorithm.verify_signature(&key, &message, &bad).is_err());
            }
        }
    }
}

#[test]
fn ed25519_size_and_scalar_boundaries_fail_without_panicking() {
    let (key, message, signature) = RFC8032[0];
    let key = hex(key);
    let message = hex(message);
    let signature = hex(signature);
    for algorithm in production_algorithms() {
        for size in [0, 1, 31, 33, 8192] {
            assert!(algorithm
                .verify_signature(&vec![0; size], &message, &signature)
                .is_err());
        }
        for size in [0, 1, 63, 65, 8192] {
            assert!(algorithm
                .verify_signature(&key, &message, &vec![0; size])
                .is_err());
        }
        // S must be below the Ed25519 subgroup order L, not merely 32 bytes.
        // Exact L is rejected rather than reduced modulo L by the verifier.
        let mut noncanonical = signature.clone();
        noncanonical[32..].copy_from_slice(&hex(
            "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        ));
        assert!(algorithm
            .verify_signature(&key, &message, &noncanonical)
            .is_err());
        // Test 1's valid S plus L has the same value modulo L. A verifier
        // silently reducing S would incorrectly accept this mutated signature.
        noncanonical[32..].copy_from_slice(&hex(
            "4c8c7872aa064e049dbb3013fbf29380d25bf5f0595bbe24655141438e7a101b",
        ));
        assert!(algorithm
            .verify_signature(&key, &message, &noncanonical)
            .is_err());
        noncanonical[32..].fill(0xff);
        assert!(algorithm
            .verify_signature(&key, &message, &noncanonical)
            .is_err());
    }
}
