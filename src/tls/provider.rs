//! Select the rustls AWS-LC provider and preserve application TLS policy.
//! TLS framing and certificate validation remain in rustls/webpki. AWS-LC is
//! the explicit C/assembly exception for cryptographic primitives; Ed25519
//! retains the existing strict dalek verifier for weak-key rejection.

use rustls::{
    crypto::{aws_lc_rs, CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{alg_id, SignatureVerificationAlgorithm},
    SignatureScheme,
};
use std::sync::LazyLock;

mod ed25519;

static UPSTREAM: LazyLock<CryptoProvider> = LazyLock::new(aws_lc_rs::default_provider);

pub(super) fn client_provider() -> CryptoProvider {
    let mut provider = UPSTREAM.clone();
    // Preserve supported groups; do not silently add PQ or X25519 negotiation.
    provider.kx_groups = vec![
        aws_lc_rs::kx_group::SECP256R1,
        aws_lc_rs::kx_group::SECP384R1,
    ];
    provider.signature_verification_algorithms = WebPkiSupportedAlgorithms {
        all: &CERTIFICATE_ALGORITHMS,
        mapping: &HANDSHAKE_ALGORITHMS,
    };
    provider
}

static CERTIFICATE_ALGORITHMS: LazyLock<Vec<&'static dyn SignatureVerificationAlgorithm>> =
    LazyLock::new(|| {
        UPSTREAM
            .signature_verification_algorithms
            .all
            .iter()
            .copied()
            .filter(|algorithm| {
                ![alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87]
                    .contains(&algorithm.signature_alg_id())
            })
            .map(|algorithm| {
                if algorithm.public_key_alg_id() == alg_id::ED25519
                    && algorithm.signature_alg_id() == alg_id::ED25519
                {
                    &ed25519::STRICT as &dyn SignatureVerificationAlgorithm
                } else {
                    algorithm
                }
            })
            .collect()
    });

type SignatureMapping = (
    SignatureScheme,
    &'static [&'static dyn SignatureVerificationAlgorithm],
);

static HANDSHAKE_ALGORITHMS: LazyLock<Vec<SignatureMapping>> = LazyLock::new(|| {
    UPSTREAM
        .signature_verification_algorithms
        .mapping
        .iter()
        .copied()
        .filter(|(scheme, _)| {
            !matches!(
                scheme,
                SignatureScheme::ML_DSA_44
                    | SignatureScheme::ML_DSA_65
                    | SignatureScheme::ML_DSA_87
            )
        })
        .map(|(scheme, algorithms)| {
            if scheme == SignatureScheme::ED25519 {
                (scheme, &ed25519::ALGORITHMS[..])
            } else {
                (scheme, algorithms)
            }
        })
        .collect()
});

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{NamedGroup, SupportedCipherSuite};

    const MESSAGE: &[u8] = b"gp-proxy public synthetic RSA policy regression";
    const WEAK_KEY: &[u8] = include_bytes!("testdata/rsa-1024.der");
    const STRONG_KEY: &[u8] = include_bytes!("testdata/rsa-2048.der");
    type RsaVector = (SignatureScheme, Option<&'static [u8]>, &'static [u8]);
    const RSA_VECTORS: &[RsaVector] = &[
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            Some(include_bytes!("testdata/rsa-1024-pkcs1-sha256.sig")),
            include_bytes!("testdata/rsa-2048-pkcs1-sha256.sig"),
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            Some(include_bytes!("testdata/rsa-1024-pkcs1-sha384.sig")),
            include_bytes!("testdata/rsa-2048-pkcs1-sha384.sig"),
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            None,
            include_bytes!("testdata/rsa-2048-pkcs1-sha512.sig"),
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            Some(include_bytes!("testdata/rsa-1024-pss-sha256.sig")),
            include_bytes!("testdata/rsa-2048-pss-sha256.sig"),
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            Some(include_bytes!("testdata/rsa-1024-pss-sha384.sig")),
            include_bytes!("testdata/rsa-2048-pss-sha384.sig"),
        ),
        (
            SignatureScheme::RSA_PSS_SHA512,
            None,
            include_bytes!("testdata/rsa-2048-pss-sha512.sig"),
        ),
    ];

    #[test]
    fn rsa_key_bounds_apply_to_certificates_and_handshakes() {
        let provider = client_provider();
        for &(scheme, weak_signature, strong_signature) in RSA_VECTORS {
            let handshake_algorithms = provider
                .signature_verification_algorithms
                .mapping
                .iter()
                .find(|(candidate, _)| *candidate == scheme)
                .unwrap()
                .1;
            assert_eq!(handshake_algorithms.len(), 1);
            let handshake_algorithm = handshake_algorithms[0];
            let certificate_algorithm = provider
                .signature_verification_algorithms
                .all
                .iter()
                .find(|algorithm| {
                    algorithm.public_key_alg_id() == handshake_algorithm.public_key_alg_id()
                        && algorithm.signature_alg_id() == handshake_algorithm.signature_alg_id()
                })
                .unwrap();
            for algorithm in [*certificate_algorithm, handshake_algorithm] {
                assert!(algorithm
                    .verify_signature(STRONG_KEY, MESSAGE, strong_signature)
                    .is_ok());
                assert!(algorithm
                    .verify_signature(STRONG_KEY, b"tampered", strong_signature)
                    .is_err());
                for malformed in [&[][..], &[0u8; 32][..], &[0u8; 2049][..]] {
                    assert!(algorithm
                        .verify_signature(malformed, MESSAGE, strong_signature)
                        .is_err());
                }
                if let Some(signature) = weak_signature {
                    assert!(algorithm
                        .verify_signature(WEAK_KEY, MESSAGE, signature)
                        .is_err());
                }
            }
        }
    }

    #[test]
    fn all_aes_gcm_suites_have_a_finite_confidentiality_limit() {
        let provider = client_provider();
        let mut aes_suites = 0;
        for suite in provider.cipher_suites {
            let common = match suite {
                SupportedCipherSuite::Tls12(suite) => &suite.common,
                SupportedCipherSuite::Tls13(suite) => &suite.common,
            };
            match common.suite {
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
                    assert_eq!(common.confidentiality_limit, u64::MAX);
                }
                _ => {
                    aes_suites += 1;
                    assert_eq!(common.confidentiality_limit, 1 << 24);
                }
            }
        }
        assert_eq!(aes_suites, 6);
    }

    #[test]
    fn native_x25519_rejects_low_order_peer_and_is_not_enabled() {
        let group = UPSTREAM
            .kx_groups
            .iter()
            .find(|group| group.name() == NamedGroup::X25519)
            .unwrap();
        assert!(group.start().unwrap().complete(&[0; 32]).is_err());
        assert!(client_provider()
            .kx_groups
            .iter()
            .all(|group| group.name() != NamedGroup::X25519));
    }

    #[test]
    fn migration_does_not_enable_post_quantum_signatures() {
        let provider = client_provider();
        assert!(provider
            .signature_verification_algorithms
            .all
            .iter()
            .all(|algorithm| {
                ![alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87]
                    .contains(&algorithm.signature_alg_id())
            }));
        assert!(provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .all(|(scheme, _)| {
                !matches!(
                    scheme,
                    SignatureScheme::ML_DSA_44
                        | SignatureScheme::ML_DSA_65
                        | SignatureScheme::ML_DSA_87
                )
            }));
    }
}
