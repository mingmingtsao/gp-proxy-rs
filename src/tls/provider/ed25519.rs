//! Reject weak Ed25519 keys and small-order R using the existing dalek policy.
//! This adapter does not implement a signature primitive or change TLS framing.

use rustls::pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
};

#[derive(Debug)]
pub(super) struct StrictEd25519;

impl SignatureVerificationAlgorithm for StrictEd25519 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        // Exact lengths are checked before the constant-size parsers. No peer
        // material is retained and every rejection has the same public error.
        let public_key = public_key.try_into().map_err(|_| InvalidSignature)?;
        let signature =
            ed25519_dalek::Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
        ed25519_dalek::VerifyingKey::from_bytes(public_key)
            .map_err(|_| InvalidSignature)?
            .verify_strict(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}

pub(super) static STRICT: StrictEd25519 = StrictEd25519;
pub(super) static ALGORITHMS: [&'static dyn SignatureVerificationAlgorithm; 1] = [&STRICT];
