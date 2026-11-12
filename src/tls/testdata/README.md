# Public RSA verification vectors

These DER files contain **public keys only**. The signatures cover the literal
message `gp-proxy public synthetic RSA policy regression`. Random synthetic RSA
keys were generated in a temporary Rust helper with `rsa 0.10.0`; private keys
remained in the helper's memory and were not written to disk.

The vectors exercise PKCS#1 v1.5 and PSS verification using SHA-256/384/512.
1024-bit signatures are deliberately weak inputs that the application's
certificate and handshake verification policy must reject. The selected AWS-LC
provider enforces the 2048-bit minimum. PSS/SHA-512 with its digest-length salt does not fit a 1024-bit key,
so the SHA-512 positive cases use only the 2048-bit key.

These are test fixtures, never trust anchors or credentials. Regenerating with
new random keys changes bytes but not the properties checked by the tests.
