These are public, synthetic localhost TLS test fixtures. The private key is
intentionally committed and MUST NOT be used for any deployed endpoint.

The certificate is P-256/SHA-256 with SAN `localhost`, leaf-only basic constraints,
and a long validity window for deterministic offline tests. Both peers in the test
use rustls with AWS-LC; the application does not use an OpenSSL TLS backend.
OpenSSL CLI was used once to produce these static fixtures.
