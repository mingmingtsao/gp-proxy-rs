# Public synthetic TLS interoperability fixtures

Every private key in this directory is deliberately public test material. Never
trust these CAs or use these keys outside the isolated test. No user or corporate
credential is present. The normal product and preview archive do not load them.

`rsa` is a 2048-bit RSA leaf under a separate 2048-bit RSA CA. `ecdsa` is a P-384
leaf under a P-256 ECDSA CA. Both CAs and valid leaves have fixed UTC validity
2020-01-01 through 2120-01-01; the negative expired leaf is valid only from
2019-01-01 through 2020-01-01. `wrong-eku` has only clientAuth rather than
serverAuth. Both negative leaves reuse the public ECDSA leaf key and CA and have
the same localhost DNS SAN, avoiding an unrelated hostname/issuer failure.

Generate certificates from the already committed public keys:

```sh
python3 tests/support/tls-interop/generate.py \
  --openssl /opt/homebrew/opt/openssl@3/bin/openssl
```

The generator needs OpenSSL >=3.5 for explicit `req -not_before/-not_after`.
The initial generation additionally used `--new-keys`; that flag explicitly
replaces only the four named synthetic keys here. It never reads other key paths.
Validity, extensions, subjects and serials are fixed. Key generation and ECDSA
signatures use randomness, so regeneration is a reproducible procedure, not a
promise of byte-for-byte identical certificates. No system clock is changed.

Run the opt-in development test (no OpenSSL product dependency):

```sh
OPENSSL_BIN=/opt/homebrew/opt/openssl@3/bin/openssl \
  cargo test --locked --test tls_interop_openssl -- --ignored --nocapture
```

Only numeric loopback servers are started. A single test has a 120-second total
budget and short per-case bounds; every server is killed if necessary and waited
for, and its private temporary working directory is removed. Only these named
fixture PEMs are used. The ordinary test suite keeps the external-tool test
ignored; absence of a suitable explicit executable is an error when opted in.
