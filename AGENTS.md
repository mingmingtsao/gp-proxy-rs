# gp-proxy-rs development

- Core VPN, network stack, and proxy code must remain Rust; no external OpenConnect process or FFI implementation of these components.
- TLS uses rustls with its AWS-LC provider. AWS-LC C/assembly cryptographic primitives via aws-lc-rs/aws-lc-sys are the explicit language exception; do not replace the Rust TLS protocol with libssl or add other crypto backends. Preserve the existing strict Ed25519 policy and explicit TLS configuration.
- Never create/open a virtual network interface or change OS routes, DNS, or firewall rules.
- Corporate TCP and DNS use only the current session's in-memory stack. Never add host-network fallback.
- Keep listeners on loopback. Do not log credentials, gateway response bodies, or cookie-bearing URLs.
- Preserve generation cancellation and bounded resources. New protocol behavior needs tests for malformed inputs and failure paths.
- Keep README and docs honest about real gateway validation, authentication limitations, and crypto-provider risk.
- Validate meaningful changes with `cargo test --locked`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo fmt --check`, and `python3 scripts/check-dependencies.py`.
- Never commit real session files, passwords, private CA material, or production captures. Files under `src/gp/testdata` and the explicitly allowlisted PEM fixtures under `tests/support/tls-interop` are deliberately public synthetic test keys only; never put actual CA or user keys in these directories.
- Do not inspect the user's real `.env` during agent work. Use synthetic fixtures for tests; only the application may load an explicitly selected credentials file, without printing its contents.
