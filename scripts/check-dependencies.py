#!/usr/bin/env python3
"""Require the selected AWS-LC backend; reject other TLS and host-interface bindings.

AWS-LC's crypto primitives are the sole native-crypto exception. Ordinary OS
bindings and RustCrypto primitives are allowed. This checks the active Cargo
graph, not runtime cipher/group policy or arbitrary source behavior.
"""
import argparse
from pathlib import Path
import re
import subprocess


# Exact names, not substrings or a blanket ban on *-sys. Adding another native
# backend requires an explicit policy review, rather than silently broadening
# the AWS-LC exception. This known-package denylist is not a source-code audit.
FORBIDDEN_PACKAGES = frozenset({
    "ring", "aws-lc-fips-sys",
    "rustls-rustcrypto", "rustls-provider-rustcrypto-pq", "rustls-pure",
    "rustls-scytale", "rustls-graviola", "graviola",
    "rustls-openssl", "openssl", "openssl-sys", "openssl-src", "native-tls",
    "tokio-native-tls", "boring-rustls-provider", "boring", "boring-sys",
    "rustls-mbedtls-provider", "mbedtls", "mbedtls-sys", "mbedtls-sys-auto",
    "rustls-symcrypt", "symcrypt", "symcrypt-sys",
    "rustls-wolfcrypt-provider", "wolfcrypt", "wolfcrypt-sys", "wolfssl", "wolfssl-sys",
    "openconnect", "openconnect-sys", "libopenconnect", "libopenconnect-sys",
    "tun", "tun2", "tun-rs", "tun-tap", "tuntap", "tuntap-interface",
    "tokio-tun", "utun", "wintun", "wintun-bindings", "pcap", "pcap-sys",
})
REQUIRED_PACKAGES = frozenset({"rustls", "aws-lc-rs", "aws-lc-sys"})
RUSTLS_REQUIRED_FEATURES = frozenset({"std", "tls12", "aws_lc_rs"})
FORBIDDEN_FEATURES = {
    "rustls": frozenset({"ring", "fips", "prefer-post-quantum"}),
    "aws-lc-rs": frozenset({"fips"}),
    "aws-lc-sys": frozenset({"ssl", "fips"}),
    "smoltcp": frozenset({"phy-tuntap_interface", "phy-raw_socket"}),
}
PACKAGE_LINE = re.compile(
    r"(?P<name>[A-Za-z0-9_-]+) v(?P<version>[0-9][^ |]*)(?: [^|]+)?\|"
    r"(?P<features>[A-Za-z0-9_+.,-]*)(?: \(\*\))?"
)


def inspect_tree(tree):
    """Return policy/parse failures without combining different package instances."""
    seen = set()
    violations = set()
    for number, line in enumerate(tree.splitlines(), 1):
        match = PACKAGE_LINE.fullmatch(line)
        if match is None:
            violations.add(f"unrecognized cargo tree line {number}; inspection incomplete")
            continue
        name = match["name"]
        seen.add(name)
        features = set(filter(None, match["features"].split(",")))
        if name in FORBIDDEN_PACKAGES:
            violations.add(f"forbidden package: {name}")
        for feature in features & FORBIDDEN_FEATURES.get(name, frozenset()):
            violations.add(f"forbidden feature: {name}/{feature}")
        if name == "rustls":
            missing = RUSTLS_REQUIRED_FEATURES - features
            if missing:
                violations.add(
                    f"rustls v{match['version']} missing required features: "
                    + ",".join(sorted(missing))
                )
    for name in REQUIRED_PACKAGES - seen:
        violations.add(f"missing required backend package: {name}")
    return sorted(violations)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", help="also check a proposed feature set")
    parser.add_argument("--offline", action="store_true", help="do not access the registry")
    args = parser.parse_args(argv)
    # Inspect the active graph, including all target-specific and dev/build edges.
    # Metadata/lockfiles can contain inactive weak dependencies (ring?/alloc).
    command = ["cargo", "tree", "--locked", "--target", "all", "--edges", "normal,build,dev",
               "--prefix", "none", "--color", "never", "--format", "{p}|{f}"]
    if args.features:
        command.extend(["--features", args.features])
    if args.offline:
        command.append("--offline")
    try:
        tree = subprocess.check_output(
            command, text=True, timeout=120, cwd=Path(__file__).resolve().parent.parent
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise SystemExit("cargo tree failed; dependency inspection incomplete") from error
    violations = inspect_tree(tree)
    if violations:
        raise SystemExit("Dependency guard failed:\n" + "\n".join(violations))
    print("Dependency guard passed: selected AWS-LC backend present; "
          "no forbidden TLS/backend or host-interface dependency detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
