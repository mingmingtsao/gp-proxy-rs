#!/usr/bin/env python3
"""Verify the offline smoltcp source archive, complete vendor tree and exact patch.

Usage:
  python3 scripts/check-vendor.py
  python3 scripts/check-vendor.py --archive /cache/smoltcp-0.14.0.crate
  python3 scripts/check-vendor.py --self-check

The default archive is located under $CARGO_HOME/registry/cache, or
~/.cargo/registry/cache when CARGO_HOME is unset. No network command is executed.
The original .crate SHA-256 and upstream commit are pinned below, matching
docs/smoltcp-patch.md. Files are compared as bytes; archives are never extracted.

Default allowlist metadata is embedded in this script. To approve an additional
existing upstream file, pass --metadata with a reviewed JSON file, for example:
  {"schema_version": 1, "modified_files": [
    "src/socket/tcp.rs", "src/iface/interface/tcp.rs"
  ]}
--print-default-metadata prints the current metadata without inspecting files.
Metadata cannot change the archive digest, permit missing files or use globs.

Canonical patch format: sorted modified paths, UTF-8 unified diff, three context
lines, a/<path> and b/<path> headers, no timestamps or git headers. Missing final
newlines use the standard '\\ No newline at end of file' marker. The stored
gp-proxy-snd-max.patch must match these bytes exactly; this script never writes it.

The only permitted added files are the patch and optional Cargo extraction
marker .cargo-ok (format {"v":1}). The top-level target/ build directory is
explicitly excluded and reported, including when absent. All other added files,
directories, symlinks, missing originals and undeclared changes are rejected.

--self-check uses small temporary synthetic archives/trees only. Its test-only
digest is passed to internal functions; command-line audits always use the
documented, pinned smoltcp 0.14.0 digest.
"""

import argparse
from dataclasses import dataclass
import difflib
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import tempfile


PACKAGE = "smoltcp"
VERSION = "0.14.0"
ARCHIVE_NAME = f"{PACKAGE}-{VERSION}.crate"
ARCHIVE_SHA256 = "b6f8b28ad56c6e35524a37dd492af5d1a47e31e1a4d175cd12f89c075f01980f"
UPSTREAM_COMMIT = "cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3"
PATCH = "gp-proxy-snd-max.patch"
MARKER = ".cargo-ok"
EXCLUDED_BUILD_DIR = "target"
DEFAULT_METADATA = {"schema_version": 1, "modified_files": ["src/socket/tcp.rs"]}
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 4096


class CheckFailure(Exception):
    pass


def fail(message):
    raise CheckFailure(message)


def safe_relative(value):
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        fail("metadata/archive contains an invalid relative path")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        fail("metadata/archive path contains control characters")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        fail("metadata/archive path is absolute or noncanonical")
    if any(part == ".env" or part.startswith(".env.") for part in parts):
        fail("environment files are not permitted audit inputs")
    return PurePosixPath(value).as_posix()


def forbid_environment_path(path):
    if any(part == ".env" or part.startswith(".env.") for part in path.parts):
        fail("environment files are not permitted audit inputs")


def read_regular(path, maximum):
    forbid_environment_path(path)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            fail(f"expected a regular, non-symlink file: {path}")
        if info.st_size > maximum:
            fail(f"file exceeds audit size limit: {path}")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                fail(f"audit file changed identity while opening: {path}")
            if opened.st_size > maximum:
                fail(f"file exceeds audit size limit: {path}")
            data = handle.read(maximum + 1)
        if len(data) > maximum:
            fail(f"file exceeds audit size limit: {path}")
        return data
    except OSError as error:
        fail(f"cannot read required audit file {path}: {error.strerror}")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON metadata key")
        result[key] = value
    return result


def parse_json(data, description):
    try:
        return json.loads(data, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError):
        fail(f"invalid {description} JSON")


def load_metadata(path):
    metadata = DEFAULT_METADATA if path is None else parse_json(
        read_regular(path, 16 * 1024), "allowlist metadata"
    )
    if not isinstance(metadata, dict) or set(metadata) != {"schema_version", "modified_files"}:
        fail("allowlist metadata requires exactly schema_version and modified_files")
    if type(metadata["schema_version"]) is not int or metadata["schema_version"] != 1:
        fail("unsupported allowlist metadata schema_version")
    entries = metadata["modified_files"]
    if not isinstance(entries, list) or len(entries) > 32:
        fail("modified_files must be an explicit list of at most 32 upstream files")
    paths = [safe_relative(entry) for entry in entries]
    if len(set(paths)) != len(paths):
        fail("duplicate modified_files allowlist entry")
    return frozenset(paths)


def locate_archive(explicit, cargo_home):
    if explicit is not None:
        return explicit
    cache = cargo_home / "registry" / "cache"
    candidates = sorted(cache.glob(f"*/{ARCHIVE_NAME}"))
    if not candidates:
        fail(f"offline archive unavailable: no {ARCHIVE_NAME} in {cache}; "
             "provide --archive with the official cached .crate (nothing was downloaded)")
    # Multiple registries may cache the same release. Check every candidate so
    # a corrupt copy is not silently skipped in favor of another registry.
    for path in candidates:
        data = read_regular(path, MAX_ARCHIVE_BYTES)
        if hashlib.sha256(data).hexdigest() != ARCHIVE_SHA256:
            fail(f"cached archive SHA-256 mismatch: {path}")
    return candidates[0]


def archive_files(blob, expected_digest):
    if len(blob) > MAX_ARCHIVE_BYTES:
        fail("archive exceeds audit size limit")
    if hashlib.sha256(blob).hexdigest() != expected_digest:
        fail("archive SHA-256 does not match the pinned release")
    prefix = f"{PACKAGE}-{VERSION}"
    originals = {}
    seen = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            for number, member in enumerate(archive, start=1):
                if number > MAX_MEMBERS:
                    fail("archive has too many entries")
                name = safe_relative(member.name.rstrip("/"))
                if name in seen:
                    fail("duplicate archive entry")
                seen.add(name)
                if name == prefix and member.isdir():
                    continue
                if not name.startswith(prefix + "/"):
                    fail("archive entry is outside its package prefix")
                relative = name[len(prefix) + 1:]
                if relative.split("/", 1)[0] == EXCLUDED_BUILD_DIR:
                    fail("upstream source collides with the excluded build directory")
                if member.isdir():
                    continue
                if not member.isfile():
                    fail("archive links/devices/nonregular entries are forbidden")
                if not 0 <= member.size <= MAX_FILE_BYTES:
                    fail("archive member exceeds audit size limit")
                total += member.size
                if total > MAX_SOURCE_BYTES:
                    fail("archive source exceeds total audit size limit")
                stream = archive.extractfile(member)
                if stream is None:
                    fail("archive member could not be read")
                with stream:
                    data = stream.read(MAX_FILE_BYTES + 1)
                if len(data) != member.size:
                    fail("archive member size is inconsistent")
                originals[relative] = data
    except (tarfile.TarError, OSError, EOFError):
        fail("invalid or truncated gzip/tar archive")
    if not originals:
        fail("archive contains no original source files")
    vcs = parse_json(originals.get(".cargo_vcs_info.json", b""), "upstream VCS metadata")
    if not isinstance(vcs, dict) or not isinstance(vcs.get("git"), dict) \
            or vcs["git"].get("sha1") != UPSTREAM_COMMIT or vcs.get("path_in_vcs") != "":
        fail("archive upstream commit does not match the documented release")
    return originals


def inventory(vendor, originals):
    forbid_environment_path(vendor)
    if vendor.is_symlink() or not vendor.is_dir():
        fail("vendor root must be an existing, non-symlink directory")
    allowed_dirs = {"."}
    for name in originals:
        allowed_dirs.update(str(parent) for parent in PurePosixPath(name).parents)
    allowed_files = set(originals) | {PATCH, MARKER}
    found = set()
    total_entries = 0
    excluded_present = False

    def walk_error(error):
        fail(f"cannot enumerate vendor tree: {error.strerror}")

    for directory, directories, filenames in os.walk(vendor, followlinks=False, onerror=walk_error):
        for name in sorted(directories):
            path = Path(directory) / name
            relative = path.relative_to(vendor).as_posix()
            if path.is_symlink():
                fail(f"vendor directory symlink is forbidden: {relative!r}")
            if relative == EXCLUDED_BUILD_DIR:
                directories.remove(name)
                excluded_present = True
            elif relative not in allowed_dirs:
                fail(f"undeclared extra vendor directory: {relative!r}")
        total_entries += len(directories) + len(filenames)
        if total_entries > MAX_MEMBERS:
            fail("vendor tree has too many entries")
        for name in sorted(filenames):
            path = Path(directory) / name
            relative = path.relative_to(vendor).as_posix()
            if relative not in allowed_files:
                # Reject unexpected files before opening them, including .env.
                fail(f"undeclared extra vendor file: {relative!r}")
            if not stat.S_ISREG(path.lstat().st_mode):
                fail(f"vendor symlink/nonregular file is forbidden: {relative!r}")
            found.add(relative)
    missing = (set(originals) | {PATCH}) - found
    if missing:
        fail("missing upstream/patch files: " + ", ".join(sorted(missing)))
    snapshot = {}
    total_bytes = 0
    for name in sorted(found):
        data = read_regular(vendor / name, MAX_FILE_BYTES)
        total_bytes += len(data)
        if total_bytes > MAX_SOURCE_BYTES:
            fail("vendor source exceeds total audit size limit")
        snapshot[name] = data
    if MARKER in snapshot:
        marker = parse_json(snapshot[MARKER], "Cargo extraction marker")
        if not isinstance(marker, dict) or set(marker) != {"v"} \
                or type(marker["v"]) is not int or marker["v"] != 1:
            fail("unrecognized Cargo extraction marker")
    return snapshot, excluded_present


def canonical_patch(originals, snapshot, changed):
    output = []
    for name in sorted(changed):
        try:
            before = originals[name].decode("utf-8").splitlines(keepends=True)
            after = snapshot[name].decode("utf-8").splitlines(keepends=True)
        except UnicodeError:
            fail(f"modified file is not UTF-8 text and cannot form a unified diff: {name!r}")
        for line in difflib.unified_diff(before, after, fromfile="a/" + name, tofile="b/" + name, n=3):
            output.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return "".join(output).encode("utf-8")


@dataclass
class Result:
    upstream_files: int
    changed: list
    patch_sha256: str
    excluded_present: bool


def verify(blob, vendor, allowed, expected_digest=ARCHIVE_SHA256):
    originals = archive_files(blob, expected_digest)
    unknown = set(allowed) - set(originals)
    if unknown:
        fail("allowlist names nonexistent upstream files: " + ", ".join(sorted(unknown)))
    snapshot, excluded_present = inventory(vendor, originals)
    changed = sorted(name for name, data in originals.items() if snapshot[name] != data)
    unexpected = set(changed) - set(allowed)
    if unexpected:
        fail("undeclared upstream modifications: " + ", ".join(sorted(unexpected)))
    expected_patch = canonical_patch(originals, snapshot, changed)
    if snapshot[PATCH] != expected_patch:
        fail("stored patch differs from the canonical unified diff; "
             f"expected SHA-256 {hashlib.sha256(expected_patch).hexdigest()}, "
             f"stored {hashlib.sha256(snapshot[PATCH]).hexdigest()}; "
             "review and regenerate the patch explicitly")
    if inventory(vendor, originals) != (snapshot, excluded_present):
        fail("vendor tree changed during verification; rerun after edits finish")
    return Result(len(originals), changed, hashlib.sha256(expected_patch).hexdigest(), excluded_present)


def self_check():
    """Independent negative fixtures exercise the whole verifier, not production files."""
    baseline = {
        ".cargo_vcs_info.json": json.dumps({"git": {"sha1": UPSTREAM_COMMIT}, "path_in_vcs": ""}).encode(),
        "Cargo.toml": b'[package]\nname = "smoltcp"\nversion = "0.14.0"\n',
        "LICENSE-0BSD.txt": b"synthetic license fixture\n",
        "src/socket/tcp.rs": b"before\n",
        "src/iface/interface/tcp.rs": b"iface before\n",
    }
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in baseline.items():
            member = tarfile.TarInfo(f"{PACKAGE}-{VERSION}/{name}")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    blob = stream.getvalue()
    digest = hashlib.sha256(blob).hexdigest()
    patch = b"--- a/src/socket/tcp.rs\n+++ b/src/socket/tcp.rs\n@@ -1 +1 @@\n-before\n+after\n"
    allowed = frozenset(DEFAULT_METADATA["modified_files"])
    passed = 0

    def case(name, change, expected_error=None, policy=allowed, archive_bytes=blob):
        nonlocal passed
        with tempfile.TemporaryDirectory(prefix="gp-vendor-self-check-") as temporary:
            vendor = Path(temporary) / "smoltcp"
            for filename, data in baseline.items():
                destination = vendor / filename
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
            (vendor / "src/socket/tcp.rs").write_bytes(b"after\n")
            (vendor / PATCH).write_bytes(patch)
            (vendor / MARKER).write_bytes(b'{"v":1}')
            change(vendor)
            try:
                verify(archive_bytes, vendor, policy, digest)
            except CheckFailure as error:
                if expected_error is None or expected_error not in str(error):
                    raise AssertionError(f"self-check {name}: unexpected failure: {error}") from error
            else:
                if expected_error is not None:
                    raise AssertionError(f"self-check {name}: failure was not detected")
        passed += 1

    case("valid", lambda root: None)
    case("bad archive", lambda root: None, "SHA-256", archive_bytes=blob + b"tampered")
    case("missing original", lambda root: (root / "LICENSE-0BSD.txt").unlink(), "missing upstream")
    case("undeclared edit", lambda root: (root / "Cargo.toml").write_bytes(b"changed\n"), "undeclared upstream")
    case("extra source", lambda root: (root / "extra.rs").write_bytes(b"extra\n"), "undeclared extra")
    case("unexpected env", lambda root: (root / ".env").write_bytes(b"synthetic-never-read"), "undeclared extra")
    case("missing patch", lambda root: (root / PATCH).unlink(), "missing upstream/patch")
    case("stale patch", lambda root: (root / PATCH).write_bytes(patch + b"\n"), "canonical unified diff")
    case("bad marker", lambda root: (root / MARKER).write_bytes(b'{"v":true}'), "unrecognized Cargo")
    case("unknown allowlist", lambda root: None, "nonexistent upstream", policy=frozenset({"missing.rs"}))
    case("empty extra directory", lambda root: (root / "unexpected").mkdir(), "undeclared extra")

    if os.name != "nt":
        def source_link(root):
            (root / "src/socket/tcp.rs").unlink()
            (root / "src/socket/tcp.rs").symlink_to(root / "Cargo.toml")
        case("source symlink", source_link, "symlink/nonregular")
    else:
        print("Self-check limitation: symlink fixture omitted on Windows without assuming symlink privileges")

    def build_output(root):
        (root / "target").mkdir()
        (root / "target" / "synthetic.bin").write_bytes(b"\xff\x00")
    case("explicit build exclusion", build_output)

    def multi_file(root):
        (root / "src/iface/interface/tcp.rs").write_bytes(b"iface after\n")
        additional = b"--- a/src/iface/interface/tcp.rs\n+++ b/src/iface/interface/tcp.rs\n@@ -1 +1 @@\n-iface before\n+iface after\n"
        (root / PATCH).write_bytes(additional + patch)
    case("reviewed allowlist extension", multi_file, policy=allowed | {"src/iface/interface/tcp.rs"})

    def no_newline(root):
        (root / "src/socket/tcp.rs").write_bytes(b"after")
        (root / PATCH).write_bytes(patch.rstrip(b"\n") + b"\n\\ No newline at end of file\n")
    case("missing final newline", no_newline)

    with tempfile.TemporaryDirectory(prefix="gp-vendor-metadata-self-check-") as temporary:
        metadata = Path(temporary) / "policy.json"
        metadata.write_text('{"schema_version":1,"modified_files":["src/socket/tcp.rs","src/iface/interface/tcp.rs"]}')
        assert load_metadata(metadata) == allowed | {"src/iface/interface/tcp.rs"}
        metadata.write_text('{"schema_version":1,"modified_files":["../escape"]}')
        try:
            load_metadata(metadata)
        except CheckFailure:
            passed += 1
        else:
            raise AssertionError("unsafe metadata path was accepted")
        try:
            locate_archive(None, Path(temporary))
        except CheckFailure as error:
            assert "offline archive unavailable" in str(error)
            passed += 1
        else:
            raise AssertionError("missing offline cache was accepted")
    print(f"Vendor self-check passed: {passed} bounded synthetic cases; no production tree/cache inspected")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--archive", type=Path, help="official smoltcp 0.14.0 .crate file")
    parser.add_argument("--vendor", type=Path, help="vendor tree (default: repository vendor/smoltcp)")
    parser.add_argument("--metadata", type=Path, help="reviewed JSON modified-file allowlist")
    parser.add_argument("--self-check", action="store_true", help="test only temporary synthetic inputs")
    parser.add_argument("--print-default-metadata", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_check:
            if args.archive or args.vendor or args.metadata or args.print_default_metadata:
                parser.error("--self-check does not accept real archive/vendor/metadata arguments")
            self_check()
            return 0
        if args.print_default_metadata:
            if args.archive or args.vendor or args.metadata:
                parser.error("--print-default-metadata does not accept file arguments")
            print(json.dumps(DEFAULT_METADATA, indent=2))
            return 0
        allowed = load_metadata(args.metadata)
        cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
        archive = locate_archive(args.archive, cargo_home)
        vendor = args.vendor or Path(__file__).resolve().parents[1] / "vendor" / PACKAGE
        result = verify(read_regular(archive, MAX_ARCHIVE_BYTES), vendor, allowed)
        print(f"Verified archive: {archive}")
        print(f"Archive SHA-256: {ARCHIVE_SHA256}; upstream commit: {UPSTREAM_COMMIT}")
        print("Explicit modification allowlist:", json.dumps(sorted(allowed)))
        print(f"Explicit build-output exclusion: target/ (present: {result.excluded_present})")
        print("Permitted added files: gp-proxy-snd-max.patch; optional validated .cargo-ok")
        print(f"Compared all {result.upstream_files} upstream files; modified: {json.dumps(result.changed)}")
        print(f"Canonical unified patch SHA-256: {result.patch_sha256}")
        print("Vendor verification passed; no files changed, no network used")
        return 0
    except (CheckFailure, OSError) as error:
        print(f"Vendor verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
