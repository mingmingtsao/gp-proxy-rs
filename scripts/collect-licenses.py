#!/usr/bin/env python3
"""Collect actual license/notice texts for a locked release target, without network."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--target", required=True, help="the exact Rust release target triple")
parser.add_argument("--output", type=Path, required=True, help="a new output directory")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
if args.output.exists() or args.output.is_symlink():
    raise SystemExit("Output must be a new directory, so stale license files cannot be packaged")


def cargo(*arguments):
    return subprocess.check_output(["cargo", *arguments], cwd=root, text=True)


metadata = json.loads(cargo("metadata", "--format-version", "1", "--locked", "--offline"))
tree = cargo("tree", "--locked", "--offline", "--target", args.target,
             "--edges", "normal,build", "--prefix", "none", "--format", "{p}")
active = {tuple(line.split()[:2]) for line in tree.splitlines()}
packages = sorted((p for p in metadata["packages"]
                   if p["id"] != metadata["resolve"]["root"]
                   and (p["name"], "v" + p["version"]) in active),
                  key=lambda p: (p["name"], p["version"]))
if not packages:
    raise SystemExit("Dependency graph is empty; refusing an incomplete bundle")
bundle = []
missing = []
for package in packages:
    label = package["name"] + "-" + package["version"]
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", label):
        raise SystemExit("Unsafe package directory name")
    source = Path(package["manifest_path"]).parent.resolve()
    candidates = []
    for directory, directories, filenames in os.walk(source, followlinks=False):
        directories[:] = [name for name in directories if name not in {"target", ".git", ".cargo"}]
        for filename in filenames:
            path = Path(directory) / filename
            if any(part.upper().startswith(("LICENSE", "COPYING", "NOTICE"))
                   for part in path.relative_to(source).parts):
                candidates.append(path)
    if package["license_file"]:
        candidates.append(source / package["license_file"])
    files = []
    for path in sorted(set(candidates)):
        if path.is_symlink() or not path.resolve().is_relative_to(source):
            raise SystemExit(f"License path escapes package or is a symlink: {label}")
        if path.stat().st_size > 1024 * 1024:
            raise SystemExit(f"License file exceeds resource limit: {label}")
        files.append((path.relative_to(source).as_posix(), path.read_bytes()))
    if not files or not package["license"]:
        missing.append(label)
    bundle.append((package, label, files))
if missing:
    raise SystemExit("Missing license text/declaration; inspect authoritative upstream sources: "
                     + ", ".join(missing))

# Build into a temporary sibling and publish only a complete bundle. No source
# directories or environment files are recursively copied into release output.
args.output.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="gp-license-", dir=args.output.parent) as temporary:
    destination = Path(temporary) / "bundle"
    destination.mkdir()
    records = []
    index = ["# Third-party license and notice texts", "", f"Release target: `{args.target}`.", "",
             "These files preserve the texts distributed with the locked source packages.",
             "They do not replace a legal review or prove binary reproducibility.", ""]
    for package, label, files in bundle:
        record = {key: package[key] for key in ("name", "version", "license", "repository")}
        record["files"] = []
        index.append(f"- {label}: {package['license']}")
        for relative, data in files:
            output = destination / label / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
            record["files"].append({"path": f"{label}/{relative}",
                                    "sha256": hashlib.sha256(data).hexdigest()})
        records.append(record)
    manifest = {"target": args.target,
                "lock_sha256": hashlib.sha256((root / "Cargo.lock").read_bytes()).hexdigest(),
                "packages": records}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (destination / "THIRD_PARTY_NOTICES.md").write_text("\n".join(index) + "\n")
    destination.rename(args.output)
print(f"Collected license texts for {len(packages)} active packages into {args.output}")
