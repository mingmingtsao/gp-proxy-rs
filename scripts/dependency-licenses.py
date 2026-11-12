#!/usr/bin/env python3
"""Reproduce the license inventory from the locked, active production graph."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]


def cargo(*arguments):
    return subprocess.check_output(["cargo", *arguments], cwd=root, text=True)


metadata = json.loads(cargo("metadata", "--format-version", "1", "--locked", "--offline"))
tree = cargo("tree", "--locked", "--offline", "--target", "all", "--edges", "normal,build",
             "--prefix", "none", "--format", "{p}")
active = {tuple(line.split()[:2]) for line in tree.splitlines()}
packages = sorted(
    (p for p in metadata["packages"] if p["id"] != metadata["resolve"]["root"]
     and (p["name"], "v" + p["version"]) in active),
    key=lambda p: (p["name"], p["version"]),
)
if any(not p["license"] for p in packages):
    raise SystemExit("Missing SPDX license declaration; review required")
digest = hashlib.sha256((root / "Cargo.lock").read_bytes()).hexdigest()
text = f"""# 锁定依赖许可证清单

由 `python3 scripts/dependency-licenses.py` 从当前锁定的实际 normal/build 依赖图（全部 target）生成，共 {len(packages)} 项；不包含未启用的 optional dependency。Cargo.lock SHA-256：`{digest}`。

从 Cargo metadata 提取 SPDX 声明。本清单不替代分发时保留各依赖的版权和完整许可证文本，也不代表安全审计通过。本地维护的第三方差异见 [smoltcp 补丁说明](smoltcp-patch.md)。

| Crate | 版本 | 声明许可证 |
|---|---|---|
"""
text += "".join(f"| {p['name']} | {p['version']} | {p['license']} |\n" for p in packages)
output = root / "docs/dependency-licenses.md"
if args.check:
    if not output.exists() or output.read_text() != text:
        raise SystemExit("License inventory is stale; regenerate with scripts/dependency-licenses.py")
else:
    output.write_text(text)
print(f"License inventory {'verified' if args.check else 'generated'}: {len(packages)} active packages")
