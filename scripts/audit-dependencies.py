#!/usr/bin/env python3
"""Run a visible, unfiltered RustSec audit of Cargo.lock; never suppress advisories."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


AUDIT_TIMEOUT_SECONDS = 300
# The wrapper must select its own defaults. cargo-audit 0.23 otherwise reads
# cwd/.cargo/audit.toml or CARGO_HOME/audit.toml, and JSON settings do not reveal
# yanked.enabled/update_index or database.fetch. Do not change the user's files
# or HOME/CARGO_HOME: use a private child cwd with an explicit config instead.
AUDIT_CONFIG = """[database]
fetch = true
stale = false

[yanked]
enabled = true
update_index = true
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo-audit", default="cargo-audit", help="cargo-audit executable")
    parser.add_argument("--database", type=Path, help="existing RustSec database directory")
    parser.add_argument("--offline", action="store_true", help="do not fetch the database or check yanked packages")
    parser.add_argument("--deny-warnings", action="store_true", help="fail for maintenance/unsoundness/notice/yanked warnings too")
    parser.add_argument("--report", type=Path, help="write the full JSON result for review")
    args = parser.parse_args()
    if args.offline and args.database is None:
        parser.error("--offline requires an explicit --database snapshot")

    root = Path(__file__).resolve().parent.parent
    lock = root / "Cargo.lock"
    lock_before = lock.read_bytes()
    executable = args.cargo_audit
    # Relative executable paths referred to the caller's cwd before isolation.
    # Preserve that interface while a bare command still uses the inherited PATH.
    if os.sep in executable or (os.altsep and os.altsep in executable):
        executable = str(Path(executable).resolve())
    command = [executable, "audit", "--file", str(lock), "--format", "json", "--color", "never"]
    if args.database:
        command.extend(["--db", str(args.database.resolve())])
    if args.offline:
        command.extend(["--no-fetch", "--no-yanked"])
    try:
        with tempfile.TemporaryDirectory(prefix="gp-audit-config-") as isolated:
            config_directory = Path(isolated) / ".cargo"
            config_directory.mkdir(mode=0o700)
            config_path = config_directory / "audit.toml"
            config_path.write_text(AUDIT_CONFIG, encoding="utf-8")
            config_path.chmod(0o600)
            completed = subprocess.run(
                command, cwd=isolated, text=True, capture_output=True, check=False,
                timeout=AUDIT_TIMEOUT_SECONDS,
            )
    except subprocess.TimeoutExpired as error:
        if error.stderr:
            diagnostic = error.stderr
            if isinstance(diagnostic, bytes):
                diagnostic = diagnostic.decode("utf-8", errors="replace")
            print(diagnostic, file=sys.stderr, end="")
        raise SystemExit(f"cargo-audit exceeded its {AUDIT_TIMEOUT_SECONDS}-second deadline; audit incomplete") from error
    except OSError as error:
        raise SystemExit(f"Cannot run cargo-audit: {error}") from error
    if completed.stderr:
        print(completed.stderr, file=sys.stderr, end="")
    if lock.read_bytes() != lock_before:
        raise SystemExit("Cargo.lock changed during the audit; rerun against the completed lockfile")
    try:
        report = json.loads(completed.stdout)
        vulnerabilities = report["vulnerabilities"]["list"]
        warnings = report.get("warnings", {})
        settings = report["settings"]
    except (ValueError, KeyError, TypeError) as error:
        raise SystemExit("cargo-audit did not produce a valid audit report; check tool/database availability") from error
    if args.report:
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Independently reject filtered results, including unexpected tool defaults.
    if any(settings.get(key) for key in ["ignore", "target_arch", "target_os", "severity"]):
        raise SystemExit("Refusing filtered RustSec report: remove advisory ignores, severity and target filters")
    expected_warnings = {"unmaintained", "unsound", "notice"}
    if not expected_warnings.issubset(settings.get("informational_warnings", [])):
        raise SystemExit("Refusing report with disabled informational warning categories")

    print("Cargo.lock SHA-256:", hashlib.sha256(lock_before).hexdigest())
    print("RustSec database:", json.dumps(report.get("database", {}), sort_keys=True))
    print("Yanked package check:", "not performed (explicit offline mode)" if args.offline else "enabled")
    for category, findings in [("vulnerability", vulnerabilities), *sorted(warnings.items())]:
        for finding in findings:
            advisory = finding["advisory"]
            package = finding["package"]
            if category == "yanked" and advisory is None:
                print(f'yanked: {package["name"]} {package["version"]}: package is yanked')
            else:
                print(f'{category}: {advisory["id"]} {package["name"]} {package["version"]}: {advisory["title"]}')
    warning_count = sum(len(findings) for findings in warnings.values())
    print(f"RustSec findings: {len(vulnerabilities)} vulnerabilities, {warning_count} warnings")
    # cargo-audit can emit per-package yanked lookup errors yet return zero and
    # a valid report. Keep that report for diagnosis, but never treat a partial
    # registry check as a successful release check. Benign progress is allowed.
    # --color never overrides CARGO_TERM_COLOR. Strip ANSI SGR defensively for
    # alternate tool versions/wrappers before checking the diagnostic prefix.
    diagnostic = re.sub(r"\x1b\[[0-9;]*m", "", completed.stderr)
    if re.search(r"(?m)^\s*error(?:\[[^\]]+\])?:", diagnostic):
        print("Audit emitted errors; result is incomplete. See diagnostics above.", file=sys.stderr)
        return 1
    if completed.returncode or vulnerabilities or (args.deny_warnings and warning_count):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
