"""A successful audit exit must not conceal an incomplete registry lookup."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "audit_dependencies", Path(__file__).resolve().parents[1] / "audit-dependencies.py"
)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class AuditDiagnosticsTests(unittest.TestCase):
    def run_audit(self, stderr, *, code=0, warnings=None, extra_args=(), observe=None):
        report = {
            "vulnerabilities": {"list": []},
            "warnings": warnings or {},
            "settings": {
                "ignore": [], "target_arch": [], "target_os": [], "severity": None,
                "informational_warnings": ["unmaintained", "unsound", "notice"],
            },
        }
        completed = subprocess.CompletedProcess(
            ["synthetic-cargo-audit"], code, json.dumps(report), stderr
        )
        output = io.StringIO()
        def execute(command, **kwargs):
            if observe:
                observe(command, kwargs)
            return completed
        with mock.patch("sys.argv", ["audit-dependencies.py", *extra_args]), \
                mock.patch.object(AUDIT.subprocess, "run", side_effect=execute), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status = AUDIT.main()
        return status, output.getvalue()

    def test_lookup_timeout_fails_despite_zero_exit_and_valid_empty_report(self):
        status, output = self.run_audit(
            "error: couldn't check if the package is yanked: registry: request timed out\n"
        )
        self.assertEqual(status, 1)
        self.assertIn("result is incomplete", output)
        self.assertIn("request timed out", output)

    def test_coded_error_diagnostic_is_not_hidden_by_report(self):
        status, _ = self.run_audit("error[E001]: synthetic registry error\n")
        self.assertEqual(status, 1)

    def test_colored_error_cannot_hide_an_incomplete_lookup(self):
        status, output = self.run_audit(
            "\x1b[0m\x1b[1m\x1b[31merror:\x1b[0m registry: request timed out\n"
        )
        self.assertEqual(status, 1)
        self.assertIn("result is incomplete", output)

    def test_child_uses_explicit_config_and_color_then_removes_config(self):
        observed = []
        def inspect_child(command, kwargs):
            child_cwd = Path(kwargs["cwd"])
            observed.append(child_cwd)
            self.assertNotEqual(child_cwd, Path(AUDIT.__file__).resolve().parent.parent)
            config = tomllib.loads((child_cwd / ".cargo" / "audit.toml").read_text())
            self.assertTrue(config["database"]["fetch"])
            self.assertFalse(config["database"]["stale"])
            self.assertTrue(config["yanked"]["enabled"])
            self.assertTrue(config["yanked"]["update_index"])
            self.assertEqual(command[command.index("--color") + 1], "never")
            self.assertTrue(Path(command[command.index("--file") + 1]).is_absolute())
            self.assertEqual(kwargs["timeout"], 300)
            self.assertNotIn("env", kwargs, "do not repurpose HOME/CARGO_HOME")
        status, _ = self.run_audit("", observe=inspect_child)
        self.assertEqual(status, 0)
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0].exists())

    def test_child_timeout_is_failure_and_cleans_private_config(self):
        observed = []
        def timeout_child(command, kwargs):
            observed.append(Path(kwargs["cwd"]))
            raise subprocess.TimeoutExpired(command, 300, stderr=b"synthetic audit stalled\n")
        with self.assertRaisesRegex(SystemExit, "deadline; audit incomplete"):
            self.run_audit("", observe=timeout_child)
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0].exists())

    def test_yanked_warning_without_advisory_is_visible_and_deniable(self):
        warning = {"yanked": [{"advisory": None, "package": {"name": "synthetic", "version": "1.0.0"}}]}
        for extra_args, expected in [((), 0), (("--deny-warnings",), 1)]:
            status, output = self.run_audit("", warnings=warning, extra_args=extra_args)
            self.assertEqual(status, expected)
            self.assertIn("yanked: synthetic 1.0.0: package is yanked", output)
            self.assertIn("0 vulnerabilities, 1 warnings", output)

    def test_explicit_offline_mode_remains_visible_and_requires_snapshot(self):
        with tempfile.TemporaryDirectory(prefix="gp-audit-test-db-") as snapshot:
            def inspect_child(command, kwargs):
                self.assertIn("--no-fetch", command)
                self.assertIn("--no-yanked", command)
                self.assertEqual(command[command.index("--db") + 1], str(Path(snapshot).resolve()))
            status, output = self.run_audit(
                "", extra_args=("--offline", "--database", snapshot), observe=inspect_child
            )
        self.assertEqual(status, 0)
        self.assertIn("not performed (explicit offline mode)", output)
        with self.assertRaises(SystemExit):
            self.run_audit("", extra_args=("--offline",))

    def test_ordinary_progress_remains_successful(self):
        status, _ = self.run_audit("    Fetching advisory database\n    Scanning Cargo.lock\n")
        self.assertEqual(status, 0)

    def test_nonzero_tool_status_remains_failure(self):
        status, _ = self.run_audit("", code=1)
        self.assertEqual(status, 1)


if __name__ == "__main__":
    unittest.main()
