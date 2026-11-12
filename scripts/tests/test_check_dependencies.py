"""Synthetic active graphs exercise the native-crypto exception and fail-closed parsing."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "check_dependencies", Path(__file__).resolve().parents[1] / "check-dependencies.py"
)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)

VALID = """gp-proxy v0.1.0 (/synthetic/public workspace)|
rustls v0.23.46|aws_lc_rs,std,tls12
aws-lc-rs v1.19.0|aws-lc-sys,prebuilt-nasm
aws-lc-sys v0.40.0|prebuilt-nasm
smoltcp v0.14.0|medium-ip,proto-ipv4,proto-ipv6,socket-tcp,socket-udp,std
"""


class DependencyPolicyTests(unittest.TestCase):
    def test_selected_backend_and_cargo_duplicate_lines_are_accepted(self):
        graph = VALID + "rustls v0.23.46|aws_lc_rs,std,tls12 (*)\n"
        self.assertEqual(GUARD.inspect_tree(graph), [])

    def test_each_required_backend_package_must_be_active(self):
        for name in ("rustls", "aws-lc-rs", "aws-lc-sys"):
            with self.subTest(name=name):
                graph = "\n".join(line for line in VALID.splitlines()
                                  if not line.startswith(name + " "))
                self.assertIn("missing required backend package: " + name,
                              GUARD.inspect_tree(graph))

    def test_required_features_cannot_be_split_between_rustls_versions(self):
        graph = VALID.replace("aws_lc_rs,std,tls12", "std,tls12")
        graph += "rustls v0.23.45|aws_lc_rs\n"
        failures = GUARD.inspect_tree(graph)
        self.assertIn("rustls v0.23.46 missing required features: aws_lc_rs", failures)
        self.assertIn("rustls v0.23.45 missing required features: std,tls12", failures)

    def test_required_features_cannot_be_split_between_same_version_instances(self):
        graph = VALID.replace("aws_lc_rs,std,tls12", "std,tls12")
        graph += "rustls v0.23.46|aws_lc_rs\n"
        self.assertTrue(GUARD.inspect_tree(graph))

    def test_representative_other_tls_and_old_provider_paths_are_rejected(self):
        for name in ("ring", "rustls-rustcrypto", "openssl-sys", "native-tls",
                     "boring-sys", "mbedtls-sys-auto", "rustls-scytale",
                     "rustls-provider-rustcrypto-pq", "aws-lc-fips-sys"):
            with self.subTest(name=name):
                self.assertIn("forbidden package: " + name,
                              GUARD.inspect_tree(VALID + f"{name} v1.0.0|\n"))

    def test_representative_vpn_and_host_interface_bindings_are_rejected(self):
        for name in ("openconnect", "openconnect-sys", "libopenconnect-sys",
                     "tun", "tun2", "tun-rs", "tun-tap", "tokio-tun",
                     "utun", "wintun", "pcap"):
            with self.subTest(name=name):
                self.assertIn("forbidden package: " + name,
                              GUARD.inspect_tree(VALID + f"{name} v1.0.0|\n"))

    def test_backend_fips_and_prefer_pq_features_are_rejected(self):
        for name, feature in (("rustls", "ring"), ("rustls", "fips"),
                              ("rustls", "prefer-post-quantum"), ("aws-lc-rs", "fips")):
            with self.subTest(name=name, feature=feature):
                graph = VALID + f"{name} v0.23.46|aws_lc_rs,std,tls12,{feature}\n"
                self.assertIn(f"forbidden feature: {name}/{feature}", GUARD.inspect_tree(graph))

    def test_each_smoltcp_host_interface_feature_is_rejected_on_duplicate(self):
        for feature in ("phy-tuntap_interface", "phy-raw_socket"):
            with self.subTest(feature=feature):
                graph = VALID + f"smoltcp v0.14.0|std,{feature} (*)\n"
                self.assertIn(f"forbidden feature: smoltcp/{feature}", GUARD.inspect_tree(graph))

    def test_aws_lc_sys_cannot_expand_primitives_exception_to_tls_or_fips(self):
        for feature in ("ssl", "fips"):
            with self.subTest(feature=feature):
                graph = VALID + f"aws-lc-sys v0.47.0|{feature}\n"
                self.assertIn(f"forbidden feature: aws-lc-sys/{feature}", GUARD.inspect_tree(graph))

    def test_os_sys_bindings_and_independent_rustcrypto_primitives_are_allowed(self):
        graph = VALID
        for name in ("libc", "rustix", "windows-sys", "security-framework-sys",
                     "ed25519-dalek", "p256", "sha2", "ringbuf", "tunnel-example"):
            graph += f"{name} v1.0.0|std\n"
        self.assertEqual(GUARD.inspect_tree(graph), [])

    def test_empty_and_unparseable_output_fails_closed(self):
        self.assertTrue(GUARD.inspect_tree(""))
        for bad in ("\n", "unexpected heading", "ring v0.17.14", "ring|",
                    "rustls v0.23.46|aws_lc_rs,std,tls12|unexpected"):
            with self.subTest(bad=bad):
                self.assertTrue(any("inspection incomplete" in failure
                                    for failure in GUARD.inspect_tree(VALID + bad)))

    def test_main_inspects_locked_all_target_active_graph_with_explicit_options(self):
        output = io.StringIO()
        with mock.patch.object(GUARD.subprocess, "check_output", return_value=VALID) as run, \
                contextlib.redirect_stdout(output):
            self.assertEqual(GUARD.main(["--features", "synthetic", "--offline"]), 0)
        command = run.call_args.args[0]
        for flag, value in (("--target", "all"), ("--edges", "normal,build,dev"),
                            ("--prefix", "none"), ("--color", "never"),
                            ("--format", "{p}|{f}"), ("--features", "synthetic")):
            self.assertEqual(command[command.index(flag) + 1], value)
        self.assertIn("--locked", command)
        self.assertIn("--offline", command)
        self.assertEqual(run.call_args.kwargs, {
            "text": True, "timeout": 120,
            "cwd": Path(GUARD.__file__).resolve().parent.parent,
        })
        self.assertIn("selected AWS-LC backend present", output.getvalue())

    def test_cargo_failure_or_timeout_cannot_pass(self):
        for failure in (FileNotFoundError("synthetic"),
                        subprocess.CalledProcessError(1, ["synthetic"]),
                        subprocess.TimeoutExpired(["synthetic"], 120)):
            with self.subTest(failure=type(failure).__name__), \
                    mock.patch.object(GUARD.subprocess, "check_output", side_effect=failure):
                with self.assertRaisesRegex(SystemExit, "inspection incomplete"):
                    GUARD.main([])

    def test_main_reports_policy_failure_instead_of_success(self):
        output = io.StringIO()
        with mock.patch.object(GUARD.subprocess, "check_output", return_value=VALID + "ring v0.17.14|\n"), \
                contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(SystemExit, "forbidden package: ring"):
                GUARD.main([])
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
