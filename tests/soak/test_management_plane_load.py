#!/usr/bin/env python3
"""Destructive contracts for the flagship management-plane load driver."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import management_plane_load as load  # noqa: E402


class FakeResponse(io.BytesIO):
    def __init__(self, status, payload):
        super().__init__(payload)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class ManagementPlaneLoadContracts(unittest.TestCase):
    def test_runner_derives_stable_stub_one_prefix_with_rust_mapping(self):
        runner = HERE / "run-soak-rs-flagship.sh"
        cases = {
            "50": "20.0.50.0/24",
            "255": "20.0.255.0/24",
            "256": "20.1.0.0/24",
            "400": "20.1.144.0/24",
            "65535": "20.255.255.0/24",
            "65536": "21.0.0.0/24",
            "15466495": "255.255.255.0/24",
        }
        for routes_per_peer, expected in cases.items():
            with self.subTest(routes_per_peer=routes_per_peer):
                result = subprocess.run(
                    [
                        "bash", "-c",
                        'source "$1"; management_route_prefix "$2"',
                        "runner-prefix-test", str(runner), routes_per_peer,
                    ],
                    text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

    def test_runner_fails_closed_on_invalid_management_prefix_shape(self):
        runner = HERE / "run-soak-rs-flagship.sh"
        for routes_per_peer in (
            "0", "-1", "01", "15466496", "999999999999999999",
        ):
            with self.subTest(routes_per_peer=routes_per_peer):
                env = os.environ.copy()
                env["SOAK_ROUTES_PER_PEER"] = routes_per_peer
                result = subprocess.run(
                    ["bash", str(runner)], env=env,
                    text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("SOAK_ROUTES_PER_PEER", result.stderr)

    def test_metrics_requires_http_200_and_nonempty_body(self):
        self.assertEqual(load.validate_metrics(503, b"busy", 4), "http_status")
        self.assertEqual(load.validate_metrics(200, b"", 0), "empty")
        self.assertEqual(load.validate_metrics(200, b"metric 1\n", 9), "ok")

    def test_metrics_probe_records_digest_without_payload(self):
        opener = lambda *_args, **_kwargs: FakeResponse(200, b"metric 1\n")
        result = load.probe_metrics("http://invalid.test/metrics", 1, opener)
        self.assertEqual(result.exit_code, 200)
        self.assertEqual(result.result, "ok")
        self.assertEqual(result.byte_count, 9)
        self.assertEqual(len(result.sha256), 64)

    def test_payload_fingerprint_accepts_exact_cap_and_rejects_one_more_byte(self):
        payload = b"x" * load.MAX_PAYLOAD_BYTES
        retained, byte_count, digest = load._payload_fingerprint(io.BytesIO(payload))
        self.assertEqual(retained, payload)
        self.assertEqual(byte_count, load.MAX_PAYLOAD_BYTES)
        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())

        retained, byte_count, digest = load._payload_fingerprint(
            io.BytesIO(payload + b"y")
        )
        self.assertIsNone(retained)
        self.assertEqual(byte_count, load.MAX_PAYLOAD_BYTES + 1)
        self.assertEqual(digest, hashlib.sha256(payload + b"y").hexdigest())

    def test_metrics_timeout_is_classified_without_retry(self):
        def opener(*_args, **_kwargs):
            raise urllib.error.URLError(TimeoutError("timed out"))

        result = load.probe_metrics("http://invalid.test/metrics", 0.05, opener)
        self.assertIsNone(result.exit_code)
        self.assertEqual(result.result, "timeout")

    def test_neighbor_requires_array_and_exact_peer_cardinality(self):
        valid = json.dumps([{}, {}, {}]).encode()
        self.assertEqual(load.validate_cli_json("neighbor", valid, 3, "p"), "ok")
        self.assertEqual(load.validate_cli_json("neighbor", valid, 2, "p"), "cardinality")
        self.assertEqual(load.validate_cli_json("neighbor", b"{}", 3, "p"), "schema")

    def test_policy_requires_object_with_chains_array(self):
        self.assertEqual(
            load.validate_cli_json("policy_stats", b'{"chains":[]}', 1, "p"),
            "ok",
        )
        for payload in (b"[]", b"{}", b'{"chains":{}}'):
            self.assertEqual(
                load.validate_cli_json("policy_stats", payload, 1, "p"),
                "schema",
            )

    def test_route_requires_one_exact_requested_prefix(self):
        prefix = "20.0.0.0/24"
        self.assertEqual(
            load.validate_cli_json(
                "rib_prefix", b'[{"prefix":"20.0.0.0/24"}]', 1, prefix
            ),
            "ok",
        )
        for payload in (
            b"[]",
            b'[{"prefix":"20.0.1.0/24"}]',
            b'[{"prefix":"20.0.0.0/24"},{"prefix":"20.0.0.0/24"}]',
        ):
            self.assertEqual(
                load.validate_cli_json("rib_prefix", payload, 1, prefix),
                "route",
            )

    def test_malformed_json_and_wrong_root_are_rejected(self):
        self.assertEqual(load.validate_cli_json("neighbor", b"{", 1, "p"), "json")
        self.assertEqual(load.validate_cli_json("rib_prefix", b"{}", 1, "p"), "schema")

    def test_cli_nonzero_exit_is_recorded_without_retry(self):
        result = load.run_cli_command(
            [sys.executable, "-c", "raise SystemExit(7)"],
            "neighbor",
            1,
            1,
            "20.0.0.0/24",
        )
        self.assertEqual(result.exit_code, 7)
        self.assertEqual(result.result, "cli_exit")

    def test_cli_timeout_is_recorded_and_process_reaped(self):
        started = time.monotonic()
        result = load.run_cli_command(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            "neighbor",
            0.05,
            1,
            "20.0.0.0/24",
        )
        self.assertEqual(result.result, "timeout")
        self.assertIsNone(result.exit_code)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_commands_are_the_shipped_json_uds_surfaces(self):
        commands = load.cli_commands("/bin/rbgp", "unix:///tmp/grpc.sock", "20.0.0.0/24")
        self.assertEqual(
            commands["neighbor"],
            ["/bin/rbgp", "-s", "unix:///tmp/grpc.sock", "--json", "neighbor"],
        )
        self.assertEqual(
            commands["policy_stats"],
            [
                "/bin/rbgp", "-s", "unix:///tmp/grpc.sock", "--json",
                "policy", "stats", "--direction", "both",
            ],
        )
        self.assertEqual(
            commands["rib_prefix"],
            [
                "/bin/rbgp", "-s", "unix:///tmp/grpc.sock", "--json",
                "rib", "--prefix", "20.0.0.0/24",
            ],
        )

    def test_clean_stop_writes_one_terminal_summary_as_last_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "load.jsonl")
            engine = load.ManagementPlaneLoad(
                output=path,
                metrics_url="http://127.0.0.1:1/metrics",
                rbgp="/missing/rbgp",
                uds="unix:///tmp/grpc.sock",
                peer_count=1,
                route_prefix="20.0.0.0/24",
                metrics_interval_seconds=60,
                cli_interval_seconds=60,
                timeout_seconds=0.05,
            )
            engine._probe = lambda _operation: load.ProbeResult(0, "ok", 2, "a" * 64)
            stopper = threading.Timer(0.05, engine.request_stop)
            stopper.start()
            self.assertEqual(engine.run(), 0)
            stopper.join()
            raw = Path(path).read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        records = [json.loads(line) for line in raw.splitlines()]
        summaries = [record for record in records if record["record"] == "summary"]
        self.assertEqual(len(summaries), 1)
        self.assertIs(records[-1], summaries[0])
        self.assertEqual(summaries[0]["result"], "clean_sigterm")
        self.assertNotIn("payload", raw.decode())

    def test_runner_starts_load_after_convergence_before_measured_window(self):
        runner = (HERE / "run-soak-rs-flagship.sh").read_text()
        main = runner.split("main() {", 1)[1]
        convergence = main.index('log "engine converged')
        load_start = main.index("start_management_load")
        measured_start = main.index("MEASURED_START_MONOTONIC=")
        sample_start = main.index("start_epoch=$(date +%s)")
        early_exit = main.index(
            'pid_running "$MANAGEMENT_LOAD_PID" || abort '
            '"management-plane load exited before engine"'
        )
        measured_end = main.index("MEASURED_END_MONOTONIC=")
        stop = main.index("if ! stop_management_load; then")
        analyzer = main.index("analyze-soak-rs-flagship.py")
        self.assertLess(convergence, load_start)
        self.assertLess(load_start, measured_start)
        self.assertLess(measured_start, sample_start)
        self.assertLess(sample_start, early_exit)
        self.assertLess(sample_start, measured_end)
        self.assertLess(measured_end, stop)
        self.assertLess(stop, analyzer)
        self.assertNotIn("ENABLE_MANAGEMENT", runner)
        self.assertNotIn("grpcurl", runner)
        self.assertNotIn("readonly MANAGEMENT_ROUTE_PREFIX=20.0.0.0/24", runner)
        self.assertIn(
            'MANAGEMENT_ROUTE_PREFIX=$(management_route_prefix '
            '"$SOAK_ROUTES_PER_PEER")',
            runner,
        )
        self.assertIn('--route-prefix "$MANAGEMENT_ROUTE_PREFIX"', runner)
        self.assertIn('"management_route_prefix": "%s"', runner)
        cleanup = runner.split("cleanup() {", 1)[1].split("\n}", 1)[0]
        self.assertLess(
            cleanup.index("stop_management_load"),
            cleanup.index('terminate "$DAEMON_PID"'),
        )


if __name__ == "__main__":
    unittest.main()
