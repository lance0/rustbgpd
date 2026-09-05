"""Run with python3 -m unittest discover -s bench/evpn-load -p test_fanout.py."""

import ast
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import patch
import json

RUNNER = Path(__file__).with_name("fanout.py")
# Load the collection helpers without starting the script's peers.
functions = [
    node
    for node in ast.parse(RUNNER.read_text()).body
    if isinstance(node, ast.FunctionDef) and node.name in {"convergence_range", "cli_snapshot"}
]
namespace = {"subprocess": subprocess, "json": json}
exec(compile(ast.Module(body=functions, type_ignores=[]), str(RUNNER), "exec"), namespace)


class FanoutFailures(unittest.TestCase):
    def test_nullable_and_missing_convergence_never_become_successful_times(self):
        collect = namespace["convergence_range"]
        self.assertEqual(collect([{"initial_convergence_sec": 0.5}]), (0.5, 0.5))
        for missing in ({"initial_convergence_sec": None}, {}):
            self.assertEqual(collect([{"initial_convergence_sec": 0.5}, missing]), (None, None))

    def test_cli_snapshots_keep_raw_output_and_reject_failures(self):
        for name in ("neighbors", "selected"):
            for code, stdout, expected in (
                (0, '[{"ok": true}]', [{"ok": True}]),
                (1, "permission denied", None),
                (0, "truncated json", None),
                (0, "{}", None),
            ):
                with (
                    self.subTest(name=name, code=code, stdout=stdout),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    root = Path(tmp)
                    result = subprocess.CompletedProcess([], code, stdout, "diagnostic")
                    with patch.object(subprocess, "run", return_value=result):
                        rows = namespace["cli_snapshot"](root, name, [], 1)
                    self.assertEqual(rows, expected)
                    self.assertEqual((root / f"{name}.json").read_text(), stdout)
                    self.assertEqual((root / f"{name}.stderr").read_text(), "diagnostic")

    def test_cli_timeout_keeps_partial_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            error = subprocess.TimeoutExpired([], 1, output=b"partial", stderr=b"waiting")
            with patch.object(subprocess, "run", side_effect=error):
                self.assertIsNone(namespace["cli_snapshot"](Path(tmp), "selected", [], 1))
            self.assertEqual((Path(tmp) / "selected.json").read_bytes(), b"partial")
            self.assertEqual((Path(tmp) / "selected.stderr").read_bytes(), b"waiting")

    def test_early_process_failure_writes_summary_and_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("rustbgpd", "rbgp", "evpn-tester", "evpn-monitor"):
                binary = root / name
                binary.write_text("#!/bin/sh\necho diagnostic >&2\nexit 1\n")
                binary.chmod(0o755)
            result = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--bin-dir",
                    tmp,
                    "--receivers",
                    "1",
                    "--routes",
                    "40",
                    "--out",
                    str(root / "run"),
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertNotEqual(result.returncode, 0)
            summary = json.loads((root / "run/summary.json").read_text())
            self.assertFalse(summary["correct"])
            self.assertIn("peer failed", summary["error"])
            self.assertIn("diagnostic", (root / "run/monitor-000.log").read_text())
