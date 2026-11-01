#!/usr/bin/env python3
"""Mutation proofs for the core-test shard partition check."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("check_ci_test_shards.py")
SPEC = importlib.util.spec_from_file_location("check_ci_test_shards", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
shards = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shards)


def artifact(kind: str, name: str, *, test: bool = True, executable: bool = True) -> str:
    return json.dumps({
        "reason": "compiler-artifact",
        "target": {"kind": [kind], "name": name},
        "profile": {"test": test},
        "executable": f"/target/debug/deps/{name}-0" if executable else None,
        "fresh": True,
    })


def build_output() -> list[str]:
    """Cargo output listing exactly the targets the real shards select."""
    lines = [artifact("lib", "rustbgpd_wire"), artifact("proc-macro", "a_macro"),
             artifact("bin", "rustbgpd"), artifact("lib", "rustbgpd_wire", test=False),
             artifact("bin", "rustbgpd", test=False), '{"reason":"build-finished","success":true}']
    for selectors in shards.SHARDS.values():
        lines += [artifact("test", s.removeprefix("--test=")) for s in selectors
                  if s.startswith("--test=")]
    return lines


class ShardPartitionTests(unittest.TestCase):
    def errors(self, lines: list[str], table: dict[str, list[str]] | None = None) -> list[str]:
        return shards.check(shards.built_targets(lines), table or shards.SHARDS)

    def test_current_shards_partition_the_build(self) -> None:
        self.assertEqual(self.errors(build_output()), [])

    def test_new_test_target_in_no_shard_fails(self) -> None:
        errors = self.errors([*build_output(), artifact("test", "brand_new_target")])
        self.assertEqual(errors, ["test target brand_new_target is in no shard"])

    def test_new_example_or_bench_test_target_fails(self) -> None:
        errors = self.errors([*build_output(), artifact("example", "tested_example")])
        self.assertEqual(errors, ["example target tested_example is in no shard"])

    def test_target_in_both_shards_fails(self) -> None:
        table = {key: list(value) for key, value in shards.SHARDS.items()}
        table["2"].append("--test=runtime_config_settlement_matrix")
        self.assertIn("test target runtime_config_settlement_matrix is in shards 1, 2",
                      self.errors(build_output(), table))

    def test_library_selector_in_two_shards_fails(self) -> None:
        table = {key: list(value) for key, value in shards.SHARDS.items()}
        table["1"].append("--lib")
        self.assertIn("lib target rustbgpd_wire is in shards 1, 2", self.errors(build_output(), table))

    def test_removed_bins_selector_drops_binaries(self) -> None:
        table = {key: [s for s in value if s != "--bins"] for key, value in shards.SHARDS.items()}
        self.assertIn("bin target rustbgpd is in no shard", self.errors(build_output(), table))

    def test_stale_selector_fails(self) -> None:
        lines = [line for line in build_output() if '"name": "read_deadlines"' not in line]
        self.assertIn("shard 2: --test=read_deadlines selects no built test target", self.errors(lines))

    def test_unknown_selector_and_empty_build_fail(self) -> None:
        self.assertIn("shard 1: unsupported selector --workspace",
                      self.errors(build_output(), {"1": ["--workspace"], "2": []}))
        self.assertIn("the build output lists no test executables", self.errors([]))

    def test_non_test_and_non_executable_artifacts_are_ignored(self) -> None:
        lines = [*build_output(), artifact("test", "not_built", executable=False),
                 artifact("bin", "helper", test=False)]
        self.assertEqual(self.errors(lines), [])

    def test_cli_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.jsonl"
            good.write_text("\n".join(build_output()) + "\n", encoding="utf-8")
            bad = Path(tmp) / "bad.jsonl"
            bad.write_text("\n".join([*build_output(), artifact("test", "x")]) + "\n", encoding="utf-8")
            run = lambda *a: subprocess.run([sys.executable, str(SCRIPT), *a], check=False,
                                            capture_output=True, text=True)
            self.assertEqual(run("check", str(good)).returncode, 0)
            failed = run("check", str(bad))
            self.assertEqual(failed.returncode, 1)
            self.assertIn("test target x is in no shard", failed.stderr)
            self.assertEqual(run("args", "1").stdout.split()[0], "--bins")
            self.assertEqual(run("args", "9").returncode, 2)


if __name__ == "__main__":
    unittest.main()
