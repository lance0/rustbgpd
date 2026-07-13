#!/usr/bin/env python3
"""Adversarial tests for reload-stall host process fencing."""

from __future__ import annotations

import unittest

from process_fence import Process, find_competitors


ROOT = "/work/rustbgpd-lan-350"


def process(
    pid: int,
    ppid: int,
    comm: str,
    *argv: str,
    cwd: str = "/tmp",
    exe: str = "",
) -> Process:
    return Process(pid=pid, ppid=ppid, comm=comm, argv=tuple(argv), cwd=cwd, exe=exe)


class ProcessFenceTests(unittest.TestCase):
    def competitors(self, *records: Process, ignored: set[int] | None = None):
        return find_competitors(records, ignored or set(), [ROOT, "/tmp/exact-source"])

    def test_python_launched_bgperf2_is_detected(self) -> None:
        found = self.competitors(
            process(20, 1, "python3", "python3", "/opt/bgperf2/bgperf2.py")
        )
        self.assertEqual(found[0][1], "known-executable:bgperf2")

    def test_truncated_comm_uses_full_argv_name(self) -> None:
        found = self.competitors(
            process(
                20,
                1,
                "event_history_p",
                f"{ROOT}/target/release/deps/event_history_producer-deadbeef",
            )
        )
        self.assertTrue(found)

    def test_unknown_rustbgpd_target_binary_is_detected(self) -> None:
        found = self.competitors(
            process(
                20,
                1,
                "new_benchmark",
                "/home/lance/projects/rustbgpd-next/target/release/new_benchmark",
            )
        )
        self.assertEqual(found[0][1], "rustbgpd-target-binary")

    def test_interpreted_repo_benchmark_is_detected(self) -> None:
        found = self.competitors(
            process(20, 1, "bash", "bash", f"{ROOT}/bench/scale/new-bench.sh")
        )
        self.assertEqual(found[0][1], "interpreted-rustbgpd-benchmark")

    def test_relative_interpreted_repo_benchmark_uses_cwd(self) -> None:
        found = self.competitors(
            process(
                20,
                1,
                "python3",
                "python3",
                "bench/scale/new-bench.py",
                cwd=ROOT,
            )
        )
        self.assertEqual(found[0][1], "interpreted-rustbgpd-benchmark")

    def test_proc_exe_catches_target_binary_hidden_by_argv(self) -> None:
        found = self.competitors(
            process(
                20,
                1,
                "worker",
                "innocuous-name",
                exe=f"{ROOT}/target/release/new_benchmark",
            )
        )
        self.assertEqual(found[0][1], "rustbgpd-target-binary")

    def test_descendant_of_competitor_is_detected(self) -> None:
        found = self.competitors(
            process(20, 1, "cargo", "cargo", "bench"),
            process(21, 20, "worker", "worker"),
        )
        self.assertEqual([record.pid for record, _ in found], [20, 21])
        self.assertEqual(found[1][1], "descendant-of:20")

    def test_runner_ancestry_is_ignored(self) -> None:
        found = self.competitors(
            process(10, 1, "cargo", "cargo", "run"),
            process(11, 10, "python3", "python3", "process_fence.py"),
            ignored={10, 11},
        )
        self.assertEqual(found, [])

    def test_benign_python_and_editor_are_not_detected(self) -> None:
        found = self.competitors(
            process(20, 1, "python3", "python3", "/opt/service.py"),
            process(21, 1, "vim", "vim", f"{ROOT}/bench/scale/README.md"),
        )
        self.assertEqual(found, [])

    def test_command_rendering_cannot_break_tsv(self) -> None:
        record = process(20, 1, "cargo", "cargo", "bad\tvalue\nnext")
        self.assertNotIn("\t", record.command)
        self.assertNotIn("\n", record.command)


if __name__ == "__main__":
    unittest.main()
