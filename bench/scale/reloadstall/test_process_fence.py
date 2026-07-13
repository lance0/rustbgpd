#!/usr/bin/env -S /usr/bin/python3 -I -S
"""Adversarial tests for reload-stall host process fencing."""

from __future__ import annotations

import tempfile
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from process_fence import (
    Process,
    ProcessScanError,
    find_competitors,
    is_system_init_identity,
    read_process,
)


ROOT = "/work/rustbgpd-policy-reload-receipt"


def process(
    pid: int,
    ppid: int,
    comm: str,
    *argv: str,
    cwd: str = "/tmp",
    exe: str = "",
    state: str = "S",
    kernel_thread: bool = False,
) -> Process:
    return Process(
        pid=pid,
        ppid=ppid,
        comm=comm,
        argv=tuple(argv),
        cwd=cwd,
        exe=exe,
        state=state,
        kernel_thread=kernel_thread,
    )


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
                "/work/rustbgpd-next/target/release/new_benchmark",
            )
        )
        self.assertEqual(found[0][1], "rustbgpd-root-executable")

    def test_unknown_native_binary_anywhere_under_root_is_detected(self) -> None:
        found = self.competitors(
            process(
                20,
                1,
                "helper",
                f"{ROOT}/tools/helper",
                exe=f"{ROOT}/tools/helper",
            )
        )
        self.assertEqual(found[0][1], "rustbgpd-root-executable")

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

    def test_interpreted_pyc_under_bench_is_detected(self) -> None:
        found = self.competitors(
            process(20, 1, "python3", "python3", f"{ROOT}/bench/scale/cache.pyc")
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
        self.assertEqual(found[0][1], "rustbgpd-root-executable")

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

    def test_ignored_native_and_pyc_ancestry_stays_ignored(self) -> None:
        found = self.competitors(
            process(
                10,
                1,
                "helper",
                f"{ROOT}/tools/helper",
                exe=f"{ROOT}/tools/helper",
            ),
            process(11, 10, "python3", "python3", f"{ROOT}/bench/cache.pyc"),
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


class ProcfsCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.proc = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def make_record(
        self,
        pid: int = 20,
        *,
        ppid: int = 1,
        comm: str = "cargo",
        argv: tuple[str, ...] = ("cargo", "build"),
        state: str = "S",
        flags: int = 0,
        links: bool = True,
    ) -> Path:
        base = self.proc / str(pid)
        base.mkdir()
        (base / "stat").write_text(
            f"{pid} ({comm}) {state} {ppid} 0 0 0 0 {flags}\n",
            encoding="utf-8",
        )
        (base / "comm").write_text(f"{comm}\n", encoding="utf-8")
        (base / "cmdline").write_bytes(
            b"\0".join(value.encode("utf-8") for value in argv)
            + (b"\0" if argv else b"")
        )
        if links:
            (base / "cwd").symlink_to("/tmp")
            (base / "exe").symlink_to("/usr/bin/cargo")
        return base

    def test_complete_live_record_reads_required_links(self) -> None:
        self.make_record()
        record = read_process(20, self.proc)
        self.assertIsNotNone(record)
        self.assertEqual(record.ppid, 1)
        self.assertEqual(record.cwd, "/tmp")
        self.assertEqual(record.exe, "/usr/bin/cargo")

    def test_missing_links_are_allowed_for_proven_zombie(self) -> None:
        self.make_record(state="Z", links=False)
        record = read_process(20, self.proc)
        self.assertIsNotNone(record)
        self.assertEqual(record.state, "Z")
        self.assertEqual(record.cwd, "")
        self.assertEqual(record.exe, "")

    def test_missing_links_are_allowed_for_proven_kernel_thread(self) -> None:
        self.make_record(flags=0x00200000, links=False)
        record = read_process(20, self.proc)
        self.assertIsNotNone(record)
        self.assertTrue(record.kernel_thread)
        self.assertEqual(record.cwd, "")
        self.assertEqual(record.exe, "")

    def test_missing_links_for_live_ordinary_process_fail_closed(self) -> None:
        self.make_record(links=False)
        with self.assertRaisesRegex(ProcessScanError, "incomplete procfs link"):
            read_process(20, self.proc)

    def test_vanished_pid_is_the_only_silent_skip(self) -> None:
        self.assertIsNone(read_process(20, self.proc))

    def test_malformed_stat_is_rejected(self) -> None:
        base = self.make_record()
        (base / "stat").write_text("malformed\n", encoding="utf-8")
        with self.assertRaisesRegex(ProcessScanError, "malformed procfs stat"):
            read_process(20, self.proc)

    def test_malformed_stat_flags_are_rejected(self) -> None:
        base = self.make_record()
        (base / "stat").write_text(
            "20 (cargo worker) S 1 0 0 0 0 invalid\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ProcessScanError, "malformed procfs numeric field"):
            read_process(20, self.proc)

    def test_missing_required_file_is_rejected_while_pid_exists(self) -> None:
        base = self.make_record()
        (base / "comm").unlink()
        with self.assertRaisesRegex(ProcessScanError, "incomplete procfs record"):
            read_process(20, self.proc)

    def test_hidepid_permission_error_is_rejected(self) -> None:
        self.make_record()
        original = Path.read_bytes

        def denied(path: Path) -> bytes:
            if path.name == "cmdline":
                raise PermissionError("denied")
            return original(path)

        with mock.patch.object(Path, "read_bytes", denied):
            with self.assertRaisesRegex(ProcessScanError, "permission/hidepid"):
                read_process(20, self.proc)

    def test_permission_hidden_links_are_allowed_for_exact_system_init(self) -> None:
        self.make_record(
            pid=1,
            ppid=0,
            comm="systemd",
            argv=("/sbin/init", "splash"),
        )
        with mock.patch(
            "process_fence.os.readlink", side_effect=PermissionError("denied")
        ):
            record = read_process(1, self.proc)
        self.assertIsNotNone(record)
        self.assertEqual(record.cwd, "")
        self.assertEqual(record.exe, "")

    def test_permission_hidden_links_are_allowed_for_proven_kernel_thread(self) -> None:
        self.make_record(flags=0x00200000)
        with mock.patch(
            "process_fence.os.readlink", side_effect=PermissionError("denied")
        ):
            record = read_process(20, self.proc)
        self.assertIsNotNone(record)
        self.assertTrue(record.kernel_thread)
        self.assertEqual(record.cwd, "")
        self.assertEqual(record.exe, "")

    def test_permission_hidden_links_are_allowed_for_proven_zombie(self) -> None:
        self.make_record(state="Z")
        with mock.patch(
            "process_fence.os.readlink", side_effect=PermissionError("denied")
        ):
            record = read_process(20, self.proc)
        self.assertIsNotNone(record)
        self.assertEqual(record.state, "Z")
        self.assertEqual(record.cwd, "")
        self.assertEqual(record.exe, "")

    def test_system_init_identity_rejects_every_required_field_mismatch(self) -> None:
        self.assertTrue(
            is_system_init_identity(1, 0, "systemd", ("/sbin/init", "splash"))
        )
        identities = (
            (2, 0, "systemd", ("/sbin/init",)),
            (1, 1, "systemd", ("/sbin/init",)),
            (1, 0, "init", ("/sbin/init",)),
            (1, 0, "systemd", ("systemd",)),
            (1, 0, "systemd", ()),
        )
        for identity in identities:
            with self.subTest(identity=identity):
                self.assertFalse(is_system_init_identity(*identity))

    def test_permission_hidden_links_for_ordinary_process_fail_closed(self) -> None:
        self.make_record()
        with mock.patch(
            "process_fence.os.readlink", side_effect=PermissionError("denied")
        ):
            with self.assertRaisesRegex(ProcessScanError, "permission/hidepid"):
                read_process(20, self.proc)


if __name__ == "__main__":
    unittest.main()
