#!/usr/bin/env python3
"""Adversarial tests for the LAN-393 full-daemon perf classifier."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("validate-lan393-perf.py")
SPEC = importlib.util.spec_from_file_location("lan393_perf", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
perf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(perf)


MANAGER = """rustbgpd PID/TID [CPU] TIME: cycles:
        rustbgpd_rib::manager::RibManager::process_update
        tokio::runtime::task
"""
PRODUCER = """rustbgpd PID/TID [CPU] TIME: cycles:
        rustbgpd_api::event_history_sinks::EhmRibSink::publish_route_event
        rustbgpd_rib::manager::RibManager::publish_route_event
"""
OTHER = """rustbgpd PID/TID [CPU] TIME: cycles:
        tokio::runtime::park
"""
UNRELATED_PROTOST = """rustbgpd PID/TID [CPU] TIME: cycles:
        prost::message::Message::encode_to_vec
        rustbgpd_rib::manager::RibManager::process_update
"""


class PerfClassifierTests(unittest.TestCase):
    def write(self, root: Path, text: str) -> Path:
        path = root / "perf-script.txt"
        path.write_text(text, encoding="utf-8")
        return path

    def test_enabled_gate_and_disabled_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(Path(directory), "\n".join([MANAGER] * 19 + [PRODUCER, OTHER]))
            result = perf.classify(path, "baseline", "enabled")
            self.assertTrue(result["baseline_proceed_pass"])

        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                Path(directory), MANAGER + "\n" + UNRELATED_PROTOST + "\n" + OTHER
            )
            result = perf.classify(path, "baseline", "disabled")
            self.assertEqual(result["ehm_producer_samples"], 0)

    def test_missing_manager_unsanitized_path_and_disabled_producer_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SystemExit):
                perf.classify(self.write(Path(directory), OTHER), "baseline", "enabled")

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SystemExit):
                perf.classify(
                    self.write(Path(directory), MANAGER + "        /home/alice/private\n"),
                    "baseline",
                    "enabled",
                )

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SystemExit):
                perf.classify(self.write(Path(directory), PRODUCER), "baseline", "disabled")

    def test_parent_symlink_and_invalid_utf8_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            path = self.write(real, MANAGER)
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaises(SystemExit):
                perf.classify(alias / path.name, "baseline", "enabled")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "perf-script.txt"
            path.write_bytes(b"\xff\xfe")
            with self.assertRaises(SystemExit):
                perf.classify(path, "baseline", "enabled")


if __name__ == "__main__":
    unittest.main()
