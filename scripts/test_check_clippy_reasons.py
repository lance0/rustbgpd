#!/usr/bin/env python3
"""Mutation proofs for the clippy-suppression reason ratchet."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-clippy-reasons.py")
SPEC = importlib.util.spec_from_file_location("check_clippy_reasons", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class ClippyReasonTests(unittest.TestCase):
    def test_crate_level_suppression_without_reason_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "lib.rs"
            source.write_text(
                "#![allow(clippy::module_name_repetitions)]\n", encoding="utf-8"
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(source)],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("missing reason", result.stdout)
        self.assertIn("#![allow(clippy::module_name_repetitions)]", result.stdout)
        self.assertNotIn("unterminated", result.stdout)

    def test_cli_and_event_history_are_ratcheted_by_default(self) -> None:
        self.assertIn("crates/cli/src", checker.DEFAULT_PATHS)
        self.assertIn("crates/event-history/src", checker.DEFAULT_PATHS)


if __name__ == "__main__":
    unittest.main()
