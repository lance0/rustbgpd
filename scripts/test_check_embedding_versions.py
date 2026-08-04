#!/usr/bin/env python3
"""Mutation proofs for the embedding-version documentation contract."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check_embedding_versions.py"
DOCUMENT = (ROOT / "docs" / "EMBEDDING.md").read_text(encoding="utf-8")


class EmbeddingVersionContractTests(unittest.TestCase):
    def run_checker(self, document: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "EMBEDDING.md"
            path.write_text(document, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(CHECKER), str(path)],
                capture_output=True,
                text=True,
            )

    def assert_fails(self, document: str, diagnostic: str) -> None:
        result = self.run_checker(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(diagnostic, result.stdout + result.stderr)

    def replace_nth(self, old: str, new: str, occurrence: int = 0) -> str:
        start = -1
        for _ in range(occurrence + 1):
            start = DOCUMENT.find(old, start + 1)
        self.assertGreaterEqual(start, 0)
        return DOCUMENT[:start] + new + DOCUMENT[start + len(old) :]

    def test_each_wire_snippet_is_guarded(self) -> None:
        """Red if either wire dependency example drifts to 0.15.0."""
        old = 'rustbgpd-wire = "0.16.2"'
        for occurrence in (0, 1):
            with self.subTest(occurrence=occurrence):
                self.assert_fails(
                    self.replace_nth(old, 'rustbgpd-wire = "0.15.0"', occurrence),
                    "wire-snippet-version",
                )

    def test_fsm_snippet_is_guarded(self) -> None:
        """Red if the FSM dependency example drifts to 0.3.0."""
        self.assert_fails(
            self.replace_nth('rustbgpd-fsm = "0.3.1"', 'rustbgpd-fsm = "0.3.0"'),
            "fsm-snippet-version",
        )

    def test_publish_statuses_are_guarded(self) -> None:
        """Red if either numbered publish heading names an old version."""
        mutations = (("wire", "0.16.2", "0.16.1"), ("fsm", "0.3.1", "0.3.0"))
        for package, current, old in mutations:
            with self.subTest(package=package):
                self.assert_fails(
                    self.replace_nth(
                        f"(published as `{current}`)", f"(published as `{old}`)"
                    ),
                    "publish-status-version",
                )

    def test_current_boundary_is_guarded(self) -> None:
        """Red if §7 loses either authoritative current-version slot."""
        self.assert_fails(
            self.replace_nth("`rustbgpd-fsm 0.3.1`", "rustbgpd-fsm 0.3.1"),
            "current-boundary-version",
        )

    def test_prepared_language_is_forbidden(self) -> None:
        """Red if a published release is again described as prepared."""
        self.assert_fails(
            self.replace_nth(
                "**The 0.16.0 release**", "**The prepared 0.16.0 release**"
            ),
            "forbidden-prepared",
        )


if __name__ == "__main__":
    unittest.main()
