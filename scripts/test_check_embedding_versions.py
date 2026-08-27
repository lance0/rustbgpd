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
        """Fails if any wire dependency example drifts to 0.15.0."""
        old = 'rustbgpd-wire = "0.18.0"'
        for occurrence in (0, 1, 2):
            with self.subTest(occurrence=occurrence):
                self.assert_fails(
                    self.replace_nth(old, 'rustbgpd-wire = "0.15.0"', occurrence),
                    "wire-snippet-version",
                )

    def test_fsm_snippet_is_guarded(self) -> None:
        """Fails if the FSM dependency example drifts to 0.3.1."""
        self.assert_fails(
            self.replace_nth('rustbgpd-fsm = "0.5.0"', 'rustbgpd-fsm = "0.3.1"'),
            "fsm-snippet-version",
        )

    def test_rpki_snippet_is_guarded(self) -> None:
        """Fails if the RPKI dependency example drifts from its published line."""
        self.assert_fails(
            self.replace_nth('rustbgpd-rpki = "0.1.0"', 'rustbgpd-rpki = "0.2.0"'),
            "rpki-snippet-version",
        )

    def test_publish_statuses_are_guarded(self) -> None:
        """Fails if any numbered publish heading names an old version."""
        mutations = (
            ("wire", "0.18.0", "0.17.2"),
            ("fsm", "0.5.0", "0.4.1"),
            ("rpki", "0.1.0", "0.0.1"),
        )
        for package, current, old in mutations:
            with self.subTest(package=package):
                self.assert_fails(
                    self.replace_nth(
                        f"(published as `{current}`)", f"(published as `{old}`)"
                    ),
                    "publish-status-version",
                )

    def test_current_boundary_is_guarded(self) -> None:
        """Fails if §7 loses any authoritative current-version slot."""
        for package, version in (("wire", "0.18.0"), ("fsm", "0.5.0"), ("rpki", "0.1.0")):
            with self.subTest(package=package):
                self.assert_fails(
                    self.replace_nth(
                        f"`rustbgpd-{package} {version}`",
                        f"rustbgpd-{package} {version}",
                    ),
                    "current-boundary-version",
                )

    def test_status_parser_rejects_prepared_as(self) -> None:
        """Fails if an actual publish status changes from published to prepared."""
        self.assert_fails(
            self.replace_nth(
                "(published as `0.18.0`)", "(prepared as `0.18.0`)"
            ),
            "publish-status-version",
        )

    def test_heading_renumbering_and_unrelated_prepared_prose_are_allowed(self) -> None:
        changed = DOCUMENT
        for old, new in (("## 7. ", "## 70. "), ("### 3.1 ", "### 30.1 "),
                         ("### 3.3 ", "### 30.3 "), ("### 3.4 ", "### 30.4 "),
                         ("## 4. ", "## 40. ")):
            changed = changed.replace(old, new, 1)
        changed += "\nAn unrelated consumer prepared its own deployment.\n"
        self.assertEqual(self.run_checker(changed).returncode, 0)

    def test_each_semantic_heading_is_required(self) -> None:
        titles = (
            "Published-crate release boundary",
            "Decode an UPDATE (codec-only — the canonical embedder)",
            'Build a session (codec + FSM — the "minimal speaker" consumer)',
            "Validate an origin (RPKI table — the synchronous consumer)",
            "Which crate to publish next, and why",
        )
        for title in titles:
            with self.subTest(title=title):
                self.assert_fails(
                    DOCUMENT.replace(title, f"{title} drifted", 1),
                    f"semantic-heading:{title}:missing",
                )

    def test_duplicate_semantic_heading_is_rejected(self) -> None:
        title = "Published-crate release boundary"
        self.assert_fails(DOCUMENT + f"\n## {title}\n", f"semantic-heading:{title}")

    def test_wrong_semantic_heading_levels_are_rejected(self) -> None:
        title = "Published-crate release boundary"
        for level in (1, 4, 5, 6):
            with self.subTest(level=level):
                changed = DOCUMENT.replace(f"## 7. {title}", f"{'#' * level} 7. {title}")
                self.assert_fails(changed, f"semantic-heading:{title}:duplicate-or-wrong-level")


if __name__ == "__main__":
    unittest.main()
