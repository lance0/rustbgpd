#!/usr/bin/env python3
"""Mutation proofs for the embedding-version documentation contract."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.check_embedding_versions import check, manifest_versions


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
        old = 'rustbgpd-wire = "0.19.0"'
        for occurrence in (0, 1, 2):
            with self.subTest(occurrence=occurrence):
                self.assert_fails(
                    self.replace_nth(old, 'rustbgpd-wire = "0.15.0"', occurrence),
                    "wire-snippet-version",
                )

    def test_fsm_snippet_is_guarded(self) -> None:
        """Fails if the FSM dependency example drifts to 0.3.1."""
        self.assert_fails(
            self.replace_nth('rustbgpd-fsm = "0.6.0"', 'rustbgpd-fsm = "0.3.1"'),
            "fsm-snippet-version",
        )

    def test_rpki_snippet_is_guarded(self) -> None:
        """Fails if the RPKI dependency example drifts from the published release."""
        self.assert_fails(
            self.replace_nth('rustbgpd-rpki = "0.1.0"', 'rustbgpd-rpki = "0.0.1"'),
            "rpki-snippet-version",
        )

    def test_rpki_path_snippet_is_rejected(self) -> None:
        """Fails if the published RPKI release is demoted back to a path dependency."""
        for replacement in (
            'rustbgpd-rpki = { version = "0.1.0", path = "../rustbgpd/crates/rpki" }',
            'rustbgpd-rpki = { version = "0.1.0" }',
        ):
            with self.subTest(replacement=replacement):
                self.assert_fails(
                    self.replace_nth('rustbgpd-rpki = "0.1.0"', replacement),
                    "rpki-snippet-version",
                )

    def test_publication_map_state_is_guarded(self) -> None:
        """Fails if §1 stops claiming that all three crates are registry-published."""
        self.assert_fails(
            self.replace_nth(
                "`rustbgpd-rpki` is on the registry from its first",
                "`rustbgpd-rpki` is absent from the registry despite its first",
            ),
            "publication-map-state",
        )

    def test_publish_statuses_are_guarded(self) -> None:
        """Fails if any numbered publish heading names an old version."""
        published_mutations = (
            ("wire", "0.19.0", "0.17.2"),
            ("fsm", "0.6.0", "0.4.1"),
            ("rpki", "0.1.0", "0.0.1"),
        )
        for package, current, old in published_mutations:
            with self.subTest(package=package):
                self.assert_fails(
                    self.replace_nth(f"published as `{current}`", f"published as `{old}`"),
                    "publish-status-version",
                )

    def test_current_boundary_is_guarded(self) -> None:
        """Fails if §7 loses any authoritative registry-version slot."""
        for package, version in (("wire", "0.19.0"), ("fsm", "0.6.0"), ("rpki", "0.1.0")):
            with self.subTest(package=package):
                self.assert_fails(
                    self.replace_nth(
                        f"`rustbgpd-{package} {version}`",
                        f"rustbgpd-{package} {version}",
                    ),
                    "current-boundary-version",
                )

    def test_prepared_boundary_is_guarded(self) -> None:
        """Fails if §7 loses any authoritative prepared-version slot."""
        for package, version in (("wire", "0.19.0"), ("fsm", "0.6.0"), ("rpki", "0.1.0")):
            with self.subTest(package=package):
                self.assert_fails(
                    self.replace_nth(
                        f"`rustbgpd-{package} {version}`",
                        f"rustbgpd-{package} {version}",
                        1,
                    ),
                    "prepared-boundary-version",
                )

    def test_coordinated_published_version_drift_is_rejected(self) -> None:
        """Published prose and snippets cannot drift together from the known release."""
        self.assert_fails(
            DOCUMENT.replace("0.19.0", "9.9.9"),
            "current-boundary-version",
        )

    def test_coordinated_prepared_version_drift_is_rejected(self) -> None:
        """Prepared prose and snippets stay anchored to package manifests."""
        self.assert_fails(
            DOCUMENT.replace("0.6.0", "9.9.9"),
            "prepared-boundary-version",
        )

    def test_prepared_clause_expresses_a_tree_ahead_of_the_registry(self) -> None:
        """The published/prepared split survives this release's zero-width gap.

        Today every manifest version is also on crates.io, so no §4 entry carries
        a prepared clause. The next version bump reopens the gap; re-adding the
        clause and moving the §7 prepared paragraph must still validate.
        """
        changed = DOCUMENT.replace(
            "1. **`rustbgpd-wire` (published as `0.19.0`).**",
            "1. **`rustbgpd-wire` (published as `0.19.0`; `0.20.0` prepared).**",
            1,
        )
        marker = "`rustbgpd-wire 0.19.0`"
        second = changed.find(marker, changed.find(marker) + 1)
        self.assertGreaterEqual(second, 0)
        changed = changed[:second] + "`rustbgpd-wire 0.20.0`" + changed[second + len(marker) :]
        self.assertEqual(
            check(changed, {"wire": "0.20.0", "fsm": "0.6.0", "rpki": "0.1.0"}),
            [],
        )

    def test_a_staged_version_cannot_hide_by_omitting_the_prepared_clause(self) -> None:
        """An absent clause claims tree == registry, so a bumped tree is rejected."""
        errors = check(DOCUMENT, {"wire": "0.20.0", "fsm": "0.6.0", "rpki": "0.1.0"})
        self.assertIn("publish-status-version", errors)
        self.assertIn("prepared-boundary-version", errors)

    def test_rpki_wire_pair_is_guarded(self) -> None:
        """The first RPKI line cannot silently pair back to wire 0.18."""
        self.assert_fails(
            self.replace_nth(
                "first `0.1.0` release starts directly on wire `0.19.0`",
                "first `0.1.0` release starts directly on wire `0.18.0`",
            ),
            "rpki-wire-pair",
        )

    def test_fsm_wire_pair_is_guarded(self) -> None:
        """The published FSM line cannot silently pair back to wire 0.18."""
        self.assert_fails(
            self.replace_nth(
                "The `0.6.0` line pairs with wire `0.19.0`",
                "The `0.6.0` line pairs with wire `0.18.0`",
            ),
            "fsm-wire-pair",
        )

    def test_status_parser_rejects_stale_rpki_prepublish_label(self) -> None:
        """Fails if the published RPKI release is relabeled as merely prepared."""
        self.assert_fails(
            self.replace_nth(
                "3. **`rustbgpd-rpki` (published as `0.1.0`).**",
                "3. **`rustbgpd-rpki` (first publish prepared as `0.1.0`).**",
            ),
            "publish-status-version",
        )

    def test_heading_renumbering_and_unrelated_prepared_prose_are_allowed(self) -> None:
        changed = DOCUMENT
        for old, new in (
            ("## 7. ", "## 70. "),
            ("### 3.1 ", "### 30.1 "),
            ("### 3.3 ", "### 30.3 "),
            ("### 3.4 ", "### 30.4 "),
            ("## 4. ", "## 40. "),
        ):
            changed = changed.replace(old, new, 1)
        changed += "\nAn unrelated consumer prepared its own deployment.\n"
        self.assertEqual(self.run_checker(changed).returncode, 0)

    def test_labeled_boundary_paragraphs_allow_an_intro(self) -> None:
        """A harmless intro does not displace either authoritative paragraph."""
        marker = "## 7. Published-crate release boundary\n\n"
        changed = DOCUMENT.replace(
            marker,
            marker + "This section records the live registry state of the crates.\n\n",
            1,
        )
        self.assertEqual(self.run_checker(changed).returncode, 0)

    def test_duplicate_truthful_dependency_assignments_are_allowed(self) -> None:
        """A second equivalent example does not make the version contract ambiguous."""
        assignments = (
            'rustbgpd-wire = "0.19.0"',
            'rustbgpd-rpki = "0.1.0"',
        )
        for assignment in assignments:
            with self.subTest(assignment=assignment):
                changed = DOCUMENT.replace(assignment, f"{assignment}\n{assignment}", 1)
                self.assertEqual(self.run_checker(changed).returncode, 0)

    def test_manifest_versions_guard_root_workspace_pins(self) -> None:
        """Prepared package versions must match the root path/version pins."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "crates/wire").mkdir(parents=True)
            (root / "crates/fsm").mkdir(parents=True)
            (root / "crates/rpki").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                "[workspace]\n"
                "[workspace.dependencies]\n"
                'rustbgpd-wire = { version = "0.19.0", path = "crates/wire" }\n'
                'rustbgpd-fsm = { version = "0.6.0", path = "crates/fsm" }\n'
                'rustbgpd-rpki = { version = "0.1.0", path = "crates/rpki" }\n',
                encoding="utf-8",
            )
            for path, package, version in (
                ("crates/wire/Cargo.toml", "rustbgpd-wire", "0.19.0"),
                ("crates/fsm/Cargo.toml", "rustbgpd-fsm", "0.6.0"),
                ("crates/rpki/Cargo.toml", "rustbgpd-rpki", "0.1.0"),
            ):
                (root / path).write_text(
                    f'[package]\nname = "{package}"\nversion = "{version}"\n',
                    encoding="utf-8",
                )
            self.assertEqual(
                manifest_versions(root),
                {"wire": "0.19.0", "fsm": "0.6.0", "rpki": "0.1.0"},
            )

            root_manifest = (root / "Cargo.toml").read_text(encoding="utf-8")
            (root / "Cargo.toml").write_text(
                root_manifest.replace(
                    'rustbgpd-wire = { version = "0.19.0"',
                    'rustbgpd-wire = { version = "9.9.9"',
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "workspace-pin:wire"):
                manifest_versions(root)

    def test_each_semantic_heading_is_required(self) -> None:
        titles = (
            "Crate map and publish status",
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
