#!/usr/bin/env python3
"""Mutation proofs for the local release preflight."""

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("check_release_preflight.py")
SPEC = importlib.util.spec_from_file_location("release_preflight", PATH)
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)

# A release-ready tree: wire 0.2.0 is ahead of the published 0.1.0.
RELEASE_TREE = {
    "Cargo.toml": '[workspace.package]\nversion = "1.2.3"\n',
    "CHANGELOG.md": "# Changelog\n\n## [Unreleased]\n\n## [1.2.3] — 2026-01-02\n\n- Fix.\n",
    "crates/wire/Cargo.toml": '[package]\nname = "demo-wire"\nversion = "0.2.0"\n',
    "crates/wire/CHANGELOG.md": "# Changelog\n\n## 0.2.0 - 2026-01-02\n\n- Fix.\n",
    "crates/wire/README.md": "# demo-wire\n\n`demo-wire 0.2.0` fixes a thing.\n",
    "crates/private/Cargo.toml": '[package]\nname = "p"\nversion = "9.9.9"\npublish = false\n',
    check.RECORD: '{"wire": "0.1.0"}\n',
    "scripts/test_check_metric_release_notes.py": (
        "import unittest\n\n\nclass Stub(unittest.TestCase):\n"
        "    def test_stub(self):\n        pass\n"
    ),
    "scripts/check_metric_release_notes.py": "",
}
STAGING = {
    "CHANGELOG.md": "## [Unreleased]\n\n- Pending.\n\n## [1.2.2] — 2026-01-01\n\n- Old.\n",
    "crates/wire/CHANGELOG.md": "# Changelog\n\n## 0.2.0 - Unreleased\n\n- Fix.\n",
    "crates/wire/README.md": "`demo-wire 0.2.0`, prepared in the source\ncheckout, fixes it.\n",
}


class ReleasePreflightTests(unittest.TestCase):
    def tree(self, **overrides: str) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative, text in {**RELEASE_TREE, **overrides}.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text, encoding="utf-8")
        return root

    def commit(self, root: Path, message: str) -> str:
        identity = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        for args in (["init", "-q"], ["add", "-A"], [*identity, "commit", "-qm", message]):
            subprocess.run(["git", *args], cwd=root, check=True)
        return check.git(root, "rev-parse", "HEAD").strip()

    def statuses(self, root: Path, mode: str) -> tuple[str, list[str]]:
        mode, rows = check.preflight(root, mode, self.commit(root, "tree"), heavy=False)
        return mode, [status for status, _, _ in rows]

    def test_release_tree_runs_every_fast_check(self):
        mode, statuses = self.statuses(self.tree(), "auto")
        self.assertEqual(mode, "release")
        self.assertEqual(statuses, ["ok"] * 6 + ["skipped [--heavy]"] * 3)

    def test_staging_tree_passes_and_reports_the_release_only_skips(self):
        mode, statuses = self.statuses(self.tree(**STAGING), "auto")
        self.assertEqual(mode, "staging")
        self.assertEqual(
            statuses, ["ok"] * 4 + ["skipped [release-only]"] * 2 + ["skipped [--heavy]"] * 3
        )

    def test_release_mode_does_not_relax_checks_for_a_staging_tree(self):
        _, statuses = self.statuses(self.tree(**STAGING), "release")
        self.assertEqual(statuses[4:6], ["FAIL", "FAIL"])

    def test_pending_fragment_with_empty_unreleased_is_staging(self):
        fragment = {"changelog.d/fixed-a.md": "### Fixed\n\n- Pending fix.\n"}
        mode, statuses = self.statuses(self.tree(**fragment), "auto")
        self.assertEqual(mode, "staging")
        self.assertEqual(statuses[1], "ok")
        self.assertEqual(check.detect_mode(self.tree()), "release")

    def test_release_mode_refuses_a_leftover_fragment(self):
        root = self.tree(**{"changelog.d/fixed-a.md": "### Fixed\n\n- Pending fix.\n"})
        _, statuses = self.statuses(root, "release")
        self.assertEqual(statuses[1], "FAIL")
        errors = check.fragment_errors(root, release=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("still holds fixed-a.md", errors[0])
        self.assertEqual(check.fragment_errors(root, release=False), [])

    def test_malformed_fragment_fails_in_every_mode(self):
        root = self.tree(**{"changelog.d/broken.md": "### Bogus\n\n- Bullet.\n"})
        for release in (False, True):
            with self.subTest(release=release):
                errors = check.fragment_errors(root, release)
                self.assertEqual(len(errors), 1)
                self.assertIn("changelog.d/broken.md: first line", errors[0])
        self.assertEqual(check.detect_mode(root), "staging")

    def test_failing_metric_release_note_checker_fails(self):
        root = self.tree(**{"scripts/check_metric_release_notes.py": "raise SystemExit(1)\n"})
        errors = check.metric_release_note_errors(root)
        self.assertEqual(errors, ["`scripts/check_metric_release_notes.py` exited 1"])

    def test_version_bump_without_readme_change_fails(self):
        root = self.tree(**{"crates/wire/Cargo.toml": '[package]\nname = "w"\nversion = "0.1.0"\n'})
        base = self.commit(root, "base")
        (root / "crates/wire/Cargo.toml").write_text(RELEASE_TREE["crates/wire/Cargo.toml"])
        self.commit(root, "bump")
        errors = check.readme_freshness_errors(root, base)
        self.assertEqual(len(errors), 1)
        self.assertIn("crates/wire/README.md is untouched", errors[0])

        (root / "crates/wire/README.md").write_text("# demo-wire\n\nReviewed.\n")
        self.commit(root, "readme")
        self.assertEqual(check.readme_freshness_errors(root, base), [])

    def test_crate_changelog_must_open_with_the_pending_version(self):
        root = self.tree(**{"crates/wire/CHANGELOG.md": "# Changelog\n\n## 0.1.0 - 2025-01-01\n"})
        errors = check.crate_heading_errors(root, check.pending_crates(root))
        self.assertIn("not the manifest version 0.2.0", errors[0])
        # A longer version that merely starts with the pending one is not a match.
        root = self.tree(**{"crates/wire/CHANGELOG.md": "## 0.2.01 - 2026-01-02\n"})
        self.assertTrue(check.crate_heading_errors(root, check.pending_crates(root)))

    def test_release_needs_dated_crate_heading_and_released_readme_wording(self):
        for relative, text, needle in (
            ("crates/wire/CHANGELOG.md", STAGING["crates/wire/CHANGELOG.md"], "release date"),
            ("crates/wire/CHANGELOG.md", "## 0.2.0\n", "release date"),
            ("crates/wire/README.md", STAGING["crates/wire/README.md"], "still says"),
            ("crates/wire/README.md", "The source checkout prepares 0.2.0.\n", "still says"),
        ):
            with self.subTest(text=text):
                root = self.tree(**{relative: text})
                errors = check.crate_release_errors(root, check.pending_crates(root))
                self.assertEqual(len(errors), 1)
                self.assertIn(needle, errors[0])

    def test_published_crate_is_not_pending(self):
        root = self.tree(**{check.RECORD: '{"wire": "0.2.0"}\n', **STAGING})
        self.assertEqual(check.pending_crates(root), {})

    def test_record_must_list_exactly_the_publishable_crates(self):
        for record in ('{"fsm": "0.1.0"}', '{"wire": "0.1.0", "private": "9.9.9"}', "[]"):
            with self.subTest(record=record), self.assertRaises(check.PreflightError):
                check.pending_crates(self.tree(**{check.RECORD: record}))

    def test_root_changelog_needs_the_workspace_section_without_a_v(self):
        for changelog in (
            "## [Unreleased]\n\n## [1.2.2] — 2026-01-01\n\n- Old.\n",
            "## [v1.2.3] — 2026-01-02\n\n- Fix.\n",
            "## [1.2.3] — 2026-01-02\n\n## [1.2.2] — 2026-01-01\n\n- Old.\n",
        ):
            with self.subTest(changelog=changelog):
                root = self.tree(**{"CHANGELOG.md": changelog})
                self.assertTrue(check.root_changelog_errors(root))

    def test_publish_dry_run_names_only_pending_packages(self):
        commands = check.heavy_commands({"wire": ("demo-wire", "0.2.0")})
        self.assertEqual(commands[-1][-2:], ["-p", "demo-wire"])
        self.assertEqual(len(check.heavy_commands({})), 2)


if __name__ == "__main__":
    unittest.main()
