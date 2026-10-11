#!/usr/bin/env python3
"""Mutation proofs for the local release preflight."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("check_release_preflight.py")
SPEC = importlib.util.spec_from_file_location("release_preflight", PATH)
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)

ROOT_MANIFEST = '[workspace.package]\nversion = "1.2.3"\n\n[workspace.dependencies]\n'
# A release-ready tree: wire 0.2.0 has a dated changelog, a workspace pin, and
# matching README and embedding-guide snippets.
RELEASE_TREE = {
    "Cargo.toml": ROOT_MANIFEST + 'demo-wire = { path = "crates/wire", version = "0.2.0" }\n',
    check.EMBEDDING: '### 3.1 Decode\n\n```toml\ndemo-wire = "0.2.0"\nbytes = "1"\n```\n',
    "CHANGELOG.md": "# Changelog\n\n## [Unreleased]\n\n## [1.2.3] — 2026-01-02\n\n- Fix.\n",
    "crates/wire/Cargo.toml": '[package]\nname = "demo-wire"\nversion = "0.2.0"\n',
    "crates/wire/CHANGELOG.md": "# Changelog\n\n## 0.2.0 - 2026-01-02\n\n- Fix.\n",
    "crates/wire/README.md": (
        "# demo-wire\n\n`demo-wire 0.2.0` fixes a thing.\n\n## Usage\n\n"
        "```toml\ndemo-wire = \"0.2.0\"\n```\n"
    ),
    "crates/private/Cargo.toml": '[package]\nname = "p"\nversion = "9.9.9"\npublish = false\n',
    "scripts/test_check_metric_release_notes.py": (
        "import unittest\n\n\nclass Stub(unittest.TestCase):\n"
        "    def test_stub(self):\n        pass\n"
    ),
    "scripts/check_metric_release_notes.py": "",
}
USAGE = "## Usage\n\n"
DECODE = "### 3.1 Decode\n\n"
# A second publishable crate that depends on wire, for the multi-crate sections.
RPKI_TREE = {
    "Cargo.toml": RELEASE_TREE["Cargo.toml"] + 'demo-rpki = { path = "crates/rpki", version = "0.3.0" }\n',
    "crates/rpki/Cargo.toml": '[package]\nname = "demo-rpki"\nversion = "0.3.0"\n',
    "crates/rpki/CHANGELOG.md": "# Changelog\n\n## 0.3.0 - 2026-01-02\n\n- Fix.\n",
    "crates/rpki/README.md": USAGE + 'demo-rpki = "0.3.0"\ndemo-wire = "0.2.0"\n',
    check.EMBEDDING: RELEASE_TREE[check.EMBEDDING]
    + '### 3.4 Validate\n\ndemo-rpki = "0.3.0"\ndemo-wire = "0.2.0"\n',
}
STAGING = {
    "CHANGELOG.md": "## [Unreleased]\n\n- Pending.\n\n## [1.2.2] — 2026-01-01\n\n- Old.\n",
    "crates/wire/CHANGELOG.md": "# Changelog\n\n## 0.2.0 - Unreleased\n\n- Fix.\n",
    "crates/wire/README.md": (
        "`demo-wire 0.2.0`, prepared in the source\ncheckout, fixes it.\n\n"
        '## Usage\n\ndemo-wire = "0.2.0"\n'
    ),
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

    def statuses(self, root: Path, mode: str) -> tuple[str, list[str]]:
        mode, rows = check.preflight(root, mode, heavy=False)
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

    def test_crate_changelog_must_open_with_the_pending_version(self):
        root = self.tree(**{"crates/wire/CHANGELOG.md": "# Changelog\n\n## 0.1.0 - 2025-01-01\n"})
        errors = check.crate_heading_errors(root, check.publishable_crates(root))
        self.assertIn("not the manifest version 0.2.0", errors[0])
        # A longer version that merely starts with the manifest one is not a match.
        root = self.tree(**{"crates/wire/CHANGELOG.md": "## 0.2.01 - 2026-01-02\n"})
        self.assertTrue(check.crate_heading_errors(root, check.publishable_crates(root)))

    def test_readme_snippets_and_workspace_pins_must_name_the_manifest_version(self):
        # The v0.76.0 defect: a packaged README naming the previous release.
        for relative, text, needle in (
            ("crates/wire/README.md", USAGE + 'demo-wire = "0.1.0"\n', "names demo-wire '0.1.0'"),
            ("crates/wire/README.md", USAGE + 'demo-wire="0.2.01"\n', "names demo-wire '0.2.01'"),
            (
                "crates/wire/README.md",
                USAGE + 'demo-wire = { version = "0.1.0", path = "../wire" }\n',
                "names demo-wire '0.1.0'",
            ),
            (check.EMBEDDING, DECODE + 'demo-wire = "0.1.0"\n', "embedding.md names demo-wire '0.1.0'"),
            # A deleted, path-only or misplaced required line fails too.
            ("crates/wire/README.md", USAGE + 'bytes = "1"\n', "`## Usage` has no versioned demo-wire"),
            (
                "crates/wire/README.md",
                USAGE + 'demo-wire = { path = "../wire" }\n',
                "`## Usage` has no versioned demo-wire",
            ),
            ("crates/wire/README.md", 'demo-wire = "0.2.0"\n', "has no `## Usage` section"),
            (check.EMBEDDING, DECODE + 'bytes = "1"\n', "`### 3.1` has no versioned demo-wire"),
            (
                check.EMBEDDING,
                DECODE + '### 3.2 Next\n\ndemo-wire = "0.2.0"\n',
                "`### 3.1` has no versioned demo-wire",
            ),
            (
                "Cargo.toml",
                ROOT_MANIFEST + 'demo-wire = { path = "crates/wire", version = "0.1.0" }\n',
                "workspace pin for demo-wire is '0.1.0'",
            ),
            (
                "Cargo.toml",
                ROOT_MANIFEST + 'demo-wire = "0.1.0"\n',
                "workspace pin for demo-wire is '0.1.0'",
            ),
            (
                "Cargo.toml",
                ROOT_MANIFEST + 'demo-wire = { path = "crates/wire" }\n',
                "workspace pin for demo-wire is None",
            ),
            ("Cargo.toml", ROOT_MANIFEST, "workspace pin for demo-wire is None"),
        ):
            with self.subTest(text=text):
                root = self.tree(**{relative: text})
                errors = check.version_copy_errors(root, check.publishable_crates(root))
                self.assertEqual(len(errors), 1)
                self.assertIn(needle, errors[0])
                # It fails in staging mode too, not only on the release commit.
                _, statuses = self.statuses(self.tree(**{**STAGING, relative: text}), "auto")
                self.assertEqual(statuses[3], "FAIL")
        # Other dependencies, and path-only snippets, carry no checked version;
        # the string form of a matching workspace pin is accepted.
        root = self.tree(
            **{
                "crates/wire/README.md": USAGE
                + 'demo-wire = "0.2.0"\nbytes = "1"\np = "0.0.1"\ndemo-wire = { path = "x" }\n',
                "Cargo.toml": ROOT_MANIFEST + 'demo-wire = "0.2.0"\n',
            }
        )
        self.assertEqual(check.version_copy_errors(root, check.publishable_crates(root)), [])

    def test_each_section_keeps_every_required_dependency_line(self):
        root = self.tree(**RPKI_TREE)
        self.assertEqual(check.version_copy_errors(root, check.publishable_crates(root)), [])
        for relative, text, needle in (
            (
                "crates/rpki/README.md",
                USAGE + 'demo-wire = "0.2.0"\n',
                "rpki/README.md `## Usage` has no versioned demo-rpki",
            ),
            (
                check.EMBEDDING,
                RELEASE_TREE[check.EMBEDDING] + '### 3.4 Validate\n\ndemo-rpki = "0.3.0"\n',
                "`### 3.4` has no versioned demo-wire",
            ),
        ):
            with self.subTest(text=text):
                root = self.tree(**{**RPKI_TREE, relative: text})
                errors = check.version_copy_errors(root, check.publishable_crates(root))
                self.assertEqual(len(errors), 1)
                self.assertIn(needle, errors[0])

    def test_release_needs_dated_crate_heading_and_released_readme_wording(self):
        for relative, text, needle in (
            ("crates/wire/CHANGELOG.md", STAGING["crates/wire/CHANGELOG.md"], "release date"),
            ("crates/wire/CHANGELOG.md", "## 0.2.0\n", "release date"),
            ("crates/wire/README.md", STAGING["crates/wire/README.md"], "still says"),
            ("crates/wire/README.md", "The source checkout prepares 0.2.0.\n", "still says"),
            ("crates/wire/README.md", "Version 0.2.0 is prepared in this\ncheckout.\n", "still says"),
            ("crates/wire/README.md", "The Prepared 0.2.0 release pairs with fsm.\n", "still says"),
        ):
            with self.subTest(text=text):
                root = self.tree(**{relative: text})
                errors = check.crate_release_errors(root, check.publishable_crates(root))
                self.assertEqual(len(errors), 1)
                self.assertIn(needle, errors[0])

    def test_root_changelog_needs_the_workspace_section_without_a_v(self):
        for changelog in (
            "## [Unreleased]\n\n## [1.2.2] — 2026-01-01\n\n- Old.\n",
            "## [v1.2.3] — 2026-01-02\n\n- Fix.\n",
            "## [1.2.3] — 2026-01-02\n\n## [1.2.2] — 2026-01-01\n\n- Old.\n",
        ):
            with self.subTest(changelog=changelog):
                root = self.tree(**{"CHANGELOG.md": changelog})
                self.assertTrue(check.root_changelog_errors(root))

    def test_publish_dry_run_names_every_publishable_package(self):
        commands = check.heavy_commands(check.publishable_crates(self.tree()))
        self.assertEqual(commands[-1][-2:], ["-p", "demo-wire"])
        self.assertNotIn("p", commands[-1])


if __name__ == "__main__":
    unittest.main()
