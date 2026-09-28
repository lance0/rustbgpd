#!/usr/bin/env python3
"""Regression tests for the emitted-metric release-note contract."""

import importlib.util
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


PATH = Path(__file__).with_name("check_metric_release_notes.py")
SPEC = importlib.util.spec_from_file_location("metric_release_note_check", PATH)
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class MetricReleaseNoteContractTests(unittest.TestCase):
    def test_consumed_new_family_without_release_note_fails(self):
        baseline = {"bgp_existing_total"}
        current = {
            "bgp_existing_total": "ordinary",
            "bgp_consumed_new_total": "ordinary",
        }
        # Consumer coverage and release-note coverage are independent contracts.
        check.METRIC_CHECK.validate_coverage(current, set(current), {})

        with self.assertRaisesRegex(ValueError, "added=bgp_consumed_new_total"):
            check.validate_release_notes(
                baseline,
                set(current),
                "\n### Added\n\n- Added a consumed metric.\n",
                {},
            )

    def test_consumed_new_family_with_release_note_passes(self):
        baseline = {"bgp_existing_total"}
        current = {
            "bgp_existing_total": "ordinary",
            "bgp_consumed_new_total": "ordinary",
        }
        check.METRIC_CHECK.validate_coverage(current, set(current), {})

        added, removed = check.validate_release_notes(
            baseline,
            set(current),
            "\n### Added\n\n- Export `bgp_consumed_new_total`.\n",
            {},
        )

        self.assertEqual(added, {"bgp_consumed_new_total"})
        self.assertEqual(removed, set())

    def test_metric_name_substrings_do_not_count_as_release_notes(self):
        for documented in ("bgp_new_total_suffix", "prefix_bgp_new_total"):
            with self.subTest(documented=documented), self.assertRaisesRegex(
                ValueError, "added=bgp_new_total"
            ):
                check.validate_release_notes(
                    set(),
                    {"bgp_new_total"},
                    f"\n- Export `{documented}`.\n",
                    {},
                )

    def test_removal_and_rename_require_old_and_new_names(self):
        baseline = {"bgp_stable", "bgp_removed", "bgp_old_name"}
        current = {"bgp_stable", "bgp_new_name"}

        with self.assertRaisesRegex(
            ValueError, "removed=bgp_old_name, bgp_removed"
        ):
            check.validate_release_notes(
                baseline,
                current,
                "\n- Rename to `bgp_new_name`.\n",
                {},
            )

        added, removed = check.validate_release_notes(
            baseline,
            current,
            "\n- Rename `bgp_old_name` to `bgp_new_name`; remove `bgp_removed`.\n",
            {},
        )
        self.assertEqual(added, {"bgp_new_name"})
        self.assertEqual(removed, {"bgp_old_name", "bgp_removed"})

    def test_released_sections_cannot_document_a_later_change(self):
        changelog = """# Changelog

## [Unreleased]

- Other change.

## [0.70.0] - 2026-09-13

- Rename `bgp_old_name` to `bgp_new_name`; remove `bgp_removed`.
"""
        notes = check.notes_since(changelog, "v0.70.0")
        with self.assertRaisesRegex(
            ValueError,
            "added=bgp_new_name; removed=bgp_old_name, bgp_removed",
        ):
            check.validate_release_notes(
                {"bgp_stable", "bgp_old_name", "bgp_removed"},
                {"bgp_stable", "bgp_new_name"},
                notes,
                {},
            )

    def test_untagged_release_section_documents_changes_since_the_tag(self):
        # A release commit: the new section exists, its tag does not yet.
        changelog = """# Changelog

## [Unreleased]

## [0.71.0] - 2026-09-20

- Export `bgp_new_total`.

## [0.70.2] - 2026-09-18

- Export `bgp_older_total`.
"""
        added, _ = check.validate_release_notes(
            {"bgp_stable"},
            {"bgp_stable", "bgp_new_total"},
            check.notes_since(changelog, "v0.70.2"),
            {},
        )
        self.assertEqual(added, {"bgp_new_total"})
        # Once v0.71.0 is tagged, its section is history and the same change
        # would need a new note.
        with self.assertRaisesRegex(ValueError, "added=bgp_new_total"):
            check.validate_release_notes(
                {"bgp_stable"},
                {"bgp_stable", "bgp_new_total"},
                check.notes_since(changelog, "v0.71.0"),
                {},
            )

    def test_unreleased_must_name_every_changed_metric_family(self):
        section = "\n- Rename a metric to `bgp_new_name`.\n"
        with self.assertRaisesRegex(
            ValueError, "removed=bgp_old_name, bgp_removed"
        ):
            check.validate_release_notes(
                {"bgp_stable", "bgp_old_name", "bgp_removed"},
                {"bgp_stable", "bgp_new_name"},
                section,
                {},
            )

    def test_empty_unreleased_with_a_family_change_names_the_family(self):
        changelog = """# Changelog

## [Unreleased]

## [0.71.0] - 2026-09-20

- Export `bgp_new_total`.
"""
        notes = check.notes_since(changelog, "v0.71.0")
        added, removed = check.validate_release_notes(
            {"bgp_stable"}, {"bgp_stable"}, notes, {}
        )
        self.assertEqual((added, removed), (set(), set()))
        with self.assertRaisesRegex(ValueError, "added=bgp_new_total"):
            check.validate_release_notes(
                {"bgp_stable"}, {"bgp_stable", "bgp_new_total"}, notes, {}
            )

    def test_missing_or_duplicate_release_heading_fails_closed(self):
        for changelog in (
            "# Changelog\n\n## [Unreleased]\n",
            "## [0.71.0]\n\n## [0.71.0]\n",
        ):
            with self.subTest(changelog=changelog), self.assertRaisesRegex(
                ValueError, "CHANGELOG section for 0.71.0"
            ):
                check.notes_since(changelog, "v0.71.0")

    def test_fragment_notes_count_and_are_required_alongside_unreleased(self):
        changelog = """# Changelog

## [Unreleased]

- Export `bgp_in_section_total`.

## [0.71.0] - 2026-09-20

- Export `bgp_carried_total`.
"""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "changelog.d").mkdir()
        baseline = {"bgp_stable"}
        current = {"bgp_stable", "bgp_in_section_total", "bgp_in_fragment_total"}

        with self.assertRaisesRegex(ValueError, "added=bgp_in_fragment_total$"):
            check.validate_release_notes(
                baseline, current, check.target_notes(changelog, root, "v0.71.0"), {}
            )

        (root / "changelog.d/added-fragment.md").write_text(
            "### Added\n\n- Export `bgp_in_fragment_total`\n  over two lines.\n",
            encoding="utf-8",
        )
        added, removed = check.validate_release_notes(
            baseline, current, check.target_notes(changelog, root, "v0.71.0"), {}
        )
        self.assertEqual(added, {"bgp_in_section_total", "bgp_in_fragment_total"})
        self.assertEqual(removed, set())

        (root / "changelog.d/broken.md").write_text("- no category\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "changelog.d/broken.md: first line"):
            check.target_notes(changelog, root, "v0.71.0")

    def test_exceptions_are_reasoned_narrow_and_nonredundant(self):
        with self.assertRaisesRegex(ValueError, "specific reasons"):
            check.validate_release_notes(
                set(), {"bgp_new"}, "\n- Internal change.\n", {"bgp_new": "short"}
            )
        with self.assertRaisesRegex(ValueError, "stale or not changed"):
            check.validate_release_notes(
                set(),
                {"bgp_new"},
                "\n- Internal change.\n",
                {"bgp_unknown": "A specific public-contract exception reason."},
            )
        with self.assertRaisesRegex(ValueError, "now documented"):
            check.validate_release_notes(
                set(),
                {"bgp_new"},
                "\n- Export `bgp_new`.\n",
                {"bgp_new": "A specific public-contract exception reason."},
            )

    def test_baseline_is_the_previous_release_read_by_its_own_parser(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)

        def run(*args: str) -> str:
            return subprocess.run(
                ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                cwd=root, check=True, capture_output=True, text=True,
            ).stdout

        def commit(families: list[str], message: str) -> None:
            (root / "scripts").mkdir(exist_ok=True)
            (root / "scripts/check-metric-consumers.py").write_text(
                textwrap.dedent(f"""\
                    def workspace_metric_inventory():
                        return {{name: "ordinary" for name in {families!r}}}
                    """),
                encoding="utf-8",
            )
            run("add", "-A")
            run("commit", "-qm", message)

        run("init", "-q")
        commit(["bgp_shipped"], "first release")
        run("tag", "-a", "v0.1.0", "-m", "v0.1.0")
        commit(["bgp_shipped", "bgp_next"], "second release")
        run("tag", "-a", "v0.2.0", "-m", "v0.2.0")
        commit(["bgp_shipped", "bgp_next", "bgp_later"], "after the release")
        run("tag", "soak-marker")
        # A newer pre-release or malformed version tag is never the baseline.
        run("tag", "-a", "v0.3.0-rc.1", "-m", "v0.3.0-rc.1")
        run("tag", "v0.3")

        self.assertEqual(check.previous_release(root), "v0.2.0")
        # The tag's tree and parser, not HEAD's.
        self.assertEqual(check.release_inventory("v0.1.0", root), {"bgp_shipped"})
        self.assertEqual(
            check.release_inventory("v0.2.0", root), {"bgp_shipped", "bgp_next"}
        )
        self.assertEqual(len(run("worktree", "list").splitlines()), 1)

        # No reachable release tag fails closed, as in a shallow or tagless
        # checkout: a non-release tag, or a release tag HEAD does not
        # contain, is never taken as the baseline.
        run("tag", "-d", "v0.1.0", "v0.2.0")
        with self.assertRaisesRegex(ValueError, "needs history and release tags"):
            check.previous_release(root)
        branch = run("symbolic-ref", "--short", "HEAD").strip()
        run("switch", "-q", "--orphan", "unrelated")
        commit(["bgp_elsewhere"], "unrelated history")
        run("tag", "-a", "v9.9.9", "-m", "v9.9.9")
        run("switch", "-q", branch)
        with self.assertRaisesRegex(ValueError, "needs history and release tags"):
            check.previous_release(root)


if __name__ == "__main__":
    unittest.main()
