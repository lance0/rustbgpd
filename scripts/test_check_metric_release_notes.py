#!/usr/bin/env python3
"""Regression tests for the emitted-metric release-note contract."""

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PATH = Path(__file__).with_name("check_metric_release_notes.py")
SPEC = importlib.util.spec_from_file_location("metric_release_note_check", PATH)
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class MetricReleaseNoteContractTests(unittest.TestCase):
    def test_live_release_delta_is_exact_and_documented(self):
        baseline = check.parse_baseline(check.BASELINE.read_text(encoding="utf-8"))
        current = set(check.METRIC_CHECK.workspace_metric_inventory())
        version = check.workspace_version(check.CARGO_MANIFEST.read_bytes())
        check.validate_workspace_release(version)
        section = check.target_notes(check.CHANGELOG.read_text(encoding="utf-8"), check.ROOT)

        added, removed = check.validate_release_notes(baseline, current, section)

        self.assertEqual(len(baseline), 219)
        self.assertEqual(
            added,
            {"bgp_fib_owned_state_persist_failures_total", "bgp_max_prefix_latched"},
        )
        self.assertEqual(removed, set())

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

    def test_previous_release_cannot_satisfy_target_metric_changes(self):
        changelog = f"""# Changelog

## [{check.TARGET_CHANGELOG_SECTION}]

- Other change.

## [0.70.0] - 2026-09-13

- Rename `bgp_old_name` to `bgp_new_name`; remove `bgp_removed`.
"""
        section = check.release_section(changelog, check.TARGET_CHANGELOG_SECTION)
        with self.assertRaisesRegex(
            ValueError,
            "added=bgp_new_name; removed=bgp_old_name, bgp_removed",
        ):
            check.validate_release_notes(
                {"bgp_stable", "bgp_old_name", "bgp_removed"},
                {"bgp_stable", "bgp_new_name"},
                section,
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

    def test_empty_unreleased_target_without_family_changes_passes(self):
        changelog = f"""# Changelog

## [{check.UNRELEASED_SECTION}]

## [0.71.0] - 2026-09-20

- Export `bgp_carried_total`.
"""
        section = check.release_section(changelog, check.UNRELEASED_SECTION)
        self.assertEqual(section.strip(), "")

        added, removed = check.validate_release_notes(
            {"bgp_stable"}, {"bgp_stable"}, section, {}
        )

        self.assertEqual(added, set())
        self.assertEqual(removed, set())

    def test_empty_unreleased_target_with_a_family_change_names_the_family(self):
        changelog = f"""# Changelog

## [{check.UNRELEASED_SECTION}]

## [0.71.0] - 2026-09-20

- Export `bgp_new_total`.
"""
        section = check.release_section(changelog, check.UNRELEASED_SECTION)
        self.assertEqual(section.strip(), "")

        with self.assertRaisesRegex(ValueError, "added=bgp_new_total"):
            check.validate_release_notes(
                {"bgp_stable"}, {"bgp_stable", "bgp_new_total"}, section, {}
            )

    def test_fragment_notes_count_and_are_required_alongside_unreleased(self):
        # Fragments are pending only while the target is [Unreleased]; a
        # release commit moves the target, so pin it for this fixture.
        target = mock.patch.object(
            check, "TARGET_CHANGELOG_SECTION", check.UNRELEASED_SECTION
        )
        target.start()
        self.addCleanup(target.stop)
        changelog = f"""# Changelog

## [{check.UNRELEASED_SECTION}]

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
                baseline, current, check.target_notes(changelog, root), {}
            )

        (root / "changelog.d/added-fragment.md").write_text(
            "### Added\n\n- Export `bgp_in_fragment_total`\n  over two lines.\n",
            encoding="utf-8",
        )
        added, removed = check.validate_release_notes(
            baseline, current, check.target_notes(changelog, root), {}
        )
        self.assertEqual(added, {"bgp_in_section_total", "bgp_in_fragment_total"})
        self.assertEqual(removed, set())

        (root / "changelog.d/broken.md").write_text("- no category\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "changelog.d/broken.md: first line"):
            check.target_notes(changelog, root)

    def test_empty_versioned_target_section_still_fails_closed(self):
        changelog = """# Changelog

## [0.71.0] - 2026-09-20

## [0.70.2] - 2026-09-18

- Export `bgp_carried_total`.
"""
        with self.assertRaisesRegex(ValueError, r"section for 0\.71\.0 is empty"):
            check.release_section(changelog, "0.71.0")

    def test_workspace_release_change_requires_explicit_target_review(self):
        check.validate_workspace_release("0.72.0")
        with self.assertRaisesRegex(
            ValueError,
            "roll the baseline to that release in the post-release commit",
        ):
            check.validate_workspace_release("0.72.1")

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

    def test_baseline_metadata_ordering_and_names_fail_closed(self):
        cases = (
            (
                '{"release":"v0.71.0","source_commit":"x","families":["bgp_a"]}',
                "release must be",
            ),
            (
                '{"release":"v0.72.0","source_commit":"x","families":["bgp_a"]}',
                "commit must be",
            ),
            (
                '{"release":"v0.72.0","source_commit":"'
                + check.BASELINE_COMMIT
                + '","families":["bgp_b","bgp_a"]}',
                "sorted and unique",
            ),
            (
                '{"release":"v0.72.0","source_commit":"'
                + check.BASELINE_COMMIT
                + '","families":["not a metric"]}',
                "invalid family name",
            ),
        )
        for document, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                ValueError, message
            ):
                check.parse_baseline(document)


if __name__ == "__main__":
    unittest.main()
