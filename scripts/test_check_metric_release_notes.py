#!/usr/bin/env python3
"""Regression tests for the emitted-metric release-note contract."""

import importlib.util
import unittest
from pathlib import Path


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
        section = check.release_section(
            check.CHANGELOG.read_text(encoding="utf-8"),
            check.TARGET_CHANGELOG_SECTION,
        )

        added, removed = check.validate_release_notes(baseline, current, section)

        self.assertEqual(len(baseline), 196)
        self.assertEqual(
            added,
            {
                "bgp_evpn_nlri_discarded_total",
                "bgp_dataplane_reconcile_planning_failures_total",
                "bgp_path_attribute_discarded_total",
                "bgp_peer_session_state",
                "bgp_rib_policy_transition_total",
                "bgp_session_down_total",
                "bgp_session_lifecycle_source_dropped_total",
                "bgp_sighup_reload_outcomes_total",
            },
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

    def test_only_current_unreleased_section_counts(self):
        changelog = """# Changelog

## [Unreleased]

- Other change.

## [0.67.0] - 2026-08-26

- `bgp_new_total`

## [0.66.0] - 2026-08-22

- `bgp_new_total`
"""
        section = check.release_section(changelog, check.TARGET_CHANGELOG_SECTION)
        with self.assertRaisesRegex(ValueError, "added=bgp_new_total"):
            check.validate_release_notes(set(), {"bgp_new_total"}, section, {})

    def test_workspace_release_change_requires_explicit_target_review(self):
        check.validate_workspace_release("0.67.0")
        with self.assertRaisesRegex(
            ValueError,
            "select the target changelog section explicitly and review whether the "
            "released metric baseline must roll",
        ):
            check.validate_workspace_release("0.68.0")

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
                '{"release":"v0.65.0","source_commit":"x","families":["bgp_a"]}',
                "release must be",
            ),
            (
                '{"release":"v0.67.0","source_commit":"x","families":["bgp_a"]}',
                "commit must be",
            ),
            (
                '{"release":"v0.67.0","source_commit":"'
                + check.BASELINE_COMMIT
                + '","families":["bgp_b","bgp_a"]}',
                "sorted and unique",
            ),
            (
                '{"release":"v0.67.0","source_commit":"'
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
