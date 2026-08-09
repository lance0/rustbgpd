#!/usr/bin/env python3
"""Mutation proofs for the fail-closed public tracker ID gate."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_public_tracker_ids as guard


CITATIONS = (
    "See LAN-931 for the design.",
    "| Lean daemon build flavors (LAN-548) | ...",
    "closed by LAN-663.",
    "  # contextual `let` (LAN-302)",
)

CLEAN_LINES = (
    "See [ADR-0115](adr/0115-lean-daemon-build-flavors.md).",
    "See [#1041](https://github.com/lance0/rustbgpd/pull/1041).",
    "The LAN party ran until LANE-4 closed.",
    "Milestone M84 covers multi-cache RTR conformance.",
)


class PublicTrackerIdTests(unittest.TestCase):
    def test_repository_documents_are_discovered_and_clean(self) -> None:
        documents = guard.discover_documents()
        self.assertTrue(documents, "document discovery must not be empty")
        self.assertIn("README.md", documents)
        self.assertTrue(
            any(name.startswith("docs/adr/") for name in documents),
            "the ADR tree must be in scope",
        )
        for relative, text in documents.items():
            with self.subTest(document=relative):
                self.assertEqual(guard.audit_document(relative, text), [])

    def test_every_citation_form_is_rejected(self) -> None:
        for line in CITATIONS:
            with self.subTest(line=line):
                failures = guard.audit_document("docs/example.md", f"{line}\n")
                self.assertTrue(failures, f"{line!r} must be rejected")

    def test_clean_references_are_accepted(self) -> None:
        for line in CLEAN_LINES:
            with self.subTest(line=line):
                failures = guard.audit_document("docs/example.md", f"{line}\n")
                self.assertEqual(failures, [], f"{line!r} must be accepted")

    def test_failure_reports_the_line_number(self) -> None:
        failures = guard.audit_document("docs/example.md", "clean\nLAN-931 here\n")
        self.assertEqual(len(failures), 1)
        self.assertIn("docs/example.md:2", failures[0])

    def test_sealed_artifacts_are_exempt_and_still_verify(self) -> None:
        sealed = guard.sealed_paths(guard.tracked_files())
        self.assertIn(
            "docs/perf/artifacts/grouped-withdrawal-fanout-2026-07/README.md",
            sealed,
            "sealed perf-receipt prose must be discovered from its SHA256SUMS",
        )
        self.assertNotIn(
            "docs/perf/artifacts/grouped-withdrawal-fanout-2026-07/README.md",
            guard.discover_documents(),
        )
        # The exemption is only defensible while the seals hold: an unsealed
        # file must never inherit it.
        self.assertNotIn("README.md", sealed)

    def test_broken_walk_fails_loudly(self) -> None:
        original = guard.tracked_files
        guard.tracked_files = lambda: [guard.ROOT / "Cargo.toml"]
        try:
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "walk is broken"):
                guard.discover_documents()
        finally:
            guard.tracked_files = original

    def test_empty_tracked_tree_fails_loudly(self) -> None:
        original = guard.tracked_files
        guard.tracked_files = lambda: (_ for _ in ()).throw(
            guard.TrackerIdGuardError("cannot list tracked files: the tracked tree is empty")
        )
        try:
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "tracked tree is empty"):
                guard.discover_documents()
        finally:
            guard.tracked_files = original


if __name__ == "__main__":
    unittest.main()
