#!/usr/bin/env python3
"""Mutation proofs for the fail-closed public tracker ID gate."""

from __future__ import annotations

import gzip
import hashlib
import sys
import tempfile
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


def write_fixture(root: Path, relative: str, contents: str | bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(contents, str):
        path.write_text(contents, encoding="utf-8")
    else:
        path.write_bytes(contents)
    return path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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

    def test_artifact_home_paths_cover_plain_gzip_and_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clean = write_fixture(
                root,
                "docs/perf/artifacts/example/clean.txt",
                "/home/<user>/run $HOME/run ${HOME}/run\n",
            )
            linux = write_fixture(root, "docs/perf/artifacts/linux.txt", "/home/alice/run\n")
            mac = root / "docs/perf/artifacts/example/mac.txt.gz"
            with gzip.open(mac, "wb") as handle:
                handle.write(b"/Users/bob/run\n")
            failures = guard.audit_artifact_home_paths([clean, linux, mac], root)
            self.assertTrue(any("/home/alice" in failure for failure in failures))
            self.assertTrue(any("/Users/bob" in failure for failure in failures))

    def test_artifact_walk_failures_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "no tracked"):
                guard.audit_artifact_home_paths([], root)

            corrupt = write_fixture(root, "docs/perf/artifacts/corrupt.gz", b"not gzip")
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "cannot read"):
                guard.audit_artifact_home_paths([corrupt], root)

            unreadable = write_fixture(root, "docs/perf/artifacts/unreadable", "clean\n")
            unreadable.chmod(0)
            try:
                with self.assertRaisesRegex(guard.TrackerIdGuardError, "cannot read"):
                    guard.audit_artifact_home_paths([unreadable], root)
            finally:
                unreadable.chmod(0o600)

            target = write_fixture(root, "target.txt", "clean\n")
            symlink = root / "docs/perf/artifacts/example/link.txt"
            symlink.parent.mkdir(parents=True)
            symlink.symlink_to(target)
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "symlink"):
                guard.audit_artifact_home_paths([symlink], root)

    def test_artifact_git_enumeration_failure_is_closed(self) -> None:
        original = guard.tracked_files
        guard.tracked_files = lambda: (_ for _ in ()).throw(
            guard.TrackerIdGuardError("cannot list tracked files: synthetic failure")
        )
        try:
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "synthetic failure"):
                guard.audit_artifact_home_paths()
        finally:
            guard.tracked_files = original

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

    def test_nested_seals_and_dot_paths_verify_without_widening_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            readme = write_fixture(
                root, "docs/perf/artifacts/example/README.md", "sealed\n"
            )
            data = write_fixture(
                root, "docs/perf/artifacts/example/nested/data.tsv", "row\n"
            )
            nested = write_fixture(
                root,
                "docs/perf/artifacts/example/nested/SHA256SUMS",
                f"{digest(data)}  data.tsv\n",
            )
            manifest = write_fixture(
                root,
                "docs/perf/artifacts/example/SHA256SUMS",
                f"{digest(readme)}  ./README.md\n"
                f"{digest(nested)}  ./nested/SHA256SUMS\n"
                f"{digest(data)}  ./nested/data.tsv\n",
            )
            public = write_fixture(root, "docs/public.md", "living\n")
            outside = write_fixture(
                root, "docs/SHA256SUMS", f"{digest(public)}  public.md\n"
            )
            sealed = guard.sealed_paths(
                [manifest, readme, nested, data, outside, public], root
            )
            self.assertIn("docs/perf/artifacts/example/README.md", sealed)
            self.assertIn("docs/perf/artifacts/example/nested/data.tsv", sealed)
            self.assertNotIn("docs/public.md", sealed)

    def test_malformed_or_unsafe_seals_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = write_fixture(
                root, "docs/perf/artifacts/example/README.md", "sealed\n"
            )
            outside = write_fixture(root, "docs/perf/artifacts/README.md", "outside\n")
            checksum = digest(payload)
            manifest = root / "docs/perf/artifacts/example/SHA256SUMS"
            cases = {
                "empty": "",
                "malformed": f"{checksum} README.md\n",
                "absolute": f"{checksum}  {payload}\n",
                "escape": f"{digest(outside)}  ../README.md\n",
                "duplicate": (
                    f"{checksum}  README.md\n{checksum}  ./README.md\n"
                ),
                "digest mismatch": f"{'0' * 64}  README.md\n",
            }
            for label, contents in cases.items():
                with self.subTest(label=label):
                    write_fixture(root, manifest.relative_to(root).as_posix(), contents)
                    with self.assertRaises(guard.TrackerIdGuardError):
                        guard.sealed_paths([manifest, payload, outside], root)

    def test_missing_untracked_and_symlink_entries_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_fixture(
                root,
                "docs/perf/artifacts/example/SHA256SUMS",
                f"{'0' * 64}  missing.txt\n",
            )
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "is missing or escapes"):
                guard.sealed_paths([manifest], root)

            payload = write_fixture(
                root, "docs/perf/artifacts/example/untracked.txt", "sealed\n"
            )
            manifest.write_text(
                f"{digest(payload)}  untracked.txt\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "not tracked"):
                guard.sealed_paths([manifest], root)

            target = write_fixture(
                root, "docs/perf/artifacts/example/target.txt", "sealed\n"
            )
            symlink = root / "docs/perf/artifacts/example/link.txt"
            symlink.symlink_to(target)
            manifest.write_text(f"{digest(target)}  link.txt\n", encoding="utf-8")
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "symlink"):
                guard.sealed_paths([manifest, symlink], root)
            manifest.unlink()
            manifest.symlink_to(target)
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "seal .* is a symlink"):
                guard.sealed_paths([manifest], root)

    def test_missing_receipt_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = write_fixture(root, "docs/README.md", "living\n")
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "no tracked"):
                guard.sealed_paths([public], root)

    def test_broken_walk_fails_loudly(self) -> None:
        original_tracked = guard.tracked_files
        original_sealed = guard.sealed_paths
        guard.tracked_files = lambda: [guard.ROOT / "Cargo.toml"]
        guard.sealed_paths = lambda _paths: set()
        try:
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "walk is broken"):
                guard.discover_documents()
        finally:
            guard.tracked_files = original_tracked
            guard.sealed_paths = original_sealed

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
