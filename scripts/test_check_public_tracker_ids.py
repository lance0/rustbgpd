#!/usr/bin/env python3
"""Mutation proofs for the fail-closed public tracker ID gate."""

from __future__ import annotations

import gzip
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

RUNTIME_POSITIVES = {
    "metric help": (
        'let g = IntGauge::new(\n'
        '    "bgp_example",\n'
        '    "Example gauge (LAN-336). Refreshed per batch.",\n'
        ')\n.expect("valid");\n'
    ),
    "metric opts help": (
        'IntCounterVec::new(Opts::new("bgp_example_total", '
        '"Counted (LAN-283 fail-closed)."), &["peer"])'
    ),
    "warn literal": (
        "warn!(\n"
        "    peer = %label,\n"
        '    "peer flagged slow: outbound queue \\\n'
        '     persistently backlogged (LAN-470)"\n'
        ");\n"
    ),
    "error literal with tracing prefix": (
        'tracing::error!(?op, "install withheld (LAN-283)");\n'
    ),
}

RUNTIME_NEGATIVES = {
    "comment": '// LAN-283 rule 1 observability\nwarn!("foreign row withheld");\n',
    "doc comment": "/// LAN-283: keys withheld.\npub foreign: u32,\n",
    "url in a string is not a comment": (
        'warn!("see https://example.invalid/x"); // LAN-1 comment\n'
    ),
    "lint reason": (
        '#[allow(dead_code, reason = "LAN-311 wiring lands later")]\nfn f() {}\n'
    ),
    "test module assertion": (
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    #[test]\n"
        "    fn t() {\n"
        '        assert_eq!(1, 1, "must hold (LAN-311)");\n'
        '        warn!("even a log in tests (LAN-1)");\n'
        "    }\n"
        "}\n"
    ),
    "test module declaration does not swallow the file": (
        "#[cfg(test)]\nmod tests;\n"
        'let s = "not a metric or log literal (LAN-1)";\n'
    ),
}


def write_fixture(root: Path, relative: str, contents: str | bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(contents, str):
        path.write_text(contents, encoding="utf-8")
    else:
        path.write_bytes(contents)
    return path


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

    def test_moved_history_does_not_exempt_other_project_docs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            historical = (
                "docs/project/roadmap.md",
                "docs/project/roadmap-history.md",
                "docs/project/changelog/older-releases.md",
            )
            public = (
                "docs/project/README.md",
                "docs/project/changelog-notes.md",
                "docs/explanation/architecture.md",
                "docs/reference/known-issues.md",
            )
            paths = [write_fixture(root, name, "LAN-123\n") for name in historical + public]
            with mock.patch.multiple(
                guard,
                ROOT=root,
                tracked_files=lambda: paths,
            ):
                documents = guard.discover_documents()
            self.assertEqual(set(documents), set(public))
            for relative, text in documents.items():
                self.assertTrue(guard.audit_document(relative, text))

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

    def test_repository_runtime_sources_are_discovered_and_clean(self) -> None:
        sources = guard.discover_runtime_sources()
        self.assertIn("crates/telemetry/src/metrics.rs", sources)
        self.assertIn("src/main.rs", sources)
        self.assertFalse(
            [name for name in sources if "/tests/" in name or name.endswith("/tests.rs")],
            "test directories and modules must stay out of the runtime scan",
        )
        for relative, text in sources.items():
            with self.subTest(source=relative):
                self.assertEqual(guard.audit_runtime_text(relative, text), [])

    def test_exported_runtime_text_is_rejected(self) -> None:
        for label, code in RUNTIME_POSITIVES.items():
            with self.subTest(label=label):
                failures = guard.audit_runtime_text("crates/x/src/lib.rs", code)
                self.assertEqual(len(failures), 1, failures)
                self.assertIn("crates/x/src/lib.rs:", failures[0])
        # A continuation line reports the line the ID sits on.
        failures = guard.audit_runtime_text("src/io.rs", RUNTIME_POSITIVES["warn literal"])
        self.assertIn("src/io.rs:4 ", failures[0])
        self.assertIn("'LAN-470'", failures[0])

    def test_conventional_source_cross_references_are_accepted(self) -> None:
        for label, code in RUNTIME_NEGATIVES.items():
            with self.subTest(label=label):
                self.assertEqual(guard.audit_runtime_text("src/lib.rs", code), [])

    def test_artifact_home_paths_cover_plain_gzip_and_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clean = write_fixture(
                root,
                "docs/perf/artifacts/example/clean.txt",
                "/home/<user>/run $HOME/run ${HOME}/run <SOAK_HOME>/run\n",
            )
            linux = write_fixture(
                root,
                "docs/artifacts/soak/example/linux.txt",
                "metadata\n/home/alice/run\n",
            )
            mac = root / "docs/artifacts/soak/example/mac.txt.gz"
            with gzip.open(mac, "wb") as handle:
                handle.write(b"metadata\n/Users/bob/run\n")
            failures = guard.audit_artifact_home_paths([clean, linux, mac], root)
            self.assertEqual(len(failures), 2)
            self.assertTrue(
                any(
                    "docs/artifacts/soak/example/linux.txt:2" in failure
                    and "/home/alice" in failure
                    for failure in failures
                )
            )
            self.assertTrue(
                any(
                    "docs/artifacts/soak/example/mac.txt.gz:2" in failure
                    and "/Users/bob" in failure
                    for failure in failures
                )
            )

    def test_artifact_roots_fail_closed_independently(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            perf = write_fixture(
                root, "docs/perf/artifacts/example/clean.txt", "clean\n"
            )
            soak = write_fixture(
                root, "docs/artifacts/soak/example/clean.txt", "clean\n"
            )
            with self.assertRaisesRegex(
                guard.TrackerIdGuardError, "docs/artifacts/soak"
            ):
                guard.audit_artifact_home_paths([perf], root)
            with self.assertRaisesRegex(
                guard.TrackerIdGuardError, "docs/perf/artifacts"
            ):
                guard.audit_artifact_home_paths([soak], root)

    def test_out_of_scope_artifact_path_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            perf = write_fixture(
                root, "docs/perf/artifacts/example/clean.txt", "clean\n"
            )
            soak = write_fixture(
                root, "docs/artifacts/soak/example/clean.txt", "clean\n"
            )
            outside = write_fixture(
                root, "docs/artifacts/archive/example.txt", "/home/alice/run\n"
            )
            self.assertEqual(
                guard.audit_artifact_home_paths([perf, soak, outside], root), []
            )

    def test_repository_artifact_roots_are_discovered_and_clean(self) -> None:
        self.assertEqual(
            guard.ARTIFACT_ROOTS,
            (Path("docs/perf/artifacts"), Path("docs/artifacts/soak")),
        )
        paths = guard.tracked_files()
        relatives = [path.relative_to(guard.ROOT) for path in paths]
        for artifact_root in guard.ARTIFACT_ROOTS:
            with self.subTest(artifact_root=artifact_root):
                self.assertTrue(
                    any(path.is_relative_to(artifact_root) for path in relatives),
                    f"{artifact_root} must contain tracked evidence",
                )
        self.assertEqual(guard.audit_artifact_home_paths(paths), [])

    def test_artifact_scan_is_chunk_bounded_and_boundary_safe(self) -> None:
        class RecordingStream(io.BytesIO):
            def read(self, size: int = -1) -> bytes:
                if not 0 < size <= guard.READ_SIZE:
                    raise AssertionError(f"unbounded read request: {size}")
                return super().read(size)
            def readline(self, _size: int = -1) -> bytes:
                raise AssertionError("readline must not be used")

        prefix = b"x\n" * (guard.READ_SIZE // 2) + b"x" * (guard.READ_SIZE - 10)
        payload = prefix + b"/home/alice/" + b"z" * (guard.READ_SIZE * 2)
        failures = guard._audit_artifact_stream("artifact", RecordingStream(payload))
        self.assertEqual(len(failures), 1)
        self.assertIn(f"artifact:{guard.READ_SIZE // 2 + 1}", failures[0])
        self.assertLess(len(failures[0]), guard.EXCERPT_SIZE + 100)
        placeholder = b"x" * (guard.READ_SIZE - 3) + b"/home/<user>/run"
        failures = guard._audit_artifact_stream("artifact", RecordingStream(placeholder))
        self.assertEqual(failures, [])

    def test_artifact_walk_failures_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "no tracked"):
                guard.audit_artifact_home_paths([], root)

            perf_clean = write_fixture(
                root, "docs/perf/artifacts/clean.txt", "clean\n"
            )
            soak_clean = write_fixture(
                root, "docs/artifacts/soak/clean.txt", "clean\n"
            )
            corrupt = write_fixture(
                root, "docs/artifacts/soak/corrupt.gz", b"not gzip"
            )
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "cannot read"):
                guard.audit_artifact_home_paths([perf_clean, corrupt], root)

            unreadable = write_fixture(root, "docs/perf/artifacts/unreadable", "clean\n")
            unreadable.chmod(0)
            try:
                with self.assertRaisesRegex(guard.TrackerIdGuardError, "cannot read"):
                    guard.audit_artifact_home_paths([unreadable, soak_clean], root)
            finally:
                unreadable.chmod(0o600)

            target = write_fixture(root, "target.txt", "clean\n")
            symlink = root / "docs/artifacts/soak/example/link.txt"
            symlink.parent.mkdir(parents=True)
            symlink.symlink_to(target)
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "symlink"):
                guard.audit_artifact_home_paths([perf_clean, symlink], root)

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

    def test_artifact_documents_need_no_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [
                write_fixture(root, "README.md", "clean\n"),
                write_fixture(
                    root, "docs/perf/artifacts/new/README.md", "LAN-123\n"
                ),
                write_fixture(root, "docs/artifacts/new/README.md", "LAN-123\n"),
            ]
            with mock.patch.multiple(guard, ROOT=root, tracked_files=lambda: paths):
                documents = guard.discover_documents()
            self.assertEqual(documents, {"README.md": "clean\n"})

    def test_artifact_root_near_misses_remain_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = (
                "docs/public.md",
                "docs/perf/artifacts-extra/README.md",
                "docs/artifacts-extra/README.md",
                "docs/artifacts.md",
            )
            paths = [write_fixture(root, name, "LAN-123\n") for name in names]
            with mock.patch.multiple(guard, ROOT=root, tracked_files=lambda: paths):
                documents = guard.discover_documents()
            self.assertEqual(set(documents), set(names))
            for name, content in documents.items():
                with self.subTest(document=name):
                    self.assertTrue(guard.audit_document(name, content))

    def test_broken_walk_fails_loudly(self) -> None:
        original_tracked = guard.tracked_files
        guard.tracked_files = lambda: [guard.ROOT / "Cargo.toml"]
        try:
            with self.assertRaisesRegex(guard.TrackerIdGuardError, "walk is broken"):
                guard.discover_documents()
        finally:
            guard.tracked_files = original_tracked

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
