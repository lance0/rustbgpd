#!/usr/bin/env python3
"""Mutation proofs for the release-checklist path-existence gate."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check_release_checklist_paths.py"

CHECKLIST = """\
# Release checklist

If the release touches the parser (`src/parser.rs`) or the
originator (`src/evpn_originator/`), run M-01:

```sh
containerlab deploy -t tests/interop/m01.clab.yml
bash tests/interop/scripts/test-m01.sh
```

Unfenced prose such as docs/test improvements is not a path, and a
prefixed `$PWD/tests/prefixed.rs` token is not a repo path.
"""

FIXTURE_PATHS = (
    "src/parser.rs",
    "src/evpn_originator/",
    "tests/interop/m01.clab.yml",
    "tests/interop/scripts/test-m01.sh",
)


class ReleaseChecklistPathTests(unittest.TestCase):
    def run_checker(
        self, checklist: str, paths: tuple[str, ...]
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs" / "RELEASE_CHECKLIST.md").write_text(
                checklist, encoding="utf-8"
            )
            for relative in paths:
                target = root / relative
                if relative.endswith("/"):
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("", encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(CHECKER), str(root)],
                capture_output=True,
                text=True,
            )

    def assert_fails(self, paths: tuple[str, ...], missing: str) -> None:
        result = self.run_checker(CHECKLIST, paths)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(missing, result.stderr)

    def test_passes_when_every_named_path_exists(self) -> None:
        """Green with all named paths present; prose tokens are not extracted."""
        result = self.run_checker(CHECKLIST, FIXTURE_PATHS)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fails_on_missing_backticked_trigger_path(self) -> None:
        """Red when a backticked trigger-list file is gone."""
        remaining = tuple(p for p in FIXTURE_PATHS if p != "src/parser.rs")
        self.assert_fails(remaining, "src/parser.rs")

    def test_fails_on_missing_trigger_directory(self) -> None:
        """Red when a trailing-slash trigger directory is gone."""
        remaining = tuple(p for p in FIXTURE_PATHS if p != "src/evpn_originator/")
        self.assert_fails(remaining, "src/evpn_originator/")

    def test_fails_on_missing_fenced_reproduction_path(self) -> None:
        """Red when a bare path inside a fenced block is gone."""
        remaining = tuple(
            p for p in FIXTURE_PATHS if p != "tests/interop/scripts/test-m01.sh"
        )
        self.assert_fails(remaining, "tests/interop/scripts/test-m01.sh")

    def test_fails_when_no_paths_are_extracted(self) -> None:
        """Red when the parse yields nothing: a gate that cannot fail is broken."""
        result = self.run_checker("# Empty\n\nNo paths named here.\n", ())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no paths were extracted", result.stderr)


if __name__ == "__main__":
    unittest.main()
