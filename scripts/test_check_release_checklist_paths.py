#!/usr/bin/env python3
"""Mutation proofs for release-checklist path and proof-mapping gates."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check_release_checklist_paths.py"

CHECKLIST = """\
# Release checklist

| Source owner | Required release proofs |
| --- | --- |
| `src/evpn_es_drain.rs` | M66, M67 |
| `src/evpn_es_link_drain.rs` | M67 |
| `src/evpn_segment.rs` | M38, M66, M67 |

| Release proof | Topology | Assertion script |
| --- | --- | --- |
| `M38` | `tests/interop/m38-evpn-df-election.clab.yml` | `tests/interop/scripts/test-m38-evpn-df-election.sh` |
| `M66` | `tests/interop/m66-evpn-es-drain-handover.clab.yml` | `tests/interop/scripts/test-m66-evpn-es-drain-handover.sh` |
| `M67` | `tests/interop/m67-evpn-link-drain-failover.clab.yml` | `tests/interop/scripts/test-m67-evpn-link-drain-failover.sh` |

If the release touches the parser (`src/parser.rs`) or the
originator (`src/evpn_originator/`), run M-01:

Review the API (`proto/rustbgpd.proto`), renderer
(`tools/rs-config-render/`), and Rust configuration (`.cargo/config.toml`).
The release archive stages `share/systemd/`, including
`share/systemd/rustbgpd.service`.

```sh
containerlab deploy -t tests/interop/m01.clab.yml
bash tests/interop/scripts/test-m01.sh
```

Unfenced prose such as docs/test improvements is not a path, and a
prefixed `$PWD/tests/prefixed.rs` token is not a repo path.
These path-shaped tokens are not repository paths: `RibService/SetFibTable`,
`ghcr.io/lance0/rustbgpd:latest`, `docker/metadata-action`, and
`releases/latest/download/`.
"""

FIXTURE_PATHS = (
    "src/evpn_es_drain.rs",
    "src/evpn_es_link_drain.rs",
    "src/evpn_segment.rs",
    "src/parser.rs",
    "src/evpn_originator/",
    "tests/interop/m01.clab.yml",
    "tests/interop/m38-evpn-df-election.clab.yml",
    "tests/interop/m66-evpn-es-drain-handover.clab.yml",
    "tests/interop/m67-evpn-link-drain-failover.clab.yml",
    "tests/interop/scripts/test-m01.sh",
    "tests/interop/scripts/test-m38-evpn-df-election.sh",
    "tests/interop/scripts/test-m66-evpn-es-drain-handover.sh",
    "tests/interop/scripts/test-m67-evpn-link-drain-failover.sh",
    "proto/rustbgpd.proto",
    "tools/rs-config-render/",
    ".cargo/config.toml",
    "examples/systemd/",
    "examples/systemd/rustbgpd.service",
)


class ReleaseChecklistPathTests(unittest.TestCase):
    def run_checker(
        self, checklist: str, paths: tuple[str, ...]
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs" / "project").mkdir(parents=True)
            (root / "docs" / "project" / "release-checklist.md").write_text(
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
        """Passes with recognized paths present; prose tokens are not extracted."""
        result = self.run_checker(CHECKLIST, FIXTURE_PATHS)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fails_when_required_owner_mapping_is_removed(self) -> None:
        """Fails when a source owner disappears while its proof paths remain."""
        checklist = CHECKLIST.replace(
            "| `src/evpn_es_link_drain.rs` | M67 |\n", ""
        )
        result = self.run_checker(checklist, FIXTURE_PATHS)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "missing required release-proof owner mapping for "
            "`src/evpn_es_link_drain.rs`",
            result.stderr,
        )

    def test_fails_when_required_owner_proof_is_removed(self) -> None:
        """Fails when an owner silently drops one of its required proofs."""
        checklist = CHECKLIST.replace(
            "| `src/evpn_segment.rs` | M38, M66, M67 |",
            "| `src/evpn_segment.rs` | M38, M66 |",
        )
        result = self.run_checker(checklist, FIXTURE_PATHS)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "release-proof owner `src/evpn_segment.rs` is missing required "
            "proofs: M67",
            result.stderr,
        )

    def test_fails_when_proof_source_mapping_is_changed(self) -> None:
        """Fails when an M-number is repointed at a different existing proof."""
        checklist = CHECKLIST.replace(
            "`tests/interop/m67-evpn-link-drain-failover.clab.yml`",
            "`tests/interop/m66-evpn-es-drain-handover.clab.yml`",
        )
        result = self.run_checker(checklist, FIXTURE_PATHS)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("proof-source mapping for `M67` must be", result.stderr)

    def test_non_repository_path_tokens_stay_excluded(self) -> None:
        """Path-shaped API, image, action, and download tokens stay out."""
        result = self.run_checker(
            "`RibService/SetFibTable` `ghcr.io/lance0/rustbgpd:latest` "
            "`docker/metadata-action` `releases/latest/download/`\n",
            (),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no paths were extracted", result.stderr)

    def test_fails_on_missing_backticked_trigger_path(self) -> None:
        """Fails when a backticked trigger-list file is gone."""
        remaining = tuple(p for p in FIXTURE_PATHS if p != "src/parser.rs")
        self.assert_fails(remaining, "src/parser.rs")

    def test_fails_on_missing_trigger_directory(self) -> None:
        """Fails when a trailing-slash trigger directory is gone."""
        remaining = tuple(p for p in FIXTURE_PATHS if p != "src/evpn_originator/")
        self.assert_fails(remaining, "src/evpn_originator/")

    def test_fails_on_missing_fenced_reproduction_path(self) -> None:
        """Fails when a bare path inside a fenced block is gone."""
        remaining = tuple(
            p for p in FIXTURE_PATHS if p != "tests/interop/scripts/test-m01.sh"
        )
        self.assert_fails(remaining, "tests/interop/scripts/test-m01.sh")

    def test_fails_on_missing_proto_or_tool_path(self) -> None:
        """Fails when newly recognized proto or tool paths disappear."""
        for missing in ("proto/rustbgpd.proto", "tools/rs-config-render/"):
            with self.subTest(missing=missing):
                remaining = tuple(p for p in FIXTURE_PATHS if p != missing)
                self.assert_fails(remaining, missing)

    def test_generated_share_path_checks_its_repository_source(self) -> None:
        """Archive-only share paths resolve by prefix to checked sources."""
        self.assertNotIn("share/systemd/", FIXTURE_PATHS)
        remaining = tuple(
            p for p in FIXTURE_PATHS if not p.startswith("examples/systemd/")
        )
        self.assert_fails(remaining, "examples/systemd/")

    def test_other_share_paths_remain_repository_paths(self) -> None:
        """A non-generated share path is still checked directly."""
        result = self.run_checker("`share/repository-data/`\n", ())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("share/repository-data/", result.stderr)

    def test_fails_when_no_paths_are_extracted(self) -> None:
        """Fails when the parse yields nothing: an inert gate is broken."""
        result = self.run_checker("# Empty\n\nNo paths named here.\n", ())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no paths were extracted", result.stderr)


if __name__ == "__main__":
    unittest.main()
