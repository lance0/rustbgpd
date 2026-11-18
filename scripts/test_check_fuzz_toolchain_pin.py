#!/usr/bin/env python3
"""Mutation proofs for the fail-closed fuzz-toolchain pin gate."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_fuzz_toolchain_pin as guard


PIN_LINE = f'toolchain="$(cat {guard.PIN_PATH})"'
SEED_LINE = f"      run: {guard.SEED_SCRIPT}"

KNOWN_BUILD_PATHS = (
    ".github/workflows/fuzz.yml",
    ".oss-scanner/Dockerfile",
    "fuzz/build-fuzzers.sh",
    "justfile",
)

FUZZ_BUILDS = (
    '          cargo fuzz run "$t" -- -max_total_time=120',
    "  cargo fuzz build -O --debug-assertions",
    '        cargo +"$TOOLCHAIN" fuzz build',
    '    && cargo "+$(cat fuzz/rust-nightly.txt)" fuzz build',
)

FLOATING_SELECTIONS = (
    "      - uses: dtolnay/rust-toolchain@master",
    "      - uses: dtolnay/rust-toolchain@2c7215f132e9",
    "      - uses: dtolnay/rust-toolchain@v1",
    "      - uses: dtolnay/rust-toolchain@v1.2.3",
    "      - uses: dtolnay/rust-toolchain@nightly",
    "      - uses: dtolnay/rust-toolchain@stable",
    "      - uses: dtolnay/rust-toolchain@beta",
    "      - uses: dtolnay/rust-toolchain@nightly-2026-07-07",
    "          toolchain: nightly",
    "          toolchain: nightly-2026-07-07",
    "          cargo +nightly fuzz list",
    "          cargo +nightly-2026-07-07 fuzz run decode_update",
    '          RUSTUP_TOOLCHAIN=nightly-2026-07-07',
    "          toolchain=nightly",
    '          toolchain="nightly"',
    "          RUSTUP_TOOLCHAIN=nightly",
    "        export RUSTUP_TOOLCHAIN=nightly",
    "ENV RUSTUP_TOOLCHAIN nightly",
    "ENV RUSTUP_TOOLCHAIN=nightly",
    # A quoted `#` or a `${#var}` expansion does not start a comment.
    '          echo "#"; toolchain=nightly',
    "          [ ${#t} -gt 0 ] && toolchain=nightly",
)

PIN_DERIVED_SELECTIONS = (
    "      - uses: dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8 # v1",
    "          toolchain: ${{ steps.nightly.outputs.toolchain }}",
    '    && cargo "+$toolchain" install cargo-fuzz --version 0.13.2 --locked',
    '        cargo +"$TOOLCHAIN" fuzz build',
    "        export RUSTUP_TOOLCHAIN",
    # A comment cannot select a toolchain, so guidance may quote a bad one.
    "      # never set toolchain=nightly or RUSTUP_TOOLCHAIN=nightly-2026-07-07",
    "# Do not use dtolnay/rust-toolchain@nightly or `cargo +nightly`.",
    "          true  # never set toolchain=nightly",
    "RUN true # cargo +nightly-2026-07-07 fuzz list",
)


class FuzzToolchainPinTests(unittest.TestCase):
    def test_repository_consumers_are_discovered_and_clean(self) -> None:
        consumers = guard.discover_consumers()
        self.assertTrue(consumers, "consumer discovery must not be empty")
        self.assertIn(".github/workflows/fuzz.yml", consumers)
        for relative, text in consumers.items():
            with self.subTest(consumer=relative):
                self.assertEqual(guard.audit_consumer(relative, text), [])

    def test_dropped_pin_reference_is_rejected(self) -> None:
        failures = guard.audit_consumer(
            "fuzz/oss-fuzz/Dockerfile",
            'RUN rustup toolchain install "$toolchain" --profile minimal\n',
        )
        self.assertTrue(any("no longer reads" in failure for failure in failures))

    def test_pin_named_only_in_a_comment_is_rejected(self) -> None:
        workflow = (
            f"      # {guard.PIN_PATH} holds the single reviewed nightly.\n"
            "      - run: |\n"
            "          toolchain=nightly\n"
            '          echo "RUSTUP_TOOLCHAIN=$toolchain" >> "$GITHUB_ENV"\n'
        )
        for relative, text in (
            (".github/workflows/fuzz.yml", workflow),
            ("fuzz/build-fuzzers.sh", f"# Reads {guard.PIN_PATH}.\n"),
            ("fuzz/oss-fuzz/Dockerfile", f"  # {guard.PIN_PATH}\n"),
            ("fuzz/build-fuzzers.sh", f"true # {guard.PIN_PATH}\n"),
            ("fuzz/oss-fuzz/Dockerfile", f"RUN true\t# reads {guard.PIN_PATH}\n"),
            (".github/workflows/fuzz.yml", f"      - run: true  # {guard.PIN_PATH}\n"),
        ):
            with self.subTest(consumer=relative):
                failures = guard.audit_consumer(relative, text)
                self.assertTrue(
                    any("no longer reads" in failure for failure in failures),
                    failures,
                )

    def test_pin_read_after_a_non_comment_hash_is_accepted(self) -> None:
        for line in (
            f'          echo "#" && toolchain="$(cat {guard.PIN_PATH})"',
            f"          echo 'a #b' && toolchain=$(cat {guard.PIN_PATH})",
            f'          [ ${{#t}} -eq 0 ] && t="$(cat {guard.PIN_PATH})"',
            f'RUN echo $# && toolchain="$(cat {guard.PIN_PATH})"',
        ):
            with self.subTest(line=line):
                self.assertEqual(
                    guard.audit_consumer(".github/workflows/fuzz.yml", f"{line}\n"),
                    [],
                )

    def test_every_floating_selection_is_rejected(self) -> None:
        for line in FLOATING_SELECTIONS:
            with self.subTest(line=line):
                failures = guard.audit_consumer(
                    ".github/workflows/fuzz.yml", f"{PIN_LINE}\n{line}\n"
                )
                self.assertTrue(failures, f"{line!r} must be rejected")

    def test_pin_derived_selections_are_accepted(self) -> None:
        for line in PIN_DERIVED_SELECTIONS:
            with self.subTest(line=line):
                failures = guard.audit_consumer(
                    ".github/workflows/fuzz.yml", f"{PIN_LINE}\n{line}\n"
                )
                self.assertEqual(failures, [], f"{line!r} must be accepted")

    def test_repository_build_paths_are_discovered_and_seeded(self) -> None:
        builds = guard.discover_fuzz_builds()
        for relative in KNOWN_BUILD_PATHS:
            self.assertIn(relative, builds)
        for relative, text in builds.items():
            with self.subTest(build_path=relative):
                self.assertEqual(guard.audit_build_path(relative, text), [])

    def test_build_without_a_prior_seed_is_rejected(self) -> None:
        for build in FUZZ_BUILDS:
            for name, text in (
                ("missing", f"{build}\n"),
                ("comment only", f"  # {SEED_LINE}\n{build}\n"),
                ("after the build", f"{build}\n{SEED_LINE}\n"),
            ):
                with self.subTest(build=build, seed=name):
                    failures = guard.audit_build_path("fuzz/build-fuzzers.sh", text)
                    self.assertTrue(
                        any(guard.SEED_SCRIPT in f for f in failures), failures
                    )
            with self.subTest(build=build, seed="before the build"):
                self.assertEqual(
                    guard.audit_build_path(
                        "fuzz/build-fuzzers.sh", f"{SEED_LINE}\n{build}\n"
                    ),
                    [],
                )

    def test_build_discovery_does_not_need_a_toolchain_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            helper = root / "helper.sh"
            helper.write_text('cd crates/wire\ncargo +"$TOOLCHAIN" fuzz build\n')
            prose = root / "notes.md"
            prose.write_text("cargo fuzz run decode_update\n")
            original_root, original_files = guard.ROOT, guard.tracked_files
            guard.ROOT = root
            guard.tracked_files = lambda: [helper, prose]
            try:
                builds = guard.discover_fuzz_builds()
            finally:
                guard.ROOT, guard.tracked_files = original_root, original_files
        self.assertEqual(list(builds), ["helper.sh"])
        self.assertTrue(guard.audit_build_path("helper.sh", builds["helper.sh"]))

    def test_seed_script_seeds_every_fuzz_workspace_from_the_root_lockfile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "fuzz").mkdir()
            shutil.copy2(guard.ROOT / guard.SEED_SCRIPT, root / guard.SEED_SCRIPT)
            (root / "Cargo.lock").write_text("# workspace lockfile\n")
            for crate in ("a", "b"):
                (root / "crates" / crate / "fuzz").mkdir(parents=True)
            (root / "crates" / "c").mkdir()
            subprocess.run([root / guard.SEED_SCRIPT], cwd="/", check=True)
            for crate in ("a", "b"):
                with self.subTest(crate=crate):
                    seeded = root / "crates" / crate / "fuzz" / "Cargo.lock"
                    self.assertEqual(seeded.read_text(), "# workspace lockfile\n")
            self.assertFalse((root / "crates" / "c" / "Cargo.lock").exists())

    def test_broken_build_walk_fails_loudly(self) -> None:
        original = guard.tracked_files
        guard.tracked_files = lambda: []
        try:
            with self.assertRaisesRegex(guard.PinGuardError, "walk is broken"):
                guard.discover_fuzz_builds()
        finally:
            guard.tracked_files = original

    def test_broken_walk_fails_loudly(self) -> None:
        original = guard.tracked_files
        guard.tracked_files = lambda: []
        try:
            with self.assertRaisesRegex(guard.PinGuardError, "walk is broken"):
                guard.discover_consumers()
        finally:
            guard.tracked_files = original


if __name__ == "__main__":
    unittest.main()
