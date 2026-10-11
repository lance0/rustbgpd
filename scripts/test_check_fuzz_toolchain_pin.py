#!/usr/bin/env python3
"""Mutation proofs for the fail-closed fuzz-toolchain pin gate."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_fuzz_toolchain_pin as guard


PIN_LINE = f'toolchain="$(cat {guard.PIN_PATH})"'

FLOATING_SELECTIONS = (
    "      - uses: dtolnay/rust-toolchain@master",
    "      - uses: dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c",
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
    "      - uses: dtolnay/rust-toolchain@v1",
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
