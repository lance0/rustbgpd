#!/usr/bin/env python3
"""Mutation proofs for the Markdown test-pin list and its CI selector."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_markdown_test_pins as guard

MANIFEST = '[package]\nname = "demo"\n\n[[bin]]\nname = "demo-bin"\npath = "src/main.rs"\n'
FILES = {
    "Cargo.toml": MANIFEST,
    "README.md": "# demo\n",
    "docs/guide.md": "guide\n",
    "docs/scan.md": "scan\n",
    "src/lib.rs": 'pub mod library;\n#[cfg(feature = "internals")]\npub mod config;\n',
    "src/library.rs": 'const README: &str = include_str!("../README.md");\n',
    "src/main.rs": "mod config;\nfn main() {}\n",
    "src/config.rs": 'fn t() { assert!(err.contains("docs/guide.md")); }\n',
    "tests/guide.rs": 'const GUIDE: &str = include_str!("../docs/guide.md");\n',
    "tests/scanner.rs": 'fn t() { git(["ls-files", "--", "*.md"]); }\n',
}
PINS = {
    "pinned": {"README.md": ["src/library.rs"], "docs/guide.md": ["tests/guide.rs"]},
    "not_read": {"docs/guide.md": ["src/config.rs"]},
    "all_markdown": ["tests/scanner.rs"],
}


class MarkdownTestPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        for relative, text in FILES.items():
            self.write(relative, text)
        self.write_pins(PINS)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", relative], check=True)

    def write_pins(self, pins: dict) -> None:
        self.write(str(guard.LIST), json.dumps(pins))

    def test_classified_fixture_passes(self) -> None:
        self.assertEqual(guard.check(self.root), [])

    def test_unlisted_markdown_read_fails(self) -> None:
        self.write("tests/new_reader.rs", 'let s = read_to_string(root.join("docs/scan.md"));\n')
        errors = guard.check(self.root)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("tests/new_reader.rs names docs/scan.md", errors[0])

    def test_manifest_dir_concat_read_resolves_to_the_package(self) -> None:
        self.write(
            "tests/concat.rs",
            'include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/scan.md"));\n',
        )
        self.assertIn("docs/scan.md", " ".join(guard.check(self.root)))

    def test_stale_pinned_entry_fails(self) -> None:
        self.write("tests/guide.rs", "// the guide is no longer read\n")
        errors = guard.check(self.root)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("docs/guide.md is listed for tests/guide.rs", errors[0])

    def test_unresolved_literal_fails(self) -> None:
        self.write("tests/missing.rs", 'include_str!("../docs/missing.md");\n')
        self.assertIn("cannot resolve Markdown literal", " ".join(guard.check(self.root)))

    def test_double_classification_fails(self) -> None:
        pins = json.loads(json.dumps(PINS))
        pins["not_read"]["docs/guide.md"].append("tests/guide.rs")
        self.write_pins(pins)
        self.assertIn("both pinned and not_read", " ".join(guard.check(self.root)))

    def test_unlisted_and_stale_all_markdown_scanners_fail(self) -> None:
        self.write("tests/scanner.rs", "fn t() {}\n")
        self.write("tests/other_scanner.rs", 'git(["grep", "x", "--", "*.md"]);\n')
        errors = " ".join(guard.check(self.root))
        self.assertIn("tests/other_scanner.rs scans every Markdown file", errors)
        self.assertIn("all_markdown lists tests/scanner.rs", errors)

    def test_targets_follow_the_compiling_crate_target(self) -> None:
        self.assertEqual(guard.target(self.root, "tests/guide.rs"), ("demo", "--test guide"))
        self.assertEqual(guard.target(self.root, "src/library.rs"), ("demo", "--lib"))
        self.assertEqual(guard.target(self.root, "src/main.rs"), ("demo", "--bin demo-bin"))
        # A feature-gated library module is compiled into the default binary.
        self.assertEqual(guard.target(self.root, "src/config.rs"), ("demo", "--bin demo-bin"))

    def test_select_runs_owning_targets_and_markdown_scanners(self) -> None:
        self.assertEqual(
            guard.select(self.root, ["docs/guide.md", "src/lib.rs"]),
            ["-p demo --test guide --test scanner"],
        )
        self.assertEqual(guard.select(self.root, ["docs/scan.md"]), ["-p demo --test scanner"])
        self.assertEqual(guard.select(self.root, ["src/lib.rs", "Cargo.toml"]), [])

    def test_repository_use_cases_selects_the_strict_config_test(self) -> None:
        selected = guard.select(guard.ROOT, ["docs/explanation/use-cases.md"])
        rustbgpd = next(line for line in selected if line.startswith("-p rustbgpd "))
        self.assertIn("--test starter_configs_check_strict", rustbgpd)

    def test_repository_unpinned_markdown_selects_no_rust_target(self) -> None:
        # Whole-tree Markdown checks live in scripts/check_markdown_claims.py, so
        # `all_markdown` is empty and an unpinned document compiles nothing.
        self.assertEqual(guard.load_list(guard.ROOT)["all_markdown"], [])
        self.assertEqual(guard.select(guard.ROOT, ["docs/explanation/feature-tour.md"]), [])


if __name__ == "__main__":
    unittest.main()
