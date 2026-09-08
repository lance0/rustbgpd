#!/usr/bin/env python3
"""Negative proofs for the SIGHUP architecture route inventory."""

import unittest
from pathlib import Path

from scripts import check_sighup_architecture as checker


ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = (ROOT / "docs/explanation/architecture.md").read_text(encoding="utf-8")
SOURCE = (ROOT / "src/config/mod.rs").read_text(encoding="utf-8")


class SighupArchitectureTests(unittest.TestCase):
    @staticmethod
    def row(name):
        return next(line for line in DOCUMENT.splitlines() if line.startswith(f"| `{name}` |"))

    def assert_fails(self, document, diagnostic, source=SOURCE):
        errors = checker.check(document, source)
        self.assertTrue(any(diagnostic in error for error in errors), errors)

    def test_current_source_and_document_pass(self):
        self.assertEqual(checker.check(DOCUMENT, SOURCE), [])

    def test_missing_and_duplicate_rows_fail(self):
        for name in checker.source_routes(SOURCE):
            with self.subTest(name=name):
                row = self.row(name)
                self.assert_fails(DOCUMENT.replace(row + "\n", ""), f"missing route: {name}")
                self.assert_fails(DOCUMENT.replace(row, row + "\n" + row),
                                  f"duplicate route: {name}")

    def test_new_source_route_requires_a_documented_row(self):
        source = SOURCE.replace("pub enum SighupReloadRoute {",
                                "pub enum SighupReloadRoute {\n    Deferred,")
        source = source.replace("if !families.generation &&",
                                "if false { return SighupReloadRoute::Deferred; }\n"
                                "    if !families.generation &&", 1)
        self.assert_fails(DOCUMENT, "missing route: Deferred", source)

    def test_classifier_and_enum_must_agree(self):
        source = SOURCE.replace("pub enum SighupReloadRoute {",
                                "pub enum SighupReloadRoute {\n    Deferred,")
        self.assert_fails(DOCUMENT, "enum/classifier route mismatch", source)

    def test_unknown_or_malformed_documented_route_fails(self):
        self.assert_fails(DOCUMENT.replace("| `Rejected` |", "| `Deferred` |"),
                          "unknown route: Deferred")
        self.assert_fails(DOCUMENT.replace("| `Rejected` |", "| Rejected |"),
                          "malformed route row")

    def test_loose_words_or_rows_outside_the_section_do_not_count(self):
        row = self.row("Rejected")
        document = DOCUMENT.replace(row, "Rejected remains mentioned here.") + "\n" + row + "\n"
        self.assert_fails(document, "missing route: Rejected")

    def test_missing_section_table_or_reference_link_fails(self):
        self.assert_fails(DOCUMENT.replace(checker.SECTION, "### Old reload"),
                          "expected one Config Reload")
        self.assert_fails(DOCUMENT.replace(checker.HEADER, "| Old | Table |"),
                          "expected one Route / Settlement table")
        for link in checker.LINKS:
            self.assert_fails(DOCUMENT.replace(link, "elsewhere.md"),
                              "missing detailed-reference link")

    def test_comments_and_strings_do_not_invent_classifier_routes(self):
        source = SOURCE.replace("if !families.generation &&",
                                '// SighupReloadRoute::Deferred\n'
                                '    let _ = "SighupReloadRoute::Deferred";\n'
                                '    if !families.generation &&', 1)
        self.assertEqual(checker.check(DOCUMENT, source), [])


if __name__ == "__main__":
    unittest.main()
