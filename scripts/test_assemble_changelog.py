#!/usr/bin/env python3
"""Regression tests for the changelog fragment assembler."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("assemble-changelog.py")
SPEC = importlib.util.spec_from_file_location("assemble_changelog", PATH)
assemble = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assemble)

CHANGELOG = """# Changelog

## [Unreleased]

### Added

- Existing added entry.

### Fixed

- Existing fixed entry, hard-wrapped over
  two lines.
  **Operator-visible:** it stays as written.

## [1.0.0] — 2026-01-01

### Added

- Released entry.
"""
MULTILINE = """### Fixed

- A fix wrapped over several lines with a
  [reference link](docs/reference/stability.md) and a
  `**bold**`-free `code span`.
  **Operator-visible:** the second paragraph of the bullet.
- A second bullet in the same fragment.
"""


class AssembleChangelogTests(unittest.TestCase):
    def tree(self, changelog: str = CHANGELOG, **fragments: str) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
        (root / "changelog.d").mkdir()
        (root / "changelog.d/README.md").write_text("# Fragments\n", encoding="utf-8")
        for name, text in fragments.items():
            (root / "changelog.d" / name).write_text(text, encoding="utf-8")
        return root

    def test_assembly_is_deterministic_and_keeps_existing_entries_first(self):
        fragments = {
            "fixed-b.md": "### Fixed\n\n- Fragment fix B.\n",
            "added-z.md": "### Added\n\n- Fragment add Z.\n",
            "fixed-a.md": "### Fixed\n\n- Fragment fix A.\n",
            "upgrade-x.md": "### Upgrade notes\n\n- Fragment upgrade note.\n",
            "security-y.md": "### Security\n\n- Fragment security note.\n",
        }
        root = self.tree(**fragments)
        first = assemble.run(root, check=False)
        once = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        second = assemble.run(self.tree(**fragments), check=False)
        self.assertEqual(first, second)
        self.assertEqual(
            once, assemble.assemble(CHANGELOG, assemble.load_fragments(self.tree(**fragments)))
        )
        self.assertEqual(
            once,
            """# Changelog

## [Unreleased]

### Security

- Fragment security note.

### Added

- Existing added entry.
- Fragment add Z.

### Fixed

- Existing fixed entry, hard-wrapped over
  two lines.
  **Operator-visible:** it stays as written.
- Fragment fix A.
- Fragment fix B.

### Upgrade notes

- Fragment upgrade note.

## [1.0.0] — 2026-01-01

### Added

- Released entry.
""",
        )
        self.assertEqual(sorted(p.name for p in (root / "changelog.d").iterdir()), ["README.md"])
        self.assertIn("assembled 5 changelog fragments", first)

    def test_multiline_bullet_and_links_survive_byte_for_byte(self):
        root = self.tree(**{"fixed-multi.md": MULTILINE})
        assemble.run(root, check=False)
        text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(MULTILINE[len("### Fixed\n\n") :], text)
        self.assertEqual(text.count("### Fixed"), 1)

    def test_second_assembly_with_no_fragments_changes_nothing(self):
        root = self.tree(**{"fixed-a.md": "### Fixed\n\n- Fragment fix A.\n"})
        assemble.run(root, check=False)
        once = (root / "CHANGELOG.md").read_bytes()
        self.assertEqual(assemble.run(root, check=False), "no changelog fragments to assemble")
        self.assertEqual((root / "CHANGELOG.md").read_bytes(), once)
        self.assertEqual(once.decode().count("Fragment fix A."), 1)

    def test_check_mode_validates_without_writing(self):
        root = self.tree(**{"fixed-a.md": "### Fixed\n\n- Fragment fix A.\n"})
        self.assertIn("1 changelog fragments assemble cleanly", assemble.run(root, check=True))
        self.assertEqual((root / "CHANGELOG.md").read_text(encoding="utf-8"), CHANGELOG)
        self.assertTrue((root / "changelog.d/fixed-a.md").exists())
        with self.assertRaisesRegex(ValueError, "bad.md: first line"):
            assemble.run(self.tree(**{"bad.md": "- no heading\n"}), check=True)

    def test_empty_unreleased_gains_the_subsection(self):
        changelog = "# Changelog\n\n## [Unreleased]\n\n## [1.0.0] — 2026-01-01\n\n- Old.\n"
        root = self.tree(changelog, **{"changed-a.md": "### Changed\n\n- New.\n"})
        assemble.run(root, check=False)
        self.assertEqual(
            (root / "CHANGELOG.md").read_text(encoding="utf-8"),
            "# Changelog\n\n## [Unreleased]\n\n### Changed\n\n- New.\n\n"
            "## [1.0.0] — 2026-01-01\n\n- Old.\n",
        )

    def test_malformed_fragments_are_refused_by_name(self):
        cases = {
            "bad-heading.md": ("### Bogus\n\n- Bullet.\n", "bad-heading.md: first line"),
            "trailing-space.md": ("### Fixed \n\n- Bullet.\n", "trailing-space.md: first line"),
            "no-heading.md": ("- Bullet.\n", "no-heading.md: first line"),
            "empty.md": ("### Fixed\n\n\n", "empty.md: no bullet"),
            "blank.md": ("", "blank.md: first line"),
            "prose.md": ("### Fixed\n\nNot a bullet.\n", "prose.md: body must start"),
            "star.md": ("### Fixed\n\n* Star bullet.\n", "star.md: body must start"),
            "prose-after.md": (
                "### Fixed\n\n- Bullet.\nLoose line.\n",
                "prose-after.md:3: expected a `- ` bullet",
            ),
            "conflict.md": (
                "### Fixed\n\n<<<<<<< HEAD\n- Ours.\n=======\n- Theirs.\n>>>>>>> main\n",
                "conflict.md: unresolved merge-conflict marker",
            ),
            "stray.txt": ("### Fixed\n\n- Bullet.\n", "stray.txt: not a `.md` fragment"),
        }
        for name, (text, message) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
                assemble.load_fragments(self.tree(**{name: text}))
        root = self.tree()
        (root / "changelog.d/dir.md").mkdir()
        with self.assertRaisesRegex(ValueError, "dir.md: not a `.md` fragment"):
            assemble.load_fragments(root)

    def test_duplicate_bullet_is_refused(self):
        root = self.tree(**{"added-dup.md": "### Added\n\n- Existing added   entry.\n"})
        with self.assertRaisesRegex(
            ValueError, r"added-dup.md: bullet already present in \[Unreleased\]"
        ):
            assemble.run(root, check=True)
        root = self.tree(
            **{
                "fixed-a.md": "### Fixed\n\n- Same text.\n",
                "fixed-b.md": "### Fixed\n\n- Same text.\n",
            }
        )
        with self.assertRaisesRegex(
            ValueError, "fixed-b.md: bullet already present in changelog.d/fixed-a.md"
        ):
            assemble.run(root, check=True)
        self.assertEqual((root / "CHANGELOG.md").read_text(encoding="utf-8"), CHANGELOG)

    def test_missing_unreleased_section_is_refused(self):
        root = self.tree("# Changelog\n\n## [1.0.0] — 2026-01-01\n\n- Old.\n")
        with self.assertRaisesRegex(ValueError, r"no `## \[Unreleased\]` section"):
            assemble.run(root, check=True)

    def test_missing_fragment_directory_means_no_fragments(self):
        root = self.tree()
        (root / "changelog.d/README.md").unlink()
        (root / "changelog.d").rmdir()
        self.assertEqual(assemble.load_fragments(root), [])


if __name__ == "__main__":
    unittest.main()
