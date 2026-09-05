"""Exercise the consumer path contract without a website checkout."""

import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_site_manifest import load_manifest


class SiteManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "docs").mkdir()
        (self.root / "docs/page.md").write_text("# Page\n\nDescription.\n")
        self.manifest = self.root / "docs/site-manifest.json"

    def write(self, value):
        self.manifest.write_text(json.dumps(value))

    def test_valid_mapping_preserves_destination(self):
        entries = {"reference/page.md": "docs/page.md"}
        self.write(entries)
        self.assertEqual(load_manifest(self.root), entries)

    def test_missing_source_fails(self):
        self.write({"page.md": "docs/moved.md", "other.md": "docs/also-moved.md"})
        with self.assertRaisesRegex(ValueError, "missing source") as caught:
            load_manifest(self.root)
        self.assertIn("docs/moved.md", str(caught.exception))
        self.assertIn("docs/also-moved.md", str(caught.exception))

    def test_output_file_cannot_also_be_a_directory(self):
        self.write({"page.md": "docs/page.md", "page.md/child.md": "docs/child.md"})
        with self.assertRaisesRegex(ValueError, "inside another output file"):
            load_manifest(self.root)

    def test_malformed_or_empty_manifest_fails(self):
        for value in ({}, [], None, {"page.md": 1}):
            with self.subTest(value=value):
                self.write(value)
                with self.assertRaises(ValueError):
                    load_manifest(self.root)
        self.manifest.write_text("{")
        with self.assertRaises(ValueError):
            load_manifest(self.root)

    def test_invalid_paths_fail(self):
        for path in ("/page.md", "../page.md", "a/../page.md", "a//page.md", "./page.md", "a\\page.md", "page.txt"):
            for label in ("source", "destination"):
                with self.subTest(path=path, label=label):
                    self.write({path: "docs/page.md"} if label == "destination" else {"page.md": path})
                    with self.assertRaisesRegex(ValueError, "invalid .* path"):
                        load_manifest(self.root)

    def test_reserved_destination_and_non_docs_source_fail(self):
        for entries in ({"index.md": "docs/page.md"}, {"page.md": "README.md"}):
            self.write(entries)
            with self.assertRaises(ValueError):
                load_manifest(self.root)

    def test_duplicate_destinations_and_sources_fail(self):
        self.manifest.write_text('{"page.md":"docs/page.md","page.md":"docs/page.md"}')
        with self.assertRaisesRegex(ValueError, "duplicate destination"):
            load_manifest(self.root)
        self.write({"a.md": "docs/page.md", "b.md": "docs/page.md"})
        with self.assertRaisesRegex(ValueError, "duplicate source"):
            load_manifest(self.root)

    def test_source_symlink_cannot_escape_docs(self):
        (self.root / "outside.md").write_text("outside")
        (self.root / "docs/link.md").symlink_to(self.root / "outside.md")
        self.write({"page.md": "docs/link.md"})
        with self.assertRaisesRegex(ValueError, "escapes docs"):
            load_manifest(self.root)


if __name__ == "__main__":
    unittest.main()
