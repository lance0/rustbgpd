#!/usr/bin/env python3
"""Exercise release transitions and documentation drift with synthetic versions."""

import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from scripts import check_embedding_versions as contract

ROOT = Path(__file__).resolve().parents[1]
PUBLISHED = {"wire": "1.2.3", "fsm": "2.3.4", "rpki": "3.4.5"}
NEXT = {"wire": "2.0.0", "fsm": "3.0.0", "rpki": "4.0.0"}


class EmbeddingVersionContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.set_manifests(PUBLISHED)
        document, readme = contract.render(
            (ROOT / contract.EMBEDDING).read_text(),
            (ROOT / contract.WIRE_README).read_text(),
            PUBLISHED,
            PUBLISHED,
        )
        for path, text in {
            contract.EMBEDDING: document,
            contract.WIRE_README: readme,
            contract.RPKI_README: contract.render_readme(
                (ROOT / contract.RPKI_README).read_text(), ("wire", "rpki"), PUBLISHED, PUBLISHED
            ),
            contract.PUBLISHED_RECORD: json.dumps(PUBLISHED, indent=2) + "\n",
        }.items():
            (self.root / path).parent.mkdir(parents=True, exist_ok=True)
            (self.root / path).write_text(text)

    def set_manifests(self, versions):
        pins = ["[workspace.dependencies]"]
        for package, (name, relative, directory) in contract.MANIFESTS.items():
            version = versions[package]
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f'[package]\nname = "{name}"\nversion = "{version}"\n')
            pins.append(f'{name} = {{ version = "{version}", path = "{directory}" }}')
        (self.root / "Cargo.toml").write_text("\n".join(pins) + "\n")

    def read(self, path):
        return (self.root / path).read_text()

    def errors(self, document=None, readme=None):
        return contract.check(
            self.read(contract.EMBEDDING) if document is None else document,
            contract.manifest_versions(self.root),
            contract.published_versions(self.root),
            self.read(contract.WIRE_README) if readme is None else readme,
            self.read(contract.RPKI_README),
        )

    def mutate(self, name, transform):
        original = self.read(contract.EMBEDDING)
        changed = contract.replace_section(original, *contract.SECTIONS[name], transform)
        self.assertNotEqual(changed, original, "mutation must change its intended section")
        return changed

    def snapshot(self):
        return {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}

    @staticmethod
    def response(request, *, timeout):
        name, version = request.full_url.rsplit("/", 2)[-2:]
        return io.BytesIO(
            json.dumps(
                {
                    "version": {
                        "crate": name,
                        "num": version,
                        "yanked": False,
                    }
                }
            ).encode()
        )

    def test_repository_and_synthetic_examples_pass_offline(self):
        with patch.object(contract, "urlopen", side_effect=AssertionError("unexpected network")):
            self.assertEqual(contract.check((ROOT / contract.EMBEDDING).read_text()), [])
            self.assertEqual(self.errors(), [])

    def test_each_dependency_example_rejects_drift(self):
        for name, packages in contract.EXAMPLES.items():
            for package in packages:
                for replacement in (
                    f'rustbgpd-{package} = "9.9.9"',
                    "",
                    f'rustbgpd-{package} = {{ path = "../local" }}',
                ):
                    with self.subTest(section=name, package=package, replacement=replacement):
                        changed = self.mutate(
                            name,
                            lambda body, p=package, r=replacement: contract.assignment(p).sub(
                                r, body
                            ),
                        )
                        self.assertIn(f"{package}-snippet-version:{name}", self.errors(changed))

    def test_equal_table_columns_are_independently_guarded(self):
        for package in contract.PACKAGES:
            for column, diagnostic in (
                (1, "current-boundary-version"),
                (2, "prepared-boundary-version"),
            ):
                with self.subTest(package=package, column=column):
                    cells = [f"rustbgpd-{package}", PUBLISHED[package], PUBLISHED[package]]
                    before = "| " + " | ".join(f"`{cell}`" for cell in cells) + " |"
                    cells[column] = "9.9.9"
                    after = "| " + " | ".join(f"`{cell}`" for cell in cells) + " |"
                    changed = self.mutate(
                        "boundary", lambda body, b=before, a=after: body.replace(b, a)
                    )
                    self.assertEqual(self.errors(changed), [diagnostic])

    def test_invalid_table_rows_markers_and_headings(self):
        row = f"| `rustbgpd-wire` | `{PUBLISHED['wire']}` | `{PUBLISHED['wire']}` |"
        for replacement in ("", row + "\n" + row, row.replace("rustbgpd-wire", "rustbgpd-unknown")):
            changed = self.mutate("boundary", lambda body, r=replacement: body.replace(row, r))
            self.assertIn("current-boundary-version", self.errors(changed))
        for replacement in ("", contract.START + contract.START):
            changed = self.mutate(
                "boundary", lambda body, r=replacement: body.replace(contract.START, r)
            )
            self.assertIn("published-version-table:markers", self.errors(changed))
        for level, title in contract.SECTIONS.values():
            original = self.read(contract.EMBEDDING)
            for changed in (
                original.replace(title, "Removed section"),
                original + f"\n{'#' * level} {title}\n",
            ):
                self.assertNotEqual(changed, original)
                self.assertTrue(
                    any(e.startswith("semantic-heading:") for e in self.errors(changed))
                )

    def test_harmless_prose_does_not_define_versions(self):
        document = self.read(contract.EMBEDDING).replace("## 7. ", "## 70. ")
        document = contract.replace_section(
            document,
            2,
            "Which crate to publish next, and why",
            lambda _: (
                "\n\nCompatibility history may be reworded without changing publication state.\n\n"
            ),
        )
        self.assertEqual(
            self.errors(document + "\nAn unrelated consumer prepared its first release.\n"), []
        )

    def test_wire_readme_registry_and_path_are_separate(self):
        for pattern, replacement, diagnostic in (
            (
                contract.assignment("wire"),
                'rustbgpd-wire = "9.9.9"',
                "wire-readme-registry-version:wire",
            ),
            (
                contract.path_assignment("wire"),
                'rustbgpd-wire = { version = "9.9.9", path = "../rustbgpd/crates/wire" }',
                "wire-readme-path-version:wire",
            ),
        ):
            original = self.read(contract.WIRE_README)
            changed = contract.replace_section(
                original, 2, "Usage", lambda body, p=pattern, r=replacement: p.sub(r, body)
            )
            self.assertNotEqual(changed, original)
            self.assertIn(diagnostic, self.errors(readme=changed))

    def test_rpki_readme_dependency_drift(self):
        original = self.read(contract.RPKI_README)
        for package in ("wire", "rpki"):
            for kind, pattern in (
                ("registry", contract.assignment(package)),
                ("path", contract.path_assignment(package)),
            ):
                for replacement in ("", f'rustbgpd-{package} = "9.9.9"'):
                    changed = contract.replace_section(
                        original, 2, "Usage", lambda body, p=pattern, r=replacement: p.sub(r, body)
                    )
                    self.assertNotEqual(changed, original)
                    (self.root / contract.RPKI_README).write_text(changed)
                    self.assertIn(f"rpki-readme-{kind}-version:{package}", self.errors())
        (self.root / contract.RPKI_README).write_text(original)

    def test_workspace_pin_mismatch(self):
        original = self.read(Path("Cargo.toml"))
        for package in contract.PACKAGES:
            (self.root / "Cargo.toml").write_text(original.replace(PUBLISHED[package], "9.9.9"))
            with self.assertRaisesRegex(ValueError, f"workspace-pin:{package}"):
                contract.manifest_versions(self.root)

    def test_invalid_metadata(self):
        invalid = [[], {}, {**PUBLISHED, "extra": "1.0.0"}]
        invalid += [
            {**PUBLISHED, "wire": v} for v in (None, 1, "", "01.0.0", "1.0.0-pre", "../wire")
        ]
        for value in invalid:
            with self.subTest(value=value):
                (self.root / contract.PUBLISHED_RECORD).write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, "published-version-record:"):
                    contract.published_versions(self.root)
        (self.root / contract.PUBLISHED_RECORD).write_text('{"wire":"1.0.0","wire":"2.0.0"}')
        with self.assertRaisesRegex(ValueError, "duplicate-json-key:wire"):
            contract.published_versions(self.root)

    def test_preparation_is_offline_and_idempotent(self):
        before = self.read(contract.EMBEDDING)
        self.set_manifests(NEXT)
        with patch.object(contract, "urlopen", side_effect=AssertionError("unexpected network")):
            self.assertEqual(
                set(contract.update(self.root)),
                {contract.EMBEDDING, contract.WIRE_README, contract.RPKI_README},
            )
            self.assertEqual(contract.update(self.root), [])
        self.assertEqual(contract.published_versions(self.root), PUBLISHED)
        self.assertEqual(self.errors(), [])
        for name in contract.EXAMPLES:
            self.assertEqual(
                contract.section(before, *contract.SECTIONS[name]),
                contract.section(self.read(contract.EMBEDDING), *contract.SECTIONS[name]),
            )

    def test_complete_refresh_is_idempotent(self):
        self.set_manifests(NEXT)
        with patch.object(contract, "urlopen", side_effect=self.response) as request:
            self.assertEqual(
                set(contract.update(self.root, refresh=True)),
                {
                    contract.PUBLISHED_RECORD,
                    contract.EMBEDDING,
                    contract.WIRE_README,
                    contract.RPKI_README,
                },
            )
            self.assertEqual(
                [c.args[0].full_url for c in request.call_args_list],
                [
                    f"https://crates.io/api/v1/crates/rustbgpd-{p}/{NEXT[p]}"
                    for p in contract.PACKAGES
                ],
            )
            self.assertTrue(all(c.kwargs["timeout"] == 15 for c in request.call_args_list))
            self.assertEqual(contract.update(self.root, refresh=True), [])
        self.assertEqual(contract.published_versions(self.root), NEXT)
        self.assertEqual(self.errors(), [])

    def test_partial_publication_never_writes(self):
        self.set_manifests(NEXT)
        contract.update(self.root)
        before = self.snapshot()

        def response(request, *, timeout):
            if "rustbgpd-fsm/" in request.full_url:
                raise HTTPError(request.full_url, 404, "not published", {}, None)
            return self.response(request, timeout=timeout)

        with patch.object(contract, "urlopen", side_effect=response):
            with self.assertRaises(HTTPError):
                contract.update(self.root, refresh=True)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.errors(), [])

    def test_registry_failure_never_writes(self):
        self.set_manifests(NEXT)
        before = self.snapshot()
        valid = {"crate": "rustbgpd-wire", "num": NEXT["wire"], "yanked": False}
        payloads = [
            {"version": {**valid, key: value}}
            for key, value in (
                ("crate", "different-crate"),
                ("num", "9.9.9"),
                ("yanked", True),
                ("yanked", None),
            )
        ] + [{}, [], {"version": None}]
        for payload in payloads:
            with (
                self.subTest(payload=payload),
                patch.object(
                    contract, "urlopen", return_value=io.BytesIO(json.dumps(payload).encode())
                ),
            ):
                with self.assertRaises(ValueError):
                    contract.update(self.root, refresh=True)
                self.assertEqual(self.snapshot(), before)
        for failure in (URLError("offline"), TimeoutError("timeout")):
            with patch.object(contract, "urlopen", side_effect=failure):
                with self.assertRaises(OSError):
                    contract.update(self.root, refresh=True)
                self.assertEqual(self.snapshot(), before)
        with patch.object(contract, "urlopen", return_value=io.BytesIO(b"invalid json")):
            with self.assertRaises(ValueError):
                contract.update(self.root, refresh=True)
        self.assertEqual(self.snapshot(), before)

    def test_broken_template_fails_before_network(self):
        (self.root / contract.EMBEDDING).write_text(
            self.read(contract.EMBEDDING).replace(contract.START, "")
        )
        before = self.snapshot()
        with patch.object(contract, "urlopen", side_effect=AssertionError("unexpected network")):
            with self.assertRaisesRegex(ValueError, "published-version-table:markers"):
                contract.update(self.root, refresh=True)
        self.assertEqual(self.snapshot(), before)

    def test_cli_check_and_conflicting_flags(self):
        command = [sys.executable, str(ROOT / "scripts/check_embedding_versions.py")]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for args in (("--write", "--refresh"), ("--write", str(ROOT / contract.EMBEDDING))):
            result = subprocess.run([*command, *args], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)


if __name__ == "__main__":
    unittest.main()
