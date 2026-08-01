#!/usr/bin/env python3
"""Mutation proofs for the embedding crate-map documentation contract."""

import copy
import unittest
from pathlib import Path

from scripts import check_embedding_crate_map as checker


ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = (ROOT / "docs" / "EMBEDDING.md").read_text(encoding="utf-8")


class EmbeddingCrateMapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.metadata = checker.cargo_metadata()

    def assert_red(self, document: str, diagnostic: str, metadata=None) -> None:
        errors = checker.check(document, metadata or self.metadata)
        self.assertTrue(any(error.startswith(diagnostic) for error in errors), errors)

    @staticmethod
    def row(package: str) -> str:
        return next(
            line
            for line in DOCUMENT.splitlines()
            if line.startswith(f"| `{package}` |")
        )

    def test_added_rib_edge_is_guarded(self) -> None:
        """Red if the RIB row invents an internal FSM dependency edge."""
        old = "`rustbgpd-bmp`, `rustbgpd-policy`"
        changed = "`rustbgpd-bmp`, `rustbgpd-fsm`, `rustbgpd-policy`"
        self.assert_red(DOCUMENT.replace(old, changed, 1), "EMBEDDING_CRATE_MAP_DEPS")

    def test_removed_rib_edge_is_guarded(self) -> None:
        """Red if the RIB row drops its real internal BMP dependency edge."""
        self.assert_red(
            DOCUMENT.replace(
                "`rustbgpd-bmp`, `rustbgpd-policy`", "`rustbgpd-policy`", 1
            ),
            "EMBEDDING_CRATE_MAP_DEPS",
        )

    def test_deleted_bfd_row_is_guarded(self) -> None:
        """Red if the BFD workspace package row is deleted from the map."""
        self.assert_red(
            DOCUMENT.replace(self.row("rustbgpd-bfd") + "\n", "", 1),
            "EMBEDDING_CRATE_MAP_MISSING",
        )

    def test_new_workspace_package_is_guarded(self) -> None:
        """Red if metadata gains a workspace package without a documentation row."""
        metadata = copy.deepcopy(self.metadata)
        package = {
            "id": "path+file:///synthetic#rustbgpd-new@0.1.0",
            "name": "rustbgpd-new",
            "publish": [],
            "dependencies": [],
        }
        metadata["packages"].append(package)
        metadata["workspace_members"].append(package["id"])
        self.assert_red(DOCUMENT, "EMBEDDING_CRATE_MAP_MISSING", metadata)

    def test_extra_document_row_is_guarded(self) -> None:
        """Red if the map claims a package outside the Cargo workspace."""
        row = "| `rustbgpd-ghost` | Disabled | None | Not a package. |\n"
        changed = DOCUMENT.replace(checker.END, row + checker.END, 1)
        self.assert_red(changed, "EMBEDDING_CRATE_MAP_EXTRA")

    def test_scope_sentence_is_guarded(self) -> None:
        """Red if scope or either marker's exact cardinality drifts."""
        start, end = DOCUMENT.index(checker.BEGIN), DOCUMENT.index(checker.END)
        fenced = DOCUMENT[start : end + len(checker.END)]
        suffixes = (checker.BEGIN, checker.END, fenced)
        changes = [DOCUMENT.replace(checker.SCOPE, "Drifted.", 1)]
        changes.extend(DOCUMENT + suffix for suffix in suffixes)
        for changed in changes:
            self.assert_red(changed, "EMBEDDING_CRATE_MAP_SCOPE")

    def test_dependency_kind_scope_is_load_bearing(self) -> None:
        """Red if build/target edges are dropped or dev edges are included."""
        for kind, target in (("build", None), (None, 'cfg(target_os = "linux")')):
            metadata = copy.deepcopy(self.metadata)
            rib = next(p for p in metadata["packages"] if p["name"] == "rustbgpd-rib")
            edge = next(d for d in rib["dependencies"] if d["name"] == "rustbgpd-bmp")
            edge["kind"], edge["target"] = kind, target
            self.assertEqual(checker.check(DOCUMENT, metadata), [])
        metadata = copy.deepcopy(self.metadata)
        bfd = next(p for p in metadata["packages"] if p["name"] == "rustbgpd-bfd")
        edge = {
            "name": "rustbgpd-wire",
            "kind": "dev",
            "path": "/synthetic/wire",
        }
        bfd["dependencies"].append(edge)
        self.assertEqual(checker.check(DOCUMENT, metadata), [])

    def test_fsm_publish_flag_is_guarded(self) -> None:
        """Red if the published FSM package is marked Cargo-publish Disabled."""
        changed = DOCUMENT.replace(
            self.row("rustbgpd-fsm"),
            self.row("rustbgpd-fsm").replace("Enabled", "Disabled"),
            1,
        )
        self.assert_red(changed, "EMBEDDING_CRATE_MAP_PUBLISH")

    def test_duplicate_row_is_guarded(self) -> None:
        """Red if any workspace package appears twice in the map."""
        row = self.row("rustbgpd-bfd")
        changed = DOCUMENT.replace(row, row + "\n" + row, 1)
        self.assert_red(changed, "EMBEDDING_CRATE_MAP_DUPLICATE")


if __name__ == "__main__":
    unittest.main()
