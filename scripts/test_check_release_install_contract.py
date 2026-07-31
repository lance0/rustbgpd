#!/usr/bin/env python3
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_release_install_contract as contract
ROOT = Path(__file__).resolve().parents[1]
INPUTS = (
    ".github/workflows/release.yml",
    "packaging/nfpm.yaml",
    "docs/deployment.md",
    "docs/QUICKSTART.md",
    "examples/birdwatcher-adapter/README.md",
)

class ReleaseInstallContractTest(unittest.TestCase):
    def fixture(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for relative in INPUTS:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        return root

    def mutate(self, root: Path, relative: str, old: str, new: str) -> list[str]:
        path = root / relative
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new))
        return contract.check(root)

    def test_repository_contract(self) -> None:
        self.assertEqual(contract.check(ROOT), [])

    def test_wrong_examples_unit_path_fails(self) -> None:
        errors = self.mutate(
            self.fixture(),
            "docs/deployment.md",
            "share/systemd/rustbgpd.service",
            "examples/systemd/rustbgpd.service",
        )
        self.assertTrue(any("tarball region" in error for error in errors), errors)

    def test_removed_release_assertion_unit_fails(self) -> None:
        root = self.fixture()
        path = root / ".github/workflows/release.yml"
        text = path.read_text()
        marker = "      - name: Assert tarball has nonempty binaries, licenses, man pages, and completions"
        before, after = text.split(marker, 1)
        after = after.replace("share/systemd/rustbgpd.service", "share/systemd/removed.service", 1)
        path.write_text(before + marker + after)
        errors = contract.check(root)
        self.assertTrue(any("release assertion step" in error for error in errors), errors)

    def test_reverted_birdwatcher_boundary_fails(self) -> None:
        errors = self.mutate(
            self.fixture(),
            "examples/birdwatcher-adapter/README.md",
            "included in release tarballs",
            "not part of release tarballs",
        )
        self.assertTrue(any("birdwatcher" in error for error in errors), errors)

    def test_adapter_in_native_inventory_fails(self) -> None:
        root = self.fixture()
        path = root / "packaging/nfpm.yaml"
        path.write_text(
            path.read_text()
            + "\n  - src: synthetic/birdwatcher-adapter\n"
            + "    dst: /usr/bin/birdwatcher-adapter\n"
        )
        errors = contract.check(root)
        self.assertTrue(any("/usr/bin payload" in error for error in errors), errors)

    def test_fourth_documented_native_binary_fails(self) -> None:
        errors = self.mutate(
            self.fixture(), "docs/deployment.md", "`rs-config-render`) to", "`rs-config-render`, `extra`) to"
        )
        self.assertTrue(any("documented native binaries" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
