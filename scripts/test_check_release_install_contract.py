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
    ".github/workflows/release-install-contract.yml",
    ".github/workflows/release.yml",
    "packaging/nfpm.yaml",
    "docs/deployment.md",
    "docs/QUICKSTART.md",
    "docs/grafana/rustbgpd-overview.json",
    "examples/birdwatcher-adapter/README.md",
    "examples/prometheus/rustbgpd-alerts.yml",
    "examples/prometheus/rustbgpd-alerts_test.yml",
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
        marker = "      - name: Assert tarball release payload is complete"
        before, after = text.split(marker, 1)
        after = after.replace("share/systemd/rustbgpd.service", "share/systemd/removed.service", 1)
        path.write_text(before + marker + after)
        errors = contract.check(root)
        self.assertTrue(any("release assertion step" in error for error in errors), errors)

    def test_removed_tarball_monitoring_copy_fails(self) -> None:
        errors = self.mutate(
            self.fixture(),
            ".github/workflows/release.yml",
            "cp docs/grafana/rustbgpd-overview.json staging/share/monitoring/",
            "cp generated/rustbgpd-overview.json staging/share/monitoring/",
        )
        self.assertTrue(any("release package step" in error for error in errors), errors)

    def test_removed_tarball_monitoring_assertion_fails(self) -> None:
        root = self.fixture()
        path = root / ".github/workflows/release.yml"
        text = path.read_text()
        marker = "      - name: Assert tarball release payload is complete"
        before, after = text.split(marker, 1)
        after = after.replace(
            "share/monitoring/rustbgpd-alerts_test.yml",
            "share/monitoring/removed-alert-tests.yml",
            1,
        )
        path.write_text(before + marker + after)
        errors = contract.check(root)
        self.assertTrue(any("release assertion step" in error for error in errors), errors)

    def test_removed_native_monitoring_mapping_fails(self) -> None:
        errors = self.mutate(
            self.fixture(),
            "packaging/nfpm.yaml",
            "dst: /usr/share/doc/rustbgpd/monitoring/rustbgpd-overview.json",
            "dst: /usr/share/doc/rustbgpd/monitoring/removed-overview.json",
        )
        self.assertTrue(any("native monitoring payloads" in error for error in errors), errors)

    def test_non_relative_promtool_rule_file_fails(self) -> None:
        errors = self.mutate(
            self.fixture(),
            "examples/prometheus/rustbgpd-alerts_test.yml",
            "  - rustbgpd-alerts.yml",
            "  - /etc/prometheus/rustbgpd-alerts.yml",
        )
        self.assertTrue(any("rule_files must resolve" in error for error in errors), errors)

    def test_empty_canonical_monitoring_source_fails(self) -> None:
        root = self.fixture()
        (root / "docs/grafana/rustbgpd-overview.json").write_text("")
        errors = contract.check(root)
        self.assertTrue(any("source missing or empty" in error for error in errors), errors)

    def test_removed_monitoring_workflow_trigger_fails(self) -> None:
        errors = self.mutate(
            self.fixture(),
            ".github/workflows/release-install-contract.yml",
            "- docs/grafana/rustbgpd-overview.json",
            "- docs/grafana/removed-overview.json",
        )
        self.assertTrue(any("expected pull/push enrollment" in error for error in errors), errors)

    def test_undocumented_native_monitoring_path_fails(self) -> None:
        errors = self.mutate(
            self.fixture(),
            "docs/QUICKSTART.md",
            "/usr/share/doc/rustbgpd/monitoring/",
            "/usr/share/doc/rustbgpd/missing-monitoring/",
        )
        self.assertTrue(any("monitoring discovery" in error for error in errors), errors)

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
