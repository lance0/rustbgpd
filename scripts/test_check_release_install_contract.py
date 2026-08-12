#!/usr/bin/env python3
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_release_install_contract as contract

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ".github/workflows/release.yml"
WORKFLOW = ".github/workflows/release-install-contract.yml"
CHECK = '"$tree/usr/bin/rustbgpd" --check "$tree/etc/rustbgpd/config.toml"'
RPM_EXTRACT = "cpio --quiet -id --no-absolute-filenames --directory=extracted/rpm"
EXE_LOOP = "for exe in rustbgpd rbgp rs-config-render birdwatcher-adapter; do"
IMAGE_RUN = "run: docker run --rm --entrypoint birdwatcher-adapter"
UNIT_ASSERT = 'grep -qxF "$directive" "$unit"'
STATUS_GUARD = "from scripts.check_release_install_contract import systemd_assignments, systemd_status_is_70"
MONITORING_MAPPING = "native monitoring mappings"
GREP_ASSERT = 'if ! grep -qxF "$f" <<<"$entries"; then'
TAR_SIZE_ASSERT = (
    'if [ "$(tar -xOzf "dist/rustbgpd-${SUFFIX}.tar.gz" "$f" | wc -c)" -eq 0 ]; then'
)
INPUTS = (
    WORKFLOW,
    RELEASE,
    "packaging/nfpm.yaml",
    "docs/grafana/rustbgpd-overview.json",
    "examples/prometheus/rustbgpd-alerts.yml",
    "examples/prometheus/rustbgpd-alerts_test.yml",
    contract.SYSTEMD_UNIT,
    contract.COMPOSE_FILE,
)
MUTATIONS = (
    (
        RELEASE,
        "                   share/monitoring/rustbgpd-alerts_test.yml; do",
        "                   removed-alert-tests.yml; do\n          # share/monitoring/rustbgpd-alerts_test.yml; do",
        "tarball payload assertions",
    ),
    (
        "packaging/nfpm.yaml",
        "contents:\n",
        "contents:\n  - src: extra\n    dst: /usr/bin/extra\n",
        "native binary destinations",
    ),
    (
        WORKFLOW,
        'dpkg-deb -x "$deb" extracted/deb',
        'echo dpkg-deb -x "$deb" extracted/deb',
        "real native package assertions",
    ),
    (
        WORKFLOW,
        RPM_EXTRACT,
        "cpio --quiet -i --to-stdout",
        "real native package assertions",
    ),
    (
        WORKFLOW,
        EXE_LOOP,
        "for exe in rustbgpd rbgp rs-config-render; do",
        "real native package assertions",
    ),
    (
        WORKFLOW,
        CHECK,
        CHECK.replace('"$tree/etc', '"/etc'),
        "real native package assertions",
    ),
    (WORKFLOW, CHECK, "true\n            # " + CHECK, "real native package assertions"),
    (
        WORKFLOW,
        IMAGE_RUN,
        IMAGE_RUN.replace("birdwatcher-adapter", "rustbgpd"),
        "production image adapter assertion",
    ),
    (
        RELEASE,
        GREP_ASSERT,
        'if ! echo \'grep -qxF "$f" <<<"$entries"\'; then',
        "tarball active assertions",
    ),
    (
        RELEASE,
        TAR_SIZE_ASSERT,
        TAR_SIZE_ASSERT.replace("tar -xOzf", "echo 'tar -xOzf") + "'",
        "tarball active assertions",
    ),
    (
        contract.SYSTEMD_UNIT,
        "StartLimitIntervalSec=10min",
        "StartLimitIntervalSec=9min",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "TimeoutStopSec=32min",
        "TimeoutStopSec=31min",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "[Service]",
        "[Service]\nSuccessExitStatus=SOFTWARE",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "[Service]",
        "[Service]\nSuccessExitStatus=0x46",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "[Service]",
        "[Service]\nRestartPreventExitStatus=+70",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "[Service]",
        "[Service]\nRestartPreventExitStatus=0106",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "[Service]",
        "[Service]\nSuccessExitStatus=0b1000110",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "[Service]",
        "[Service]\nRestartPreventExitStatus=+0B1000110",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "[Service]",
        "[Service]\nSuccessExitStatus=\\\n 70",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "[Service]",
        "[Service]\nRestartPreventExitStatus=\\\n 0x46",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "[Service]",
        "[Service]\n# ignored comment \\\nSuccessExitStatus=70",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "[Service]",
        "[Service]\nRestartPreventExitStatus=\\\n# ignored comment\n; ignored too\n 0x46",
        "systemd unit",
    ),
    (
        contract.COMPOSE_FILE,
        "stop_grace_period: 32m",
        "stop_grace_period: 31m",
        "docker compose",
    ),
    (
        contract.COMPOSE_FILE,
        "stop_grace_period: 32m",
        "restart: on-failure\n    stop_grace_period: 32m",
        "docker compose",
    ),
    (WORKFLOW, UNIT_ASSERT, "true # " + UNIT_ASSERT, "real native package assertions"),
    (
        WORKFLOW,
        STATUS_GUARD,
        "if false; then # " + STATUS_GUARD,
        "real native package assertions",
    ),
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

    def test_repository_contract(self) -> None:
        self.assertEqual(contract.check(ROOT), [])

    def test_destructive_mutations_fail(self) -> None:
        for relative, old, new, label in MUTATIONS:
            with self.subTest(old=old):
                root = self.fixture()
                path = root / relative
                text = path.read_text()
                self.assertIn(old, text)
                path.write_text(text.replace(old, new, 1))
                errors = contract.check(root)
                self.assertTrue(any(label in error for error in errors), errors)

    def test_every_tarball_payload_is_asserted(self) -> None:
        marker = "          for f in "
        for payload in (
            contract.BINARIES
            + contract.SYSTEMD
            + tuple(item[1] for item in contract.MONITORING)
        ):
            with self.subTest(payload=payload):
                root = self.fixture()
                path = root / RELEASE
                before, after = path.read_text().split(marker, 1)
                self.assertIn(payload, after)
                path.write_text(
                    before + marker + after.replace(payload, "removed-payload", 1)
                )
                self.assertTrue(
                    any(
                        "tarball payload assertions" in error
                        for error in contract.check(root)
                    )
                )

    def test_every_monitoring_source_is_packaged_and_mapped(self) -> None:
        for source, _, native in contract.MONITORING:
            for path, token, label in (
                (RELEASE, source, "tarball package commands"),
                ("packaging/nfpm.yaml", native, MONITORING_MAPPING),
            ):
                with self.subTest(path=path, token=token):
                    root = self.fixture()
                    target = root / path
                    target.write_text(
                        target.read_text().replace(token, "removed-monitoring", 1)
                    )
                    errors = contract.check(root)
                    self.assertTrue(any(label in error for error in errors))
                    if path == "packaging/nfpm.yaml":
                        self.assertTrue(
                            any(repr((source, native)) in error for error in errors),
                            errors,
                        )

    def test_every_native_binary_destination_is_exact(self) -> None:
        for binary in contract.BINARIES:
            with self.subTest(binary=binary):
                root = self.fixture()
                path = root / "packaging/nfpm.yaml"
                text = path.read_text().replace(
                    f"dst: /usr/bin/{binary}", "dst: /usr/bin/removed", 1
                )
                path.write_text(text)
                self.assertTrue(
                    any(
                        "native binary destinations" in error
                        for error in contract.check(root)
                    )
                )

    def test_systemd_directive_section_is_exact(self) -> None:
        root = self.fixture()
        path = root / contract.SYSTEMD_UNIT
        text = path.read_text()
        text = text.replace("StartLimitBurst=5\n", "", 1).replace(
            "[Service]\n", "[Service]\nStartLimitBurst=5\n", 1
        )
        path.write_text(text)
        self.assertTrue(any("systemd unit" in error for error in contract.check(root)))

    def test_systemd_exit_70_spellings_are_closed(self) -> None:
        for token in (
            "70",
            "+70",
            "0x46",
            "+0X46",
            "0b1000110",
            "+0B1000110",
            "0106",
            "+0106",
            "SOFTWARE",
            "+SOFTWARE",
        ):
            with self.subTest(token=token):
                self.assertTrue(contract.systemd_status_is_70(token))
        for token in ("69", "0x47", "0105", "EX_SOFTWARE", "SIGTERM"):
            with self.subTest(token=token):
                self.assertFalse(contract.systemd_status_is_70(token))

    def test_systemd_continuations_are_unfolded(self) -> None:
        text = (
            "[Service]\n"
            "# standalone ignored \\\n"
            "SuccessExitStatus=\\\n"
            "# continued comment ignored\n"
            "; another ignored comment \\\n"
            " +0x46\\\n"
            " 69\n"
        )
        self.assertEqual(
            contract.systemd_assignments(text),
            (("Service", "SuccessExitStatus", "+0x46 69"),),
        )

    def test_empty_monitoring_source_fails(self) -> None:
        root = self.fixture()
        (root / "docs/grafana/rustbgpd-overview.json").write_text("")
        self.assertTrue(
            any("missing or empty" in error for error in contract.check(root))
        )

    def test_presentation_edits_do_not_gate_artifacts(self) -> None:
        root = self.fixture()
        path = root / WORKFLOW
        text = path.read_text()
        for old in (
            "- README.md",
            "- scripts/check_release_install_contract.py",
            "cargo test -p birdwatcher-adapter",
        ):
            text = text.replace(old, "removed-presentation")
        path.write_text(text)
        self.assertEqual(contract.check(root), [])

    def test_step_names_are_presentation(self) -> None:
        names = (
            (RELEASE, "Package binaries"),
            (RELEASE, "Assert tarball release payload is complete"),
            (WORKFLOW, "Assert real native package payloads"),
            (WORKFLOW, "Assert production image runs the adapter"),
        )
        for relative, name in names:
            with self.subTest(name=name):
                root = self.fixture()
                path = root / relative
                path.write_text(path.read_text().replace(name, "Renamed step", 1))
                self.assertEqual(contract.check(root), [])

    def test_duplicate_semantic_run_body_fails(self) -> None:
        root = self.fixture()
        path = root / WORKFLOW
        duplicate = f"\n      - name: Duplicate adapter assertion\n        {IMAGE_RUN} rustbgpd:release-install-contract --help\n"
        path.write_text(path.read_text() + duplicate)
        errors = contract.check(root)
        self.assertTrue(any("found 2" in error for error in errors), errors)

    def test_commands_from_separate_run_bodies_are_not_concatenated(self) -> None:
        root = self.fixture()
        path = root / RELEASE
        text = path.read_text().replace(TAR_SIZE_ASSERT, "if false; then", 1)
        decoy = "cat checksums-${{ matrix.suffix }}.txt"
        self.assertIn(decoy, text)
        text = text.replace(decoy, TAR_SIZE_ASSERT, 1)
        path.write_text(text)
        errors = contract.check(root)
        self.assertTrue(
            any("tarball active assertions" in error for error in errors), errors
        )


if __name__ == "__main__":
    unittest.main()
