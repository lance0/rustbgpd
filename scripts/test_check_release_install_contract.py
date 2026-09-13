#!/usr/bin/env python3
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
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
SYSTEMD_VERIFY = "systemd-analyze verify examples/systemd/rustbgpd-container.service"
UNIT_ASSERT = 'grep -qxF "$directive" "$unit"'
TEMPLATE_EXEC_ASSERT = "grep -qxF 'ExecStart=/usr/bin/rustbgpd /var/lib/rustbgpd/%i/activation/current/config.toml' \"$template\""
STATUS_GUARD = "from scripts.check_release_install_contract import check_systemd_template, systemd_assignments, systemd_status_is_70"
MONITORING_MAPPING = "native monitoring mappings"
GREP_ASSERT = 'if ! grep -qxF "$f" <<<"$entries"; then'
TAR_SIZE_ASSERT = (
    'if [ "$(tar -xOzf "dist/rustbgpd-${SUFFIX}.tar.gz" "$f" | wc -c)" -eq 0 ]; then'
)
INPUTS = (
    WORKFLOW,
    RELEASE,
    contract.INSTALLER,
    "packaging/nfpm.yaml",
    "scripts/build-packages.sh",
    "docs/grafana/rustbgpd-overview.json",
    "docs/grafana/rustbgpd-evpn.json",
    "examples/prometheus/rustbgpd-alerts.yml",
    "examples/prometheus/rustbgpd-alerts_test.yml",
    "Dockerfile",
    "docs/how-to/deployment.md",
    contract.SYSTEMD_UNIT,
    contract.SYSTEMD_TEMPLATE,
    contract.SYSTEMD_CONTAINER_UNIT,
    contract.COMPOSE_FILE,
    contract.LICENSE_MAP,
)
MUTATIONS = (
    (
        "scripts/build-packages.sh",
        "for unit in rustbgpd.service 'rustbgpd@.service'; do",
        "for unit in rustbgpd.service; do",
        "native systemd staging",
    ),
    (
        "scripts/build-packages.sh",
        "sed 's|^ExecStart=/usr/local/bin/rustbgpd |ExecStart=/usr/bin/rustbgpd |' \\",
        "sed 's|/usr/local/bin|/usr/bin|g' \\",
        "native systemd staging",
    ),
    (
        contract.SYSTEMD_TEMPLATE,
        "/var/lib/rustbgpd/%i/activation/current/config.toml",
        "/etc/rustbgpd/%i/config.toml",
        "systemd template",
    ),
    (
        contract.SYSTEMD_TEMPLATE,
        "StateDirectory=rustbgpd/%i rustbgpd/%i/activation",
        "StateDirectory=rustbgpd/%i",
        "systemd template",
    ),
    (
        contract.SYSTEMD_TEMPLATE,
        "ReadWritePaths=/var/lib/rustbgpd/%i",
        "ReadWritePaths=/var/lib/rustbgpd/%i /var/lib/rustbgpd/ixp-manager-host",
        "systemd template",
    ),
    (
        contract.SYSTEMD_TEMPLATE,
        "%i",
        "%I",
        "systemd template",
    ),
    (
        "packaging/nfpm.yaml",
        "  - src: ${PKGROOT}/lib/systemd/system/rustbgpd@.service\n    dst: /lib/systemd/system/rustbgpd@.service",
        "  - src: omitted-template\n    dst: /lib/systemd/system/omitted-template",
        "native systemd template mapping",
    ),
    (
        RELEASE,
        " examples/systemd/rustbgpd@.service",
        " examples/systemd/omitted-template.service",
        "tarball package commands",
    ),
    (
        RELEASE,
        "                   share/systemd/rustbgpd@.service \\\n",
        "",
        "tarball payload assertions",
    ),
    (
        WORKFLOW,
        "                        lib/systemd/system/rustbgpd@.service \\\n",
        "",
        "real native package assertions",
    ),
    (
        WORKFLOW,
        TEMPLATE_EXEC_ASSERT,
        "true # " + TEMPLATE_EXEC_ASSERT,
        "real native package assertions",
    ),
    (
        contract.LICENSE_MAP,
        '5.4. "Results" means any outcome obtained by computational analysis',
        '5.4. "Results" means an omitted agreement clause',
        "license map",
    ),
    (
        "packaging/nfpm.yaml",
        "  - src: LICENSES.md\n    dst: /usr/share/doc/rustbgpd/LICENSES.md",
        "  - src: omitted-license-map\n    dst: /usr/share/doc/rustbgpd/omitted",
        "native license mapping",
    ),
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
        RELEASE,
        "cp packaging/install.sh artifacts/install.sh",
        "true",
        "installer release asset",
    ),
    (
        WORKFLOW,
        "      - packaging/install.sh",
        "      - packaging/removed-install.sh",
        "release install workflow must trigger for packaging/install.sh",
    ),
    (
        contract.SYSTEMD_UNIT,
        "StartLimitIntervalSec=10min",
        "StartLimitIntervalSec=9min",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "Type=notify",
        "Type=simple",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "NotifyAccess=main",
        "NotifyAccess=all",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "WatchdogSec=5min",
        "WatchdogSec=4min",
        "systemd unit",
    ),
    (
        contract.SYSTEMD_UNIT,
        "TimeoutStartSec=10min",
        "TimeoutStartSec=9min",
        "systemd unit",
    ),
    (WORKFLOW, "Type=notify", "Type=simple", "real native package assertions"),
    (
        WORKFLOW,
        "NotifyAccess=main",
        "NotifyAccess=all",
        "real native package assertions",
    ),
    (
        WORKFLOW,
        "WatchdogSec=5min",
        "WatchdogSec=4min",
        "real native package assertions",
    ),
    (
        WORKFLOW,
        "TimeoutStartSec=10min",
        "TimeoutStartSec=9min",
        "real native package assertions",
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
        contract.SYSTEMD_CONTAINER_UNIT,
        "After=docker.service network-online.target",
        "After=network-online.target",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "Requires=docker.service",
        "Requires=network-online.target",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "Wants=network-online.target",
        "Wants=docker.service",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "WantedBy=multi-user.target",
        "WantedBy=default.target",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "--network=host",
        "--network=bridge",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "--user=root",
        "--user=rustbgpd",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "target=/etc/rustbgpd,readonly",
        "target=/etc/rustbgpd",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "target=/var/lib/rustbgpd",
        "target=/tmp/rustbgpd",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "ExecStartPre=/usr/bin/test x${RUSTBGPD_IMAGE} != x\n",
        "",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "ExecStartPre=/usr/bin/test x${RUSTBGPD_IMAGE} != x",
        "ExecStartPre=/usr/bin/test -n ${RUSTBGPD_IMAGE}",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "EnvironmentFile=/etc/rustbgpd/rustbgpd-container.env",
        "EnvironmentFile=-/etc/rustbgpd/rustbgpd-container.env",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "  --cap-drop=ALL \\\n",
        "  --cap-drop=NET_RAW \\\n",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "  --cap-add=NET_BIND_SERVICE \\\n",
        "",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "  ${RUSTBGPD_IMAGE} \\\n",
        "  ${RUSTBGPD_IMAGE_TAG} \\\n",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "ExecStartPre=-/usr/bin/docker pull",
        "ExecStartPre=/usr/bin/docker pull",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "ExecReload=/usr/bin/docker kill --signal=HUP rustbgpd",
        "ExecReload=/usr/bin/docker restart rustbgpd",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "ExecStop=-/usr/bin/docker stop -t 1920 rustbgpd",
        "ExecStop=-/usr/bin/docker stop --timeout=1920 rustbgpd",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "TimeoutStopSec=33min",
        "TimeoutStopSec=32min",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "[Service]",
        "[Service]\nSuccessExitStatus=70",
        "systemd container unit",
    ),
    (
        contract.SYSTEMD_CONTAINER_UNIT,
        "[Service]",
        "[Service]\nRestartPreventExitStatus=SOFTWARE",
        "systemd container unit",
    ),
    (
        WORKFLOW,
        SYSTEMD_VERIFY,
        "true # " + SYSTEMD_VERIFY,
        "container systemd syntax verification",
    ),
    (
        "docs/how-to/deployment.md",
        "`--cap-add=NET_BIND_SERVICE` is **not sufficient**",
        "`--cap-add=NET_BIND_SERVICE` is sufficient",
        "container deployment docs",
    ),
    (
        "docs/how-to/deployment.md",
        "    --network=bridge \\\n",
        "    --network=bridge \\\n    --cap-add=NET_BIND_SERVICE \\\n",
        "container deployment docs",
    ),
    (
        "docs/how-to/deployment.md",
        "docker run --rm \\\n  --user=root \\\n  --cap-drop=ALL \\\n",
        "sudo systemctl enable --now rustbgpd-container\ndocker run --rm \\\n  --user=root \\\n  --cap-drop=ALL \\\n",
        "container deployment docs",
    ),
    (
        "Dockerfile",
        "USER 999:999",
        "USER root",
        "container image contract",
    ),
    (
        "Dockerfile",
        "USER 999:999",
        "USER rustbgpd",
        "container image contract",
    ),
    (
        "Dockerfile",
        "--uid 999 --gid 999",
        "--user-group",
        "container image contract",
    ),
    (
        "Dockerfile",
        "CMD rbgp health --liveness",
        "CMD rbgp --json health | grep -q '\"healthy\": true' || exit 1",
        "container image contract",
    ),
    (
        "Dockerfile",
        "CMD rbgp health --liveness",
        "CMD rbgp health",
        "container image contract",
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

    def test_required_container_image_guard_is_empty_safe(self) -> None:
        unit = (ROOT / contract.SYSTEMD_CONTAINER_UNIT).read_text()
        guards = [
            value
            for section, key, value in contract.systemd_assignments(unit)
            if section == "Service"
            and key == "ExecStartPre"
            and value.startswith("/usr/bin/test ")
        ]
        self.assertEqual(guards, ["/usr/bin/test x${RUSTBGPD_IMAGE} != x"])
        for image in (None, ""):
            with self.subTest(image=image):
                expanded = guards[0].replace("${RUSTBGPD_IMAGE}", image or "")
                self.assertNotEqual(
                    subprocess.run(shlex.split(expanded), check=False).returncode,
                    0,
                )
        expanded = guards[0].replace(
            "${RUSTBGPD_IMAGE}", "ghcr.io/lance0/rustbgpd:0.67.0"
        )
        self.assertEqual(
            subprocess.run(shlex.split(expanded), check=False).returncode,
            0,
        )

    def test_host_network_container_rejects_every_publish_flag(self) -> None:
        unit = (ROOT / contract.SYSTEMD_CONTAINER_UNIT).read_text()
        message = (
            "systemd container unit: host networking must not carry bridge "
            "publish flags"
        )
        for flag in (
            "-p 179:179",
            "-p179:179",
            "-p=179:179",
            "-P ",
            "-P=true ",
            "-P=false ",
            "--publish 179:179",
            "--publish=179:179",
            "--publish-all ",
            "--publish-all=true ",
        ):
            with self.subTest(flag=flag):
                errors: list[str] = []
                mutated = unit.replace("--network=host", f"--network=host {flag}", 1)
                contract.check_systemd_container(errors, mutated)
                self.assertIn(message, errors)

    def test_container_publish_guard_ignores_non_docker_option_tokens(self) -> None:
        unit = (ROOT / contract.SYSTEMD_CONTAINER_UNIT).read_text()
        message = (
            "systemd container unit: host networking must not carry bridge "
            "publish flags"
        )
        mutations = (
            unit.replace(
                "ExecStartPre=/usr/bin/test x${RUSTBGPD_IMAGE} != x",
                "ExecStartPre=/usr/bin/test -p /run/docker.sock",
                1,
            ),
            unit.replace(
                "rustbgpd ${RUSTBGPD_CONFIG_FILE}",
                "rustbgpd ${RUSTBGPD_CONFIG_FILE} -profile",
                1,
            ),
        )
        for mutated in mutations:
            with self.subTest(mutated=mutated):
                errors: list[str] = []
                contract.check_systemd_container(errors, mutated)
                self.assertNotIn(message, errors)

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
        for source, _, _ in contract.MONITORING:
            with self.subTest(source=source):
                root = self.fixture()
                (root / source).write_text("")
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


class VerifiedInstallerTest(unittest.TestCase):
    """Exercise the released shell resolver against deterministic local assets."""

    tag = "v0.69.0"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.fakebin = self.root / "bin"
        self.assets.mkdir()
        self.fakebin.mkdir()
        self.curl_log = self.root / "curl.log"
        self.package_log = self.root / "package.log"
        self.os_release = self.root / "os-release"
        self.curl_log.touch()
        self.package_log.touch()
        self.set_os_release("debian", "12")
        self.create_assets()
        self.create_shims()

    def set_os_release(self, distribution: str, version: str) -> None:
        self.os_release.write_text(f"ID={distribution}\nVERSION_ID={version}\n")

    def write_program(self, name: str, body: str) -> None:
        path = self.fakebin / name
        path.write_text(textwrap.dedent(body))
        path.chmod(0o755)

    def sha256(self, path: Path) -> str:
        return subprocess.check_output(
            ["sha256sum", path.name], cwd=self.assets, text=True
        ).split()[0]

    def create_assets(self) -> None:
        payload = self.root / "payload"
        (payload / "share").mkdir(parents=True)
        (payload / "rbgp").write_text("#!/bin/sh\necho rbgp\n")
        (payload / "rbgp").chmod(0o755)
        (payload / "share" / "release-note").write_text("verified payload\n")

        for suffix, deb_arch, rpm_arch in (
            ("linux-amd64", "amd64", "x86_64"),
            ("linux-arm64", "arm64", "aarch64"),
        ):
            tarball = f"rustbgpd-{suffix}.tar.gz"
            subprocess.run(
                ["tar", "-C", str(payload), "-czf", str(self.assets / tarball), "rbgp", "share"],
                check=True,
            )
            deb = f"rustbgpd_0.69.0_{deb_arch}.deb"
            rpm = f"rustbgpd-0.69.0-1.{rpm_arch}.rpm"
            (self.assets / deb).write_text(f"{deb}\n")
            (self.assets / rpm).write_text(f"{rpm}\n")
            manifest = "\n".join(
                (
                    f"{self.sha256(self.assets / tarball)}  {tarball}",
                    f"{self.sha256(self.assets / deb)}  ./{deb}",
                    f"{self.sha256(self.assets / rpm)}  ./{rpm}",
                )
            )
            (self.assets / f"checksums-{suffix}.txt").write_text(manifest + "\n")

    def create_shims(self) -> None:
        real_sed = shutil.which("sed")
        self.assertIsNotNone(real_sed)
        self.write_program(
            "sed",
            f"""\
            #!/bin/sh
            if [ "$#" -eq 3 ] && [ "$3" = /etc/os-release ]; then
                exec "{real_sed}" "$1" "$2" "$FAKE_OS_RELEASE"
            fi
            exec "{real_sed}" "$@"
            """,
        )
        self.write_program(
            "curl",
            """\
            #!/bin/sh
            set -eu
            out=''
            effective=false
            url=''
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    -o) out=$2; shift 2 ;;
                    -w) effective=true; shift 2 ;;
                    *) url=$1; shift ;;
                esac
            done
            printf '%s\\n' "$url" >> "$FAKE_CURL_LOG"
            if [ "$url" = 'https://github.com/lance0/rustbgpd/releases/latest' ]; then
                [ "$effective" = true ] || exit 1
                printf '%s\\n' "${FAKE_LATEST_URL:-https://github.com/lance0/rustbgpd/releases/tag/v0.69.0}"
                exit 0
            fi
            asset=${url##*/}
            test -n "$out"
            cp "$FAKE_RELEASE_DIR/$asset" "$out"
            """,
        )
        self.write_program(
            "uname",
            """\
            #!/bin/sh
            case "$1" in
                -s) printf '%s\\n' "${FAKE_UNAME_S:-Linux}" ;;
                -m) printf '%s\\n' "${FAKE_UNAME_M:-x86_64}" ;;
                *) exit 2 ;;
            esac
            """,
        )
        self.write_program(
            "getconf",
            """\
            #!/bin/sh
            test "$1" = GNU_LIBC_VERSION
            printf '%s\\n' "${FAKE_GLIBC:-glibc 2.31}"
            """,
        )
        self.write_program(
            "sudo",
            """\
            #!/bin/sh
            exec "$@"
            """,
        )
        for manager in ("apt-get", "dnf"):
            self.write_program(
                manager,
                """\
                #!/bin/sh
                printf '%s %s\\n' "$(basename "$0")" "$*" >> "$FAKE_PACKAGE_LOG"
                """,
            )

    def run_installer(self, *args: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.fakebin}:{env['PATH']}",
                "FAKE_RELEASE_DIR": str(self.assets),
                "FAKE_CURL_LOG": str(self.curl_log),
                "FAKE_PACKAGE_LOG": str(self.package_log),
                "FAKE_OS_RELEASE": str(self.os_release),
            }
        )
        env.update(overrides)
        return subprocess.run(
            ["sh", str(ROOT / contract.INSTALLER), *args],
            check=False,
            text=True,
            capture_output=True,
            env=env,
            cwd=self.root,
        )

    def test_latest_installs_the_verified_debian_amd64_deb(self) -> None:
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "apt-get install -y -o Dpkg::Options::=--force-confold ",
            self.package_log.read_text(),
        )
        self.assertIn("rustbgpd_0.69.0_amd64.deb", self.package_log.read_text())
        self.assertIn("releases/latest", self.curl_log.read_text())
        self.assertIn("releases/download/v0.69.0/", self.curl_log.read_text())

    def test_rhel_family_installs_the_verified_rpm(self) -> None:
        for distribution in ("rhel", "rocky", "almalinux"):
            with self.subTest(distribution=distribution):
                self.set_os_release(distribution, "9.4")
                self.curl_log.write_text("")
                self.package_log.write_text("")
                result = self.run_installer("--tag", self.tag)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    self.package_log.read_text().split()[0],
                    "dnf",
                )
                self.assertIn(
                    "rustbgpd-0.69.0-1.x86_64.rpm",
                    self.package_log.read_text(),
                )

    def test_explicit_tag_download_only_selects_arm64_package(self) -> None:
        destination = self.root / "download"
        result = self.run_installer(
            "--tag", self.tag, "--download-only", str(destination), FAKE_UNAME_M="aarch64"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            {path.name for path in destination.iterdir()},
            {"checksums-linux-arm64.txt", "rustbgpd_0.69.0_arm64.deb"},
        )
        self.assertNotIn("releases/latest", self.curl_log.read_text())
        self.assertEqual(self.package_log.read_text(), "")

    def test_prefix_extracts_the_verified_tarball_layout(self) -> None:
        prefix = self.root / "prefix"
        result = self.run_installer("--tag", self.tag, "--prefix", str(prefix))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((prefix / "rbgp").is_file())
        self.assertEqual((prefix / "share" / "release-note").read_text(), "verified payload\n")
        self.assertIn(f"Next: {prefix}/rbgp doctor", result.stdout)
        self.assertEqual(self.package_log.read_text(), "")

    def test_relative_directory_starting_with_dash_is_safe(self) -> None:
        prefix = self.run_installer("--tag", self.tag, "--prefix", "-prefix")
        self.assertEqual(prefix.returncode, 0, prefix.stderr)
        self.assertTrue((self.root / "-prefix" / "rbgp").is_file())

        download = self.run_installer(
            "--tag", self.tag, "--download-only", "-download"
        )
        self.assertEqual(download.returncode, 0, download.stderr)
        self.assertTrue((self.root / "-download" / "rustbgpd_0.69.0_amd64.deb").is_file())
        self.assertEqual(self.package_log.read_text(), "")

    def test_checksum_mismatch_stops_before_download_destination(self) -> None:
        (self.assets / "rustbgpd_0.69.0_amd64.deb").write_text("tampered\n")
        destination = self.root / "download"
        result = self.run_installer("--tag", self.tag, "--download-only", str(destination))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertFalse(destination.exists())
        self.assertEqual(self.package_log.read_text(), "")

    def test_duplicate_checksum_row_stops_before_download_destination(self) -> None:
        manifest = self.assets / "checksums-linux-amd64.txt"
        manifest.write_text(manifest.read_text() + manifest.read_text().splitlines()[1] + "\n")
        destination = self.root / "download"
        result = self.run_installer("--tag", self.tag, "--download-only", str(destination))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one digest", result.stderr)
        self.assertFalse(destination.exists())

    def test_unknown_architecture_stops_before_download(self) -> None:
        result = self.run_installer(FAKE_UNAME_M="ppc64le")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported architecture", result.stderr)
        self.assertEqual(self.curl_log.read_text(), "")

    def test_non_glibc_or_old_glibc_stops_before_download(self) -> None:
        for glibc in ("musl 1.2", "glibc 2.30", "glibc .31", "glibc 3."):
            with self.subTest(glibc=glibc):
                result = self.run_installer(FAKE_GLIBC=glibc)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.curl_log.read_text(), "")

    def test_empty_option_values_stop_before_package_invocation(self) -> None:
        for option in ("--tag", "--prefix", "--download-only"):
            with self.subTest(option=option):
                self.curl_log.write_text("")
                self.package_log.write_text("")
                result = self.run_installer(option, "")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.curl_log.read_text(), "")
                self.assertEqual(self.package_log.read_text(), "")

    def test_dangling_destinations_stop_before_download(self) -> None:
        for option in ("--prefix", "--download-only"):
            with self.subTest(option=option):
                destination = self.root / option.removeprefix("--")
                destination.symlink_to(self.root / "missing")
                self.curl_log.write_text("")
                result = self.run_installer("--tag", self.tag, option, str(destination))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.curl_log.read_text(), "")
                destination.unlink()

    def test_unsupported_or_old_native_distro_stops_before_download(self) -> None:
        for distribution, version in (("fedora", "40"), ("rhel", "8")):
            with self.subTest(distribution=distribution, version=version):
                self.set_os_release(distribution, version)
                self.curl_log.write_text("")
                self.package_log.write_text("")
                result = self.run_installer("--tag", self.tag)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.curl_log.read_text(), "")
                self.assertEqual(self.package_log.read_text(), "")

    def test_non_stable_or_untrusted_tag_stops_before_artifact_download(self) -> None:
        unsafe = self.run_installer("--tag", "v0.70.0-rc.1")
        self.assertNotEqual(unsafe.returncode, 0)
        self.assertEqual(self.curl_log.read_text(), "")

        untrusted = self.run_installer(FAKE_LATEST_URL="https://example.invalid/tag/v0.69.0")
        self.assertNotEqual(untrusted.returncode, 0)
        self.assertIn("releases/latest", self.curl_log.read_text())
        self.assertNotIn("releases/download/", self.curl_log.read_text())


if __name__ == "__main__":
    unittest.main()
