#!/usr/bin/env python3

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from unittest import mock
from pathlib import Path

from scripts import classify_heavy_ci_paths as heavy
from scripts.check_ci_image_primer_contract import (
    LAB_WORKFLOWS,
    PINS,
    VERSION_TAG,
    _jobs,
    check,
)


ROOT = Path(__file__).resolve().parents[1]

PR_FILES = {
    1523: (
        ".github/workflows/release-install-contract.yml",
        ".github/workflows/release.yml",
        "CHANGELOG.md",
        "docs/tutorials/quickstart.md",
        "docs/how-to/deployment.md",
        "packaging/nfpm.yaml",
        "scripts/check_release_install_contract.py",
        "scripts/test_check_release_install_contract.py",
    ),
    1524: (
        ".github/workflows/clusterfuzzlite.yml",
        ".github/workflows/fuzz.yml",
        "docs/project/roadmap.md",
        "crates/bfd/fuzz/.gitignore",
        "crates/bfd/fuzz/Cargo.toml",
        "crates/bfd/fuzz/decode_bfd_control.options",
        "crates/bfd/fuzz/fuzz_targets/decode_bfd_control.rs",
        "crates/bfd/fuzz/seeds/decode_bfd_control/valid_down",
        "crates/rpki/fuzz/.gitignore",
        "crates/rpki/fuzz/Cargo.toml",
        "crates/rpki/fuzz/decode_rtr_pdu.options",
        "crates/rpki/fuzz/fuzz_targets/decode_rtr_pdu.rs",
        "crates/rpki/fuzz/seeds/decode_rtr_pdu/reset_query_v1",
        "crates/wire/fuzz/seeds/decode_update/malformed_next_hop_length",
        "docs/how-to/fuzzing.md",
        "docs/receipts.md",
        "docs/adr/0125-v1-stability-contract.md",
        "fuzz/build-fuzzers.sh",
        "scripts/check_fuzz_target_inventory.py",
        "scripts/test_check_fuzz_target_inventory.py",
    ),
    1525: (
        "CHANGELOG.md",
        "crates/transport/src/lib.rs",
        "crates/transport/src/listener.rs",
        "crates/transport/src/socket_opts.rs",
        "crates/transport/tests/listener.rs",
    ),
    1527: (
        ".github/workflows/interop.yml",
        "docs/interop.md",
        "docs/receipts.md",
        "tests/interop/configs/frr-bgpd-m25-ipv6-auth.conf",
        "tests/interop/configs/rustbgpd-m25-md5-gtsm.toml",
        "tests/interop/m25-md5-gtsm-frr.clab.yml",
        "tests/interop/scripts/test-m25-md5-gtsm-frr.sh",
    ),
    1528: (
        ".github/workflows/release-install-contract.yml",
        "CHANGELOG.md",
        "Dockerfile",
        "README.md",
        "docs/tutorials/quickstart.md",
        "docs/cookbook/ixp-filter-pipeline.md",
        "docs/cookbook/monitoring-feed.md",
        "docs/how-to/deployment.md",
        "examples/birdwatcher-adapter/README.md",
        "examples/birdwatcher-adapter/src/main.rs",
        "packaging/nfpm.yaml",
        "scripts/build-packages.sh",
        "scripts/check_release_install_contract.py",
        "scripts/test_check_release_install_contract.py",
        "tests/birdwatcher_adapter_smoke.rs",
    ),
}


INTEROP = ".github/workflows/interop.yml"
KERNEL = ".github/workflows/kernel-dataplane.yml"
M39_GATE = (
    "      - name: Run M39 (deploy + test + destroy with retry)\n"
    "        if: steps.dataplane.outputs.vrf-available == 'true'\n"
)
# Line of the `run:` in a step injected just before M1's lab call.
INJECTED_RUN_LINE = (ROOT / INTEROP).read_text().split("      - name: Run M1 (")[0].count("\n") + 2
MANIFEST = ".github/pinned-archives.sha256"
ARCHIVE_PINS = dict(
    (archive, digest)
    for digest, archive in (
        line.split() for line in (ROOT / MANIFEST).read_text().splitlines()
        if line and not line.startswith("#")
    )
)
BIRD3_ARCHIVE = next(archive for archive in ARCHIVE_PINS if archive.startswith("bird-3."))
BIRD3_VERSION = BIRD3_ARCHIVE.removeprefix("bird-").removesuffix(".tar.gz")
BIRD3_DIGEST = ARCHIVE_PINS[BIRD3_ARCHIVE]
BIRD3_NEXT_VERSION = ".".join((*BIRD3_VERSION.split(".")[:2], str(int(BIRD3_VERSION.split(".")[2]) + 1)))
BIRD2_DIGEST = "853ea9e9adc36ea5277c3883c5ceddf06460fc496743dbdbff191975e1f55ebd"
DRIFTED = "f" * 64
M1_CALL = (
    "        uses: ./.github/actions/run-interop-test\n"
    "        with:\n"
    "          label: M1\n"
    "          topology: tests/interop/m1-frr.clab.yml\n"
    "          script: tests/interop/scripts/test-m1-frr.sh\n"
)
M83_BIRD_STAGE = (
    "      - name: Stage verified BIRD 2.19.3 archive\n"
    "        uses: ./.github/actions/stage-bird3-artifact\n"
    "        id: bird_archive\n"
    "        with:\n"
    '          version: "2.19.3"\n\n'
)
M74_STAGE = (
    "      - name: Stage verified GoBGP archive\n"
    "        uses: ./.github/actions/stage-gobgp-artifact\n"
    "        id: gobgp_archive\n\n"
)
M74_BUILD = (
    "      - name: Build gobgp:interop\n"
    "        run: >-\n"
    '          docker build --build-arg GOBGP_AMD64_SHA256="${{ steps.gobgp_archive.outputs.sha256 }}"\n'
    "          -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop\n\n"
)
UNVERIFIED_STEP = (
    "      - name: Fetch a tool\n"
    "        run: |\n"
    "          curl -fsSLo /tmp/tool.tgz https://example.invalid/tool.tgz\n"
    "          tar -xzf /tmp/tool.tgz -C /usr/local/bin\n\n"
)


class PrimerContractTests(unittest.TestCase):
    def mutated_errors(self, *edits):
        """Run the checker on a copy of the CI surfaces with each (path, old, new) applied."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / ".github", root / ".github")
            shutil.copy2(ROOT / "Dockerfile", root / "Dockerfile")
            (root / "tests" / "interop").mkdir(parents=True)
            for dockerfile in (ROOT / "tests" / "interop").glob("Dockerfile*"):
                shutil.copy2(dockerfile, root / "tests" / "interop" / dockerfile.name)
            for relative, old, new in edits:
                path = root / relative
                text = path.read_text()
                self.assertIn(old, text, f"fixture anchor missing in {relative}")
                path.write_text(text.replace(old, new, 1))
            return check(root)

    def assert_red(self, expect, *edits):
        errors = self.mutated_errors(*edits)
        self.assertTrue(
            any(expect in error for error in errors),
            f"no error containing {expect!r}: {errors}",
        )
        return errors

    def test_live_contract(self):
        self.assertEqual([], check(ROOT))

    def test_unmutated_fixture_is_green(self):
        self.assertEqual([], self.mutated_errors())

    # 1. Verified downloads.

    def test_archive_digest_copies_match_the_manifest(self):
        with self.subTest("Dockerfile copy drifts"):
            self.assert_red(
                f"tests/interop/Dockerfile.bird2:4: digest is not in {MANIFEST}",
                (
                    "tests/interop/Dockerfile.bird2",
                    f"ARG BIRD_SHA256={BIRD2_DIGEST}",
                    f"ARG BIRD_SHA256={DRIFTED}",
                ),
            )
        for name, dockerfile, old, new, archive in (
            (
                "BIRD 2 default digest is another manifest pin",
                "tests/interop/Dockerfile.bird2",
                f"ARG BIRD_SHA256={BIRD2_DIGEST}",
                f"ARG BIRD_SHA256={ARCHIVE_PINS['bird-2.19.2.tar.gz']}",
                "bird-2.19.3.tar.gz",
            ),
            (
                "GoBGP 4.x default digest is another manifest pin",
                "tests/interop/Dockerfile.gobgp-v47",
                f"ARG GOBGP_SHA256={ARCHIVE_PINS['gobgp_4.7.0_linux_amd64.tar.gz']}",
                f"ARG GOBGP_SHA256={ARCHIVE_PINS['gobgp_4.8.0_linux_amd64.tar.gz']}",
                "gobgp_4.7.0_linux_amd64.tar.gz",
            ),
            (
                "GoBGP per-architecture default digest is the other architecture's pin",
                "tests/interop/Dockerfile.gobgp",
                f"ARG GOBGP_ARM64_SHA256={ARCHIVE_PINS['gobgp_3.37.0_linux_arm64.tar.gz']}",
                f"ARG GOBGP_ARM64_SHA256={ARCHIVE_PINS['gobgp_3.37.0_linux_amd64.tar.gz']}",
                "gobgp_3.37.0_linux_arm64.tar.gz",
            ),
            # Malformed defaults must fail closed rather than skip the pairing.
            (
                "BIRD 2 default digest is not a hash",
                "tests/interop/Dockerfile.bird2",
                f"ARG BIRD_SHA256={BIRD2_DIGEST}",
                "ARG BIRD_SHA256=invalid",
                "bird-2.19.3.tar.gz",
            ),
            (
                "BIRD 2 default digest is empty",
                "tests/interop/Dockerfile.bird2",
                f"ARG BIRD_SHA256={BIRD2_DIGEST}",
                "ARG BIRD_SHA256=",
                "bird-2.19.3.tar.gz",
            ),
            # The manifest's lowercase spelling is the canonical pin that the
            # archive-pin helper and stage actions resolve; another spelling of
            # the same hash is a second, unchecked copy of the pin.
            (
                "BIRD 2 default digest is the right hash in uppercase",
                "tests/interop/Dockerfile.bird2",
                f"ARG BIRD_SHA256={BIRD2_DIGEST}",
                f"ARG BIRD_SHA256={BIRD2_DIGEST.upper()}",
                "bird-2.19.3.tar.gz",
            ),
        ):
            with self.subTest(name):
                self.assert_red(
                    f"{dockerfile}: default digest is not the {MANIFEST} pin for {archive}",
                    (dockerfile, old, new),
                )
        with self.subTest("manifest bumped: one local Docker default still needs a bump"):
            errors = self.mutated_errors((MANIFEST, BIRD3_DIGEST, DRIFTED))
            stale = {error.split(":", 1)[0] for error in errors if "is not in" in error}
            self.assertEqual(
                {"tests/interop/Dockerfile.bird3"},
                stale,
            )
        with self.subTest("duplicate archive entry"):
            self.assert_red(
                f"{MANIFEST}: malformed or duplicate entry",
                (MANIFEST, "\n", f"\n{DRIFTED}  {BIRD3_ARCHIVE}\n"),
            )

    def test_next_bird3_pin_needs_only_manifest_and_one_dockerfile_default(self):
        self.assertEqual([], self.mutated_errors(
            (MANIFEST, f"{BIRD3_DIGEST}  {BIRD3_ARCHIVE}", f"{DRIFTED}  bird-{BIRD3_NEXT_VERSION}.tar.gz"),
            ("tests/interop/Dockerfile.bird3", f"ARG BIRD_VERSION={BIRD3_VERSION}", f"ARG BIRD_VERSION={BIRD3_NEXT_VERSION}"),
            ("tests/interop/Dockerfile.bird3", f"ARG BIRD_SHA256={BIRD3_DIGEST}", f"ARG BIRD_SHA256={DRIFTED}"),
        ))
        with tempfile.TemporaryDirectory() as temporary:
            scripts = Path(temporary) / ".github" / "scripts"
            scripts.mkdir(parents=True)
            shutil.copy2(ROOT / ".github/scripts/archive-pin.sh", scripts / "archive-pin.sh")
            (scripts.parent / "pinned-archives.sha256").write_text(
                f"{DRIFTED}  bird-{BIRD3_NEXT_VERSION}.tar.gz\n"
            )
            version = subprocess.check_output([str(scripts / "archive-pin.sh"), "--bird3-version"], text=True)
            digest = subprocess.check_output([str(scripts / "archive-pin.sh"), f"bird-{version.strip()}.tar.gz"], text=True)
            self.assertEqual((version, digest), (f"{BIRD3_NEXT_VERSION}\n", f"{DRIFTED}\n"))
            action = (ROOT / ".github/actions/stage-bird3-artifact/action.yml").read_text()
            resolve = textwrap.dedent(action.split("      run: |\n", 1)[1].split("\n\n    - name:", 1)[0])
            resolve = resolve.replace("${{ inputs.version }}", "")
            output = Path(temporary) / "github-output"
            result = subprocess.run(
                ["bash", "-eo", "pipefail", "-c", resolve], cwd=temporary,
                env={**os.environ, "GITHUB_OUTPUT": str(output)},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(), f"version={BIRD3_NEXT_VERSION}\nsha256={DRIFTED}\n")

    def test_archive_lookup_requires_one_valid_exact_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            scripts = Path(temporary) / ".github" / "scripts"
            scripts.mkdir(parents=True)
            helper = scripts / "archive-pin.sh"
            shutil.copy2(ROOT / ".github/scripts/archive-pin.sh", helper)
            manifest = scripts.parent / "pinned-archives.sha256"
            archive = f"bird-{BIRD3_VERSION}.tar.gz"

            def lookup():
                return subprocess.run(
                    ["bash", str(helper), archive], capture_output=True, text=True, check=False
                )

            manifest.write_text(f"{'a' * 64}  {archive}\n")
            self.assertEqual(lookup().stdout.strip(), "a" * 64)
            manifest.write_text(f"{'a' * 64}  other.tar.gz\n")
            self.assertNotEqual(lookup().returncode, 0)
            manifest.write_text(f"{'a' * 64}  {archive}\n{'b' * 64}  {archive}\n")
            self.assertNotEqual(lookup().returncode, 0)
            manifest.write_text(f"{'a' * 64}  {archive} extra\n")
            self.assertNotEqual(lookup().returncode, 0)
            manifest.write_text(f"{'a' * 64}  {archive}\n{'b' * 64}  {archive} extra\n")
            self.assertNotEqual(lookup().returncode, 0)
            manifest.write_text(f"bad  {archive}\n")
            self.assertNotEqual(lookup().returncode, 0)

    def test_bird3_version_lookup_requires_one_valid_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            scripts = Path(temporary) / ".github" / "scripts"
            scripts.mkdir(parents=True)
            helper = scripts / "archive-pin.sh"
            shutil.copy2(ROOT / ".github/scripts/archive-pin.sh", helper)
            manifest = scripts.parent / "pinned-archives.sha256"

            def lookup():
                return subprocess.run(
                    ["bash", str(helper), "--bird3-version"],
                    capture_output=True, text=True, check=False,
                )

            pin = f"{'a' * 64}  bird-3.3.3.tar.gz\n"
            manifest.write_text(pin + f"{'b' * 64}  bird-2.19.2.tar.gz\n")
            result = lookup()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "3.3.3\n")
            for invalid in (
                "",
                pin + f"{'c' * 64}  bird-3.3.4.tar.gz\n",
                pin + "bird-3.3.4.tar.gz  bad\n",
                f"{'a' * 64}  bird-3.3.x.tar.gz\n",
                f"{'a' * 64}  bird-3.3.3.tar.gz extra\n",
                "bad  bird-3.3.3.tar.gz\n",
            ):
                manifest.write_text(invalid)
                self.assertNotEqual(lookup().returncode, 0, invalid)

    def test_explicit_empty_checksum_override_is_rejected(self):
        for installer, variable in (
            ("install-bird3.sh", "BIRD3_SHA256"),
            ("install-gobgp.sh", "GOBGP_SHA256"),
        ):
            with self.subTest(installer=installer):
                result = subprocess.run(
                    [str(ROOT / ".github/scripts" / installer), "--sha256", "", "--self-test"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid", result.stderr)
                ambient = subprocess.run(
                    [str(ROOT / ".github/scripts" / installer), "--self-test"],
                    env={**os.environ, variable: "not-a-checksum"},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(ambient.returncode, 0, ambient.stderr)

    def test_resolve_steps_fail_before_writing_an_empty_checksum(self):
        cases = (
            (".github/actions/install-containerlab/action.yml", "0.74.3", "containerlab_0.74.3_linux_amd64.deb"),
            (".github/actions/install-gnmic-artifact/action.yml", None, "gnmic_0.46.0_Linux_x86_64.tar.gz"),
            (".github/actions/install-grpcurl-artifact/action.yml", None, "grpcurl_1.9.1_linux_x86_64.tar.gz"),
            (".github/actions/stage-bird3-artifact/action.yml", BIRD3_VERSION, BIRD3_ARCHIVE),
            (".github/actions/stage-bird3-artifact/action.yml", "", BIRD3_ARCHIVE),
            (".github/actions/stage-bird3-artifact/action.yml", "2.19.2", "bird-2.19.2.tar.gz"),
            (".github/actions/stage-gobgp-artifact/action.yml", "3.37.0", "gobgp_3.37.0_linux_amd64.tar.gz"),
            (".github/workflows/ci.yml", None, "rustbgpd-v0.64.0-linux-amd64.tar.gz"),
            (".github/workflows/kernel-dataplane.yml", None, BIRD3_ARCHIVE),
        )
        pins = dict(line.split() for line in (ROOT / MANIFEST).read_text().splitlines() if line and not line.startswith("#"))
        expected = {archive: digest for digest, archive in pins.items()}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / ".github/scripts"
            scripts.mkdir(parents=True)
            shutil.copy2(ROOT / ".github/scripts/archive-pin.sh", scripts / "archive-pin.sh")
            manifest = root / MANIFEST
            output = root / "github-output"
            for file, version, archive in cases:
                with self.subTest(file=file):
                    lines = (ROOT / file).read_text().splitlines()
                    step = next(i for i, line in enumerate(lines) if "- name: Resolve pinned " in line)
                    run = next(i for i in range(step + 1, len(lines)) if lines[i].lstrip() == "run: |")
                    indent = len(lines[run]) - len(lines[run].lstrip()) + 2
                    body = []
                    for line in lines[run + 1 :]:
                        if line.strip() and len(line) - len(line.lstrip()) < indent:
                            break
                        body.append(line[indent:])
                    script = "\n".join(body).replace("${{ inputs.version }}", version or "")
                    env = {**os.environ, "GITHUB_OUTPUT": str(output)}

                    manifest.write_text("")
                    output.write_text("")
                    missing = subprocess.run(
                        ["bash", "-eo", "pipefail", "-c", script], cwd=root, env=env,
                        capture_output=True, text=True, check=False,
                    )
                    self.assertNotEqual(missing.returncode, 0)
                    self.assertEqual(output.read_text(), "")

                    manifest.write_text((ROOT / MANIFEST).read_text())
                    valid = subprocess.run(
                        ["bash", "-eo", "pipefail", "-c", script], cwd=root, env=env,
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(valid.returncode, 0, valid.stderr)
                    version_output = f"version={version or BIRD3_VERSION}\n" if file.endswith("stage-bird3-artifact/action.yml") else ""
                    if file == KERNEL:
                        version_output = f"version={BIRD3_VERSION}\n"
                    self.assertEqual(output.read_text(), f"{version_output}sha256={expected[archive]}\n")

    def test_workflow_and_action_fetches_verify_their_archive(self):
        with self.subTest("workflow step fetches without a checksum"):
            self.assert_red(
                f"{INTEROP}:{INJECTED_RUN_LINE}: fetches without verifying a SHA-256",
                (INTEROP, "      - name: Run M1 (", UNVERIFIED_STEP + "      - name: Run M1 ("),
            )
        with self.subTest("composite action drops its checksum"):
            self.assert_red(
                ".github/actions/install-protobuf/action.yml:49: fetches without verifying a SHA-256",
                (
                    ".github/actions/install-protobuf/action.yml",
                    """printf '%s  %s\\n' "$PROTOC_SHA256" "$archive" | sha256sum -c -""",
                    "true",
                ),
            )
        with self.subTest("containerlab action drops its checksum"):
            self.assert_red(
                ".github/actions/install-containerlab/action.yml:38: fetches without verifying a SHA-256",
                (
                    ".github/actions/install-containerlab/action.yml",
                    "sha256sum --check --status",
                    "true",
                ),
            )

    def test_nothing_streams_network_bytes_into_tar(self):
        streamed = (
            "      - name: Fetch a tool\n"
            "        run: |\n"
            "          curl -fsSL https://example.invalid/tool.tgz | tar -xz\n"
            "          echo \"$SUM  tool.tgz\" | sha256sum -c -\n\n"
        )
        self.assert_red(
            f"{INTEROP}:{INJECTED_RUN_LINE}: streams network bytes into tar or a shell",
            (INTEROP, "      - name: Run M1 (", streamed + "      - name: Run M1 ("),
        )

    def test_streaming_is_caught_across_continued_lines(self):
        continued = (
            "      - name: Fetch a tool\n"
            "        run: |\n"
            "          curl -fsSL \\\n"
            "            https://example.invalid/tool.tgz | \\\n"
            "            tar -xz\n"
            "          echo \"$SUM  tool.tgz\" | sha256sum -c -\n\n"
        )
        self.assert_red(
            f"{INTEROP}:{INJECTED_RUN_LINE}: streams network bytes into tar or a shell",
            (INTEROP, "      - name: Run M1 (", continued + "      - name: Run M1 ("),
        )

    def test_installer_scripts_verify_what_they_fetch(self):
        installer = ".github/scripts/install-bird3.sh"
        with self.subTest("checksum verification removed"):
            self.assert_red(
                f"{installer}: fetch in download_archive_once is not verified by a SHA-256 check",
                (installer, "sha256sum --check --status", "cat"),
            )
        with self.subTest("verified installer gains a second, unverified download"):
            self.assert_red(
                f"{installer}: fetch in prepare_archive is not verified by a SHA-256 check",
                (
                    installer,
                    '    mkdir -p "$(dirname "$archive")"\n',
                    '    mkdir -p "$(dirname "$archive")"\n'
                    '    curl -fsSLo "$archive.sig" "https://example.invalid/bird.sig"\n',
                ),
            )
        with self.subTest("download helper called without verifying its output"):
            linters = ".github/scripts/install-developer-linters.sh"
            self.assert_red(
                f"{linters}: fetch in download is not verified by a SHA-256 check",
                (
                    linters,
                    'download "$RUFF_URL" "$ruff_archive"\n',
                    'download "$RUFF_URL" "$ruff_archive"\ndownload "$RUFF_URL" "$extra_archive"\n',
                ),
            )
        with self.subTest("download piped into tar"):
            self.assert_red(
                f"{installer}: streams network bytes into tar or a shell",
                (installer, "set -euo pipefail\n", 'set -euo pipefail\ncurl -fsSL "$1" | tar -xz\n'),
            )

    def test_lab_dockerfile_fetch_is_a_verified_fallback(self):
        with self.subTest("fetch no longer behind the staged archive"):
            self.assert_red(
                "tests/interop/Dockerfile.bird-v332: fetch is not a fallback behind a staged-archive check",
                ("tests/interop/Dockerfile.bird-v332", 'if [ ! -f "${target}" ]; then', "if true; then"),
            )
        with self.subTest("extracted without verification"):
            self.assert_red(
                "tests/interop/Dockerfile.gobgp-v47: fetch is not verified by sha256sum before extraction",
                (
                    "tests/interop/Dockerfile.gobgp-v47",
                    'echo "${GOBGP_SHA256}  ${archive}" | sha256sum --check --strict; \\',
                    "true; \\",
                ),
            )
        with self.subTest("new unverified download"):
            errors = self.assert_red(
                "tests/interop/Dockerfile.bird: streams network bytes into tar or a shell",
                (
                    "tests/interop/Dockerfile.bird",
                    "\nCMD ",
                    "\nRUN curl -fsSL https://example.invalid/x.tgz | tar -xz\nCMD ",
                ),
            )
            self.assertIn(
                "tests/interop/Dockerfile.bird: fetch is not verified by sha256sum before extraction",
                errors,
            )
        with self.subTest("root Dockerfile built without file: gains a download"):
            self.assert_red(
                "Dockerfile: fetch is not verified by sha256sum before extraction",
                (
                    "Dockerfile",
                    "\nFROM debian:bookworm-slim AS runtime\n",
                    "\nRUN curl -fsSLo /tmp/x.tgz https://example.invalid/x.tgz && tar -xzf /tmp/x.tgz"
                    "\nFROM debian:bookworm-slim AS runtime\n",
                ),
            )
        with self.subTest("checksum covers a different file than the one extracted"):
            self.assert_red(
                "tests/interop/Dockerfile.gobgp-v47: fetch is not verified by sha256sum before extraction",
                ("tests/interop/Dockerfile.gobgp-v47", 'tar -xzf "${archive}"', 'tar -xzf "/tmp/other.tgz"'),
            )
        with self.subTest("only the partial download is checked"):
            self.assert_red(
                "tests/interop/Dockerfile.bird-v332: fetch is not verified by sha256sum before extraction",
                (
                    "tests/interop/Dockerfile.bird-v332",
                    'echo "${BIRD_SHA256}  ${target}" | sha256sum --check --strict; \\',
                    "true; \\",
                ),
            )

    def test_lab_jobs_stage_the_archive_they_build(self):
        with self.subTest("stage step removed"):
            self.assert_red(
                "interop.yml:m83: builds tests/interop/Dockerfile.bird2 without first staging bird3 2.19.3",
                (INTEROP, M83_BIRD_STAGE, ""),
            )
        with self.subTest("different version staged"):
            self.assert_red(
                "interop.yml:m83: builds tests/interop/Dockerfile.bird2 without first staging bird3 2.19.3",
                (INTEROP, M83_BIRD_STAGE, M83_BIRD_STAGE.replace('"2.19.3"', '"3.3.2"')),
            )
        with self.subTest("frozen control falls back to the current Dockerfile default"):
            self.assert_red(
                "interop.yml:m100: builds tests/interop/Dockerfile.bird2 without first staging bird3 2.19.3",
                (INTEROP, "            BIRD_VERSION=2.19.2\n", ""),
            )
        with self.subTest("stage runs after the build"):
            self.assert_red(
                "interop.yml:m74: builds tests/interop/Dockerfile.gobgp without first staging gobgp 3.37.0",
                (INTEROP, M74_STAGE + M74_BUILD, M74_BUILD + M74_STAGE),
            )
        with self.subTest("local Docker version default drifts from the manifest"):
            self.assert_red(
                "tests/interop/Dockerfile.bird3: BIRD version default differs",
                ("tests/interop/Dockerfile.bird3", f"ARG BIRD_VERSION={BIRD3_VERSION}", f"ARG BIRD_VERSION={BIRD3_NEXT_VERSION}"),
            )
        with self.subTest("build arg drifts from the staged version"):
            self.assert_red(
                "kernel-dataplane.yml:m43: builds tests/interop/Dockerfile.bird3 without first staging bird3 2.19.2",
                (KERNEL, "BIRD_VERSION=${{ steps.bird_archive.outputs.version }}", "BIRD_VERSION=2.19.2"),
            )
        with self.subTest("build drops its staged checksum"):
            self.assert_red(
                "kernel-dataplane.yml:m43: builds tests/interop/Dockerfile.bird3 without its staged BIRD checksum",
                (KERNEL, "BIRD_SHA256=${{ steps.bird_archive.outputs.sha256 }}", "BIRD_SHA256=not-a-pin"),
            )
        with self.subTest("checksum comes from a different staged BIRD version"):
            self.assert_red(
                "interop.yml:m101: builds tests/interop/Dockerfile.bird-v332 without its staged BIRD checksum",
                (
                    INTEROP,
                    "        id: bird_archive\n\n      - name: Build checksum-pinned BIRD 3 image",
                    "        id: bird_archive\n\n"
                    "      - name: Stage verified BIRD 2 archive\n"
                    "        uses: ./.github/actions/stage-bird3-artifact\n"
                    "        id: bird2_archive\n"
                    "        with:\n"
                    '          version: "2.19.2"\n\n'
                    "      - name: Build checksum-pinned BIRD 3 image",
                ),
                (
                    INTEROP,
                    "BIRD_VERSION=${{ steps.bird_archive.outputs.version }}\n"
                    "            BIRD_SHA256=${{ steps.bird_archive.outputs.sha256 }}",
                    "BIRD_VERSION=${{ steps.bird_archive.outputs.version }}\n"
                    "            BIRD_SHA256=${{ steps.bird2_archive.outputs.sha256 }}",
                ),
            )

    def test_lab_workflows_do_not_use_the_artifact_service(self):
        self.assert_red(
            "interop.yml: a lab dependency flows through the artifact service",
            (INTEROP, "      - name: Run M1 (", "      - uses: actions/download-artifact@v8\n\n      - name: Run M1 ("),
        )

    # 2. Action refs.

    def test_external_action_refs_are_reviewed_version_tags(self):
        for ref in PINS:
            self.assertRegex(ref, VERSION_TAG)
        audit = ".github/workflows/audit.yml"
        clab = ".github/actions/install-containerlab/action.yml"
        sha = "0123456789abcdef0123456789abcdef01234567"
        for relative, old, new, expect in (
            (audit, "actions/checkout@v7", "actions/checkout@main", "not a reviewed version tag: actions/checkout@main"),
            (audit, "actions/checkout@v7", f"actions/checkout@{sha}", f"not a reviewed version tag: actions/checkout@{sha}"),
            (audit, "actions/checkout@v7", "actions/checkout@v8", "not in the reviewed pin set: actions/checkout@v8"),
            (
                audit,
                "      - uses: actions/checkout@v7\n",
                "      - uses: actions/checkout@v7\n      - uses: actions/setup-python@v5\n",
                "not in the reviewed pin set: actions/setup-python@v5",
            ),
            (clab, "actions/cache/restore@v6", "actions/cache/restore@main", "not a reviewed version tag: actions/cache/restore@main"),
        ):
            with self.subTest(relative=relative, ref=new.strip()):
                self.assert_red(f"{relative}: action ref is {expect}", (relative, old, new))

    # 3. Permissions.

    def test_workflow_permissions_stay_read_only(self):
        top = "permissions:\n  contents: read\n"
        for name, edit, expect in (
            ("interop.yml", (INTEROP, top, "permissions:\n  contents: write\n"), "grants contents: write"),
            (
                "interop.yml",
                (INTEROP, "    name: Prime rustbgpd:dev build cache\n", "    name: Prime rustbgpd:dev build cache\n    permissions: write-all\n"),
                "grants write-all",
            ),
            (
                "audit.yml",
                (".github/workflows/audit.yml", "      checks: write\n", "      checks: write\n      pull-requests: write\n"),
                "grants pull-requests: write",
            ),
            (
                "kernel-dataplane.yml",
                (KERNEL, "  pull_request:\n", "  pull_request_target:\n"),
                "runs on pull_request_target",
            ),
            ("ci.yml", (".github/workflows/ci.yml", top, ""), "no top-level permissions block"),
        ):
            with self.subTest(expect=expect):
                self.assert_red(f"{name}: {expect}", edit)

    # 4. Lab wiring.

    def test_lab_jobs_depend_on_the_primer(self):
        self.assert_red(
            "interop.yml:m1: does not need prime_dev_image",
            (INTEROP, "  m1:\n    needs: [prime_dev_image]\n", "  m1:\n"),
        )
        self.assert_red(
            "kernel-dataplane.yml:m43: does not need prime_dev_image",
            (KERNEL, "needs: [bird3_archive, prime_dev_image]", "needs: [bird3_archive]"),
        )

    def test_lab_calls_run_their_own_topology_and_script(self):
        for old, new, expect in (
            ("          label: M1\n", "", "interop.yml:m1: run-interop-test call missing label"),
            ("label: M1\n", "label: M2\n", "interop.yml:m1: no run-interop-test call labelled M1"),
            (
                "topology: tests/interop/m1-frr.clab.yml",
                "topology: tests/interop/m13-policy-frr.clab.yml",
                "interop.yml:m1: M1 topology drifted: tests/interop/m13-policy-frr.clab.yml",
            ),
            (
                "script: tests/interop/scripts/test-m1-frr.sh",
                "script: tests/interop/scripts/test-m13-policy-frr.sh",
                "interop.yml:m1: M1 script drifted: tests/interop/scripts/test-m13-policy-frr.sh",
            ),
        ):
            with self.subTest(seam=old.strip()):
                self.assert_red(expect, (INTEROP, M1_CALL, M1_CALL.replace(old, new)))
        with self.subTest(seam="lab job loses its scenario call"):
            self.assert_red(
                "kernel-dataplane.yml:m39: has no run-interop-test call",
                (KERNEL, M39_GATE + "        uses: ./.github/actions/run-interop-test\n", M39_GATE + "        uses: ./.github/actions/install-containerlab\n"),
            )
        with self.subTest(seam="variant label is the job identifier"):
            self.assert_red(
                "kernel-dataplane.yml:m36_m37_m37-ip_m38: no run-interop-test call labelled M37-IP",
                (KERNEL, "          label: M37+IP\n", "          label: M37\n"),
            )
        with self.subTest(seam="descriptive label satisfies the job name"):
            self.assertEqual(
                [],
                self.mutated_errors((KERNEL, "          label: M39\n", "          label: M39 crash-restart\n")),
            )

    def test_bundles_run_every_scenario_and_name_every_failure(self):
        bundle = "kernel-dataplane.yml:m36_m37_m37-ip_m38"
        fib = "kernel-dataplane.yml:m42_m50_m52_m58"
        text = (ROOT / KERNEL).read_text()
        m37 = text[text.index("      - name: Run M37 (") : text.index("      - name: Run M37+IP (")]
        m37_result = "            M37=${{ steps.m37.outcome }}/${{ steps.m37_teardown.outcome }}\n"
        m50_teardown = text[text.index("      - name: Verify M50 lab teardown") : text.index("      - name: Run M52 (")]
        for seam, expect, edits in (
            (
                "scenario dropped from a bundle",
                f"{bundle}: no run-interop-test call labelled M37",
                [(KERNEL, m37, ""), (KERNEL, m37_result, "")],
            ),
            (
                "scenario stops after an earlier failure",
                f"{bundle}: M38 run step does not run after an earlier failure",
                [(KERNEL, "        id: m38\n        if: ${{ !cancelled() && ", "        id: m38\n        if: ${{ ")],
            ),
            (
                "teardown stops after an earlier failure",
                f"{fib}: M58 teardown step does not run after an earlier failure",
                [(KERNEL, "        id: m58_teardown\n        if: ${{ !cancelled() && ", "        id: m58_teardown\n        if: ${{ ")],
            ),
            (
                "scenario guard adds success()",
                f"{bundle}: M37 run step does not run after an earlier failure",
                [(KERNEL, "        id: m37\n        if: ${{ !cancelled() && ", "        id: m37\n        if: ${{ !cancelled() && success() && ")],
            ),
            (
                "teardown guard adds success()",
                f"{fib}: M52 teardown step does not run after an earlier failure",
                [(KERNEL, "        id: m52_teardown\n        if: ${{ !cancelled() && ", "        id: m52_teardown\n        if: ${{ !cancelled() && success() && ")],
            ),
            (
                "report guard adds success()",
                f"{bundle}: does not end with its bundled scenario report",
                [(KERNEL, "      - name: Report bundled scenario results\n        if: ${{ !cancelled() }}\n", "      - name: Report bundled scenario results\n        if: ${{ !cancelled() && success() }}\n")],
            ),
            (
                "teardown check dropped",
                f"{fib}: M50 is not followed by its teardown check",
                [(KERNEL, m50_teardown, "")],
            ),
            (
                "teardown checks another topology",
                f"{fib}: M42 is not followed by its teardown check",
                [(KERNEL, "assert-lab-torn-down.sh 'M42' tests/interop/m42-", "assert-lab-torn-down.sh 'M42' tests/interop/m50-")],
            ),
            (
                "report forgets a scenario",
                f"{fib}: bundled scenario report does not name exactly its scenarios",
                [(KERNEL, "            M52=${{ steps.m52.outcome }}/${{ steps.m52_teardown.outcome }}\n", "")],
            ),
            (
                "report reads only the run outcome",
                f"{fib}: bundled scenario report does not name exactly its scenarios",
                [(KERNEL, "M52=${{ steps.m52.outcome }}/${{ steps.m52_teardown.outcome }}", "M52=${{ steps.m52.outcome }}")],
            ),
            (
                "report skipped after a failure",
                f"{bundle}: does not end with its bundled scenario report",
                [(KERNEL, "      - name: Report bundled scenario results\n        if: ${{ !cancelled() }}\n", "      - name: Report bundled scenario results\n")],
            ),
            (
                "failure swallowed by continue-on-error",
                f"{bundle}: a bundle step uses continue-on-error",
                [(KERNEL, "        id: m36\n", "        id: m36\n        continue-on-error: true\n")],
            ),
            (
                "bundle dropped from the aggregate",
                "kernel-dataplane.yml:check needs drifted: missing m42_m50_m52_m58; extra -",
                [(KERNEL, " m40, m42_m50_m52_m58,\n", " m40,\n")],
            ),
            (
                "host-setup step loses its id",
                f"{bundle}: has no host-setup step with id dataplane",
                [(KERNEL, "      - uses: ./.github/actions/setup-dataplane-host\n        id: dataplane\n      # One runner",
                  "      - uses: ./.github/actions/setup-dataplane-host\n      # One runner")],
            ),
        ):
            with self.subTest(seam=seam):
                self.assert_red(expect, *edits)

    def test_interop_bundle_runs_every_scenario_and_names_every_failure(self):
        bundle = "interop.yml:m26_m27_m28_m59_m91"
        text = (ROOT / INTEROP).read_text()
        m27 = text[text.index("      - name: Run M27 (") : text.index("      - name: Run M28 (")]
        m27_teardown = text[text.index("      - name: Verify M27 lab teardown") : text.index("      - name: Run M28 (")]
        gate = "if: ${{ !cancelled() && "
        report = "      - name: Report bundled scenario results\n        if: ${{ !cancelled() }}\n"
        for seam, expect, edits in (
            (
                "scenario dropped from the bundle",
                f"{bundle}: no run-interop-test call labelled M27",
                [(INTEROP, m27, ""),
                 (INTEROP, "            M27=${{ steps.m27.outcome }}/${{ steps.m27_teardown.outcome }}\n", "")],
            ),
            (
                "scenario stops after an earlier failure",
                f"{bundle}: M28 run step does not run after an earlier failure",
                [(INTEROP, f"        id: m28\n        {gate}", "        id: m28\n        if: ${{ ")],
            ),
            (
                "scenario guard adds success()",
                f"{bundle}: M59 run step does not run after an earlier failure",
                [(INTEROP, f"        id: m59\n        {gate}", f"        id: m59\n        {gate}success() && ")],
            ),
            (
                "teardown stops after an earlier failure",
                f"{bundle}: M91 teardown step does not run after an earlier failure",
                [(INTEROP, f"        id: m91_teardown\n        {gate}", "        id: m91_teardown\n        if: ${{ ")],
            ),
            (
                "teardown guard adds success()",
                f"{bundle}: M26 teardown step does not run after an earlier failure",
                [(INTEROP, f"        id: m26_teardown\n        {gate}", f"        id: m26_teardown\n        {gate}success() && ")],
            ),
            (
                "guard names another setup step",
                f"{bundle}: M28 run step does not run after an earlier failure",
                [(INTEROP, "        id: m28\n        if: ${{ !cancelled() && steps.dev_image.",
                  "        id: m28\n        if: ${{ !cancelled() && steps.dataplane.")],
            ),
            (
                "host-setup step loses its id",
                f"{bundle}: has no host-setup step with id dev_image",
                [(INTEROP, "        id: dev_image\n", "")],
            ),
            (
                "teardown check dropped",
                f"{bundle}: M27 is not followed by its teardown check",
                [(INTEROP, m27_teardown, "\n")],
            ),
            (
                "teardown checks another topology",
                f"{bundle}: M26 is not followed by its teardown check",
                [(INTEROP, "assert-lab-torn-down.sh 'M26' tests/interop/m26-", "assert-lab-torn-down.sh 'M26' tests/interop/m27-")],
            ),
            (
                "report forgets a scenario",
                f"{bundle}: bundled scenario report does not name exactly its scenarios",
                [(INTEROP, "            M59=${{ steps.m59.outcome }}/${{ steps.m59_teardown.outcome }}\n", "")],
            ),
            (
                "report reads only the run outcome",
                f"{bundle}: bundled scenario report does not name exactly its scenarios",
                [(INTEROP, "M91=${{ steps.m91.outcome }}/${{ steps.m91_teardown.outcome }}", "M91=${{ steps.m91.outcome }}")],
            ),
            (
                "report skipped after a failure",
                f"{bundle}: does not end with its bundled scenario report",
                [(INTEROP, report, "      - name: Report bundled scenario results\n")],
            ),
            (
                "report guard adds success()",
                f"{bundle}: does not end with its bundled scenario report",
                [(INTEROP, report, "      - name: Report bundled scenario results\n        if: ${{ !cancelled() && success() }}\n")],
            ),
            (
                "failure swallowed by continue-on-error",
                f"{bundle}: a bundle step uses continue-on-error",
                [(INTEROP, "        id: m26\n", "        id: m26\n        continue-on-error: true\n")],
            ),
            (
                "bundle dropped from the aggregate",
                "interop.yml:check needs drifted: missing m26_m27_m28_m59_m91; extra -",
                [(INTEROP, " m26_m27_m28_m59_m91, m92,", " m92,")],
            ),
        ):
            with self.subTest(seam=seam):
                self.assert_red(expect, *edits)

    # 5. Aggregate result.

    def new_lab_job(self):
        text = (ROOT / INTEROP).read_text()
        m1 = text.split("\n  m1:\n", 1)[1].split("\n  m13:\n", 1)[0]
        job = "\n  m999:\n" + m1.replace("M1", "M999").replace("m1-", "m999-") + "\n"
        return (INTEROP, "\n  m13:\n", job + "  m13:\n")

    def test_every_job_is_in_the_aggregate(self):
        with self.subTest("lab job dropped from needs"):
            self.assert_red(
                "interop.yml:check needs drifted: missing m1; extra -",
                (INTEROP, "prime_dev_image, m1,\n", "prime_dev_image,\n"),
            )
        with self.subTest("lab job dropped from the runtime roster"):
            self.assert_red(
                "interop.yml:check EXPECTED_JOBS drifted: missing m1; extra -",
                (INTEROP, "        m1 m13 m80", "        m13 m80"),
            )
        with self.subTest("new lab job not wired into the aggregate"):
            errors = self.assert_red(
                "interop.yml:check needs drifted: missing m999; extra -", self.new_lab_job()
            )
            self.assertIn("interop.yml:check EXPECTED_JOBS drifted: missing m999; extra -", errors)
        with self.subTest("new lab job following the pattern needs no checker edit"):
            self.assertEqual(
                [],
                self.mutated_errors(
                    self.new_lab_job(),
                    (INTEROP, "prime_dev_image, m1,\n", "prime_dev_image, m1, m999,\n"),
                    (INTEROP, "        m1 m13 m80", "        m1 m999 m13 m80"),
                ),
            )
        with self.subTest("aggregate stops running on failure"):
            self.assert_red(
                "kernel-dataplane.yml:check must run always()",
                (KERNEL, "    if: ${{ always() }}\n    needs: [classify_changes", "    if: success()\n    needs: [classify_changes"),
            )

    # 6. Classifier checkout.

    def test_classifier_checkout_stays_shallow_inside_its_cap(self):
        checkout = "      - uses: actions/checkout@v7\n      - name: Classify complete pull-request diff\n"
        run = "        run: python3 scripts/classify_heavy_ci_paths.py\n"
        for workflow in (INTEROP, KERNEL):
            name = Path(workflow).name
            for seam, depth in (
                ("unconditional full history", "0"),
                ("full history for pull requests", "${{ github.event_name == 'pull_request' && 0 || 1 }}"),
            ):
                with self.subTest(workflow=name, seam=seam):
                    self.assert_red(
                        f"{name}:classify_changes overrides the shallow checkout depth",
                        (workflow, checkout, checkout.replace(
                            "@v7\n", f"@v7\n        with:\n          fetch-depth: {depth}\n"
                        )),
                    )
            with self.subTest(workflow=name, seam="shallow diff without merge-base coverage"):
                self.assert_red(
                    f"{name}:classify_changes does not run the merge-base classifier",
                    (workflow, run, '        run: git diff --name-only "$BASE_SHA...$HEAD_SHA"\n'),
                )
            with self.subTest(workflow=name, seam="cap raised"):
                self.assert_red(
                    f"{name}:classify_changes must keep timeout-minutes: 1",
                    (workflow, "    timeout-minutes: 1\n", "    timeout-minutes: 2\n"),
                )

    def run_aggregate(self, workflow, run_labs, results):
        text = (ROOT / ".github" / "workflows" / workflow).read_text()
        jobs = _jobs(text)
        script = jobs["check"].split("          python3 - <<'PY'\n", 1)[1].split("\n          PY", 1)[0]
        expected = [job for job in jobs if job != "check"]
        needs = {
            job: {
                "result": results.get(job, "success"),
                "outputs": {"run_labs": run_labs} if job == "classify_changes" else {},
            }
            for job in expected
        }
        if "m43" in needs and needs["m43"]["result"] == "success":
            # A live m43 republishes its TCP-AO probe verdict; the aggregate
            # requires it whenever the labs ran.
            needs["m43"]["outputs"] = {"tcp_ao_supported": "true"}
        return subprocess.run(
            ["python3", "-c", textwrap.dedent(script)],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "NEEDS_CONTEXT": json.dumps(needs), "EXPECTED_JOBS": " ".join(expected)},
        ).returncode

    def test_heavy_workflow_aggregate_truth_table(self):
        for workflow in LAB_WORKFLOWS:
            jobs = [job for job in _jobs((ROOT / ".github/workflows" / workflow).read_text()) if job != "check"]
            first_lab = next(job for job in jobs if job.startswith("m"))
            with self.subTest(workflow=workflow, state="labs run"):
                self.assertEqual(0, self.run_aggregate(workflow, "true", {}))
            with self.subTest(workflow=workflow, state="docs only"):
                skipped = {job: "skipped" for job in jobs if job != "classify_changes"}
                self.assertEqual(0, self.run_aggregate(workflow, "false", skipped))
            for job in ("prime_dev_image", first_lab):
                for result in ("failure", "cancelled", "skipped"):
                    with self.subTest(workflow=workflow, job=job, result=result):
                        self.assertNotEqual(0, self.run_aggregate(workflow, "true", {job: result}))
            for run_labs, results in (
                ("", {}),
                ("unknown", {}),
                ("true", {"classify_changes": "failure"}),
                ("false", {"prime_dev_image": "success"}),
            ):
                with self.subTest(workflow=workflow, state=(run_labs, results)):
                    self.assertNotEqual(0, self.run_aggregate(workflow, run_labs, results))


class LabBundleHelperTests(unittest.TestCase):
    """The bundle helpers, run against stubbed sudo, containerlab, docker and ip."""

    STUBS = {
        "sudo": 'exec "$@"',
        "containerlab": 'echo "containerlab $*" >> "$CALLS"',
        "docker": 'echo "docker $*" >> "$CALLS"\n[ "$1 $2" != "ps -aq" ] || { [ -z "${DOCKER_FAILS:-}" ] || exit 1; printf %s "${LEAK_CONTAINERS:-}"; }',
        "ip": 'echo "ip $*" >> "$CALLS"\n[ "$1 $2" != "netns list" ] || { [ -z "${IP_FAILS:-}" ] || exit 1; printf %s "${LEAK_NETNS:-}"; }',
    }

    def run_helper(self, script, *args, **env):
        with tempfile.TemporaryDirectory() as temporary:
            stubs = Path(temporary)
            for name, body in self.STUBS.items():
                (stubs / name).write_text(f"#!/usr/bin/env bash\n{body}\n")
                (stubs / name).chmod(0o755)
            calls = stubs / "calls"
            calls.write_text("")
            result = subprocess.run(
                ["bash", str(ROOT / ".github/scripts" / script), *args],
                env={"PATH": f"{stubs}:/usr/bin:/bin", "CALLS": str(calls), **env},
                capture_output=True, text=True, check=False,
            )
            return result, calls.read_text()

    def test_teardown_check_passes_a_clean_host(self):
        result, calls = self.run_helper("assert-lab-torn-down.sh", "M36", "m36.clab.yml")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("containerlab destroy -t m36.clab.yml --cleanup", calls)
        self.assertNotIn("rm -f", calls)

    def test_teardown_check_fails_when_an_inventory_cannot_be_read(self):
        for env, inventory in (
            ({"DOCKER_FAILS": "1"}, "containerlab containers"),
            ({"IP_FAILS": "1"}, "network namespaces"),
        ):
            with self.subTest(**env):
                result, _ = self.run_helper("assert-lab-torn-down.sh", "M36", "m36.clab.yml", **env)
                self.assertEqual(1, result.returncode, result.stdout)
                self.assertIn(f"::error::M36: cannot list {inventory}", result.stdout)

    def test_teardown_check_fails_and_clears_leaked_state(self):
        result, calls = self.run_helper(
            "assert-lab-torn-down.sh", "M36", "m36.clab.yml",
            LEAK_CONTAINERS="abc\ndef\n", LEAK_NETNS="clab-m36-pe1 (id: 3)\nother\n",
        )
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("::error::M36 left lab state behind", result.stdout)
        self.assertIn("docker rm -f abc def", calls)
        self.assertEqual(["ip netns delete clab-m36-pe1"],
                         [line for line in calls.splitlines() if "netns delete" in line])

    def test_report_names_every_failed_scenario(self):
        ok, _ = self.run_helper("report-bundled-scenarios.sh", RESULTS="M36=success/success M37=success/success")
        self.assertEqual(0, ok.returncode, ok.stdout + ok.stderr)
        failed, _ = self.run_helper(
            "report-bundled-scenarios.sh",
            RESULTS="M36=failure/success M37=success/success M37+IP=skipped/skipped M38=success/failure",
        )
        self.assertEqual(1, failed.returncode)
        self.assertIn(
            "::error::bundled scenarios failed: M36 (failure/success) "
            "M37+IP (skipped/skipped) M38 (success/failure)",
            failed.stdout,
        )
        empty, _ = self.run_helper("report-bundled-scenarios.sh", RESULTS="")
        self.assertNotEqual(0, empty.returncode)


class HeavyLabPathClassifierTests(unittest.TestCase):
    def git(self, repo: Path, *args: str) -> str:
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "CI contract",
            "GIT_AUTHOR_EMAIL": "ci-contract@example.invalid",
            "GIT_COMMITTER_NAME": "CI contract",
            "GIT_COMMITTER_EMAIL": "ci-contract@example.invalid",
        }
        return subprocess.check_output(
            ["git", *args], cwd=repo, env=env, text=True, stderr=subprocess.STDOUT
        ).strip()

    def commit_file(self, repo: Path, relative: str, content: str) -> str:
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        self.git(repo, "add", "--", relative)
        self.git(repo, "commit", "-qm", relative)
        return self.git(repo, "rev-parse", "HEAD")

    def test_reference_pull_request_manifests(self):
        for number in (1523, 1524):
            with self.subTest(pr=number):
                self.assertFalse(heavy.classify_paths(PR_FILES[number])[0])
        for number in (1525, 1527, 1528):
            with self.subTest(pr=number):
                self.assertTrue(heavy.classify_paths(PR_FILES[number])[0])

    def test_exact_safe_roster_and_fail_closed_boundaries(self):
        self.assertEqual(
            heavy.FUZZ_ROOTS,
            (
                "crates/bfd/fuzz",
                "crates/cli/fuzz",
                "crates/evpn/fuzz",
                "crates/mrt/fuzz",
                "crates/policy/fuzz",
                "crates/rpki/fuzz",
                "crates/wire/fuzz",
            ),
        )
        self.assertEqual(heavy.PACKAGE_ROOTS, ("packaging",))
        self.assertEqual(
            heavy.FUZZ_FILES,
            frozenset(
                {
                    ".github/workflows/clusterfuzzlite.yml",
                    ".github/workflows/fuzz.yml",
                    "fuzz/build-fuzzers.sh",
                    "fuzz/oss-fuzz/Dockerfile",
                    "fuzz/oss-fuzz/build.sh",
                    "fuzz/oss-fuzz/project.yaml",
                    "fuzz/rust-nightly.txt",
                    "scripts/check_fuzz_target_inventory.py",
                    "scripts/test_check_fuzz_target_inventory.py",
                    "scripts/fuzz_corpus_cache.py",
                    "scripts/test_fuzz_corpus_cache.py",
                    "scripts/check_fuzz_toolchain_pin.py",
                    "scripts/test_check_fuzz_toolchain_pin.py",
                }
            ),
        )
        self.assertEqual(
            heavy.PACKAGE_FILES,
            frozenset(
                {
                    ".github/workflows/release.yml",
                    ".github/workflows/release-install-contract.yml",
                    ".github/workflows/release-build-features.yml",
                    "scripts/build-packages.sh",
                    "scripts/check_release_build_features.py",
                    "scripts/test_check_release_build_features.py",
                    "scripts/check_release_install_contract.py",
                    "scripts/test_check_release_install_contract.py",
                }
            ),
        )
        for path in (
            "Cargo.toml",
            "Cargo.lock",
            "Dockerfile",
            ".dockerignore",
            "src/main.rs",
            "crates/wire/src/lib.rs",
            "examples/minimal/config.toml",
            "proto/rustbgpd.proto",
            "tests/interop/scripts/test-m1-frr.sh",
            ".github/actions/run-interop-test/action.yml",
            "fuzz/future-file",
        ):
            with self.subTest(path=path):
                self.assertTrue(heavy.classify_paths(("docs/receipts.md", path))[0])
        self.assertTrue(
            heavy.classify_paths(
                ("fuzz/build-fuzzers.sh", "scripts/build-packages.sh")
            )[0]
        )

    def test_fuzz_corpus_helpers_are_narrow_without_self_whitelisting(self):
        helpers = (
            "scripts/fuzz_corpus_cache.py",
            "scripts/test_fuzz_corpus_cache.py",
        )
        for helper in helpers:
            with self.subTest(helper=helper):
                self.assertEqual(
                    heavy.classify_paths((helper,)),
                    (False, "standalone fuzz only"),
                )
                with mock.patch.object(
                    heavy, "FUZZ_FILES", heavy.FUZZ_FILES - {helper}
                ):
                    self.assertEqual(
                        heavy.classify_paths((helper,)),
                        (True, "mixed or lab-relevant paths"),
                    )

        for governance_path in (
            "scripts/classify_heavy_ci_paths.py",
            "scripts/test_check_ci_image_primer_contract.py",
        ):
            with self.subTest(governance_path=governance_path):
                self.assertEqual(
                    heavy.classify_paths((governance_path,)),
                    (True, "mixed or lab-relevant paths"),
                )

    def test_empty_malformed_and_non_pull_events_run_labs(self):
        self.assertTrue(heavy.classify_paths(())[0])
        for path in ("", "/absolute", "fuzz//seed", "fuzz/../src", "fuzz/bad\nname"):
            with self.subTest(path=path):
                self.assertTrue(heavy.classify_paths((path,))[0])
        for event in ("push", "schedule", "workflow_dispatch", "merge_group", ""):
            with self.subTest(event=event):
                self.assertTrue(heavy.classify_event(event, "", "")[0])
        with self.assertRaises(heavy.ClassificationError):
            heavy.classify_event("pull_request", "", "")

    def test_draft_pull_requests_skip_labs_and_nothing_else_does(self):
        # A draft skips without reading the diff; labs run once it is ready.
        self.assertFalse(heavy.classify_event("pull_request", "", "", draft=True)[0])
        for event in ("push", "workflow_dispatch", "merge_group"):
            with self.subTest(event=event):
                self.assertTrue(heavy.classify_event(event, "", "", draft=True)[0])
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            for draft, expected in (("true", "false"), ("false", "true"), ("", "true")):
                with self.subTest(pr_draft=draft), mock.patch.object(
                    heavy, "changed_paths", return_value=("src/main.rs",)
                ), mock.patch.dict(
                    os.environ,
                    {
                        "GITHUB_OUTPUT": str(output),
                        "EVENT_NAME": "pull_request",
                        "PR_DRAFT": draft,
                    },
                    clear=True,
                ):
                    self.assertEqual(heavy.main(), 0)
                    self.assertEqual(output.read_text(), f"run_labs={expected}\n")
                    output.unlink()

    def test_lab_workflows_run_again_when_a_draft_is_marked_ready(self):
        for workflow in (KERNEL, INTEROP):
            with self.subTest(workflow=workflow):
                text = (ROOT / workflow).read_text()
                pull_request = text.split("  pull_request:\n", 1)[1].split("\n  workflow_dispatch:", 1)[0]
                self.assertIn(
                    "types: [opened, synchronize, reopened, ready_for_review]",
                    pull_request,
                )
                self.assertIn("PR_DRAFT: ${{ github.event.pull_request.draft }}", text)

    def test_main_writes_exact_output_and_requires_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            for verdict in (False, True):
                with self.subTest(run_labs=verdict), mock.patch.object(
                    heavy, "classify_event", return_value=(verdict, "test")
                ), mock.patch.dict(
                    os.environ, {"GITHUB_OUTPUT": str(output)}, clear=True
                ):
                    self.assertEqual(heavy.main(), 0)
                    self.assertEqual(
                        output.read_text(),
                        f"run_labs={'true' if verdict else 'false'}\n",
                    )
                    output.unlink()
            with mock.patch.object(
                heavy, "classify_event", return_value=(True, "test")
            ), mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(heavy.main(), 1)

    def test_three_dot_diff_excludes_base_only_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            self.git(repo, "init", "-q")
            root = self.commit_file(repo, "README", "root")
            self.git(repo, "checkout", "-qb", "feature")
            head = self.commit_file(repo, "fuzz/seeds/new", "seed")
            self.git(repo, "checkout", "-qB", "main", root)
            base = self.commit_file(repo, "src/base_only.rs", "base only")
            self.assertEqual(
                heavy.changed_paths(repo, base, head), ("fuzz/seeds/new",)
            )

    def test_unsafe_rename_and_missing_merge_base_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            self.git(repo, "init", "-q")
            base = self.commit_file(repo, "src/old.rs", "production")
            self.git(repo, "checkout", "-qb", "rename")
            (repo / "fuzz").mkdir()
            self.git(repo, "mv", "src/old.rs", "fuzz/old.rs")
            self.git(repo, "commit", "-qm", "rename")
            renamed = self.git(repo, "rev-parse", "HEAD")
            paths = heavy.changed_paths(repo, base, renamed)
            self.assertEqual(paths, ("fuzz/old.rs", "src/old.rs"))
            self.assertTrue(heavy.classify_paths(paths)[0])

            self.git(repo, "checkout", "--orphan", "unrelated")
            self.git(repo, "rm", "-qrf", ".")
            unrelated = self.commit_file(repo, "fuzz/only", "unrelated")
            with self.assertRaises(heavy.ClassificationError):
                heavy.changed_paths(repo, base, unrelated)

    def shallow_pull_request(self, temporary: Path) -> tuple[Path, Path, str, str]:
        """A one-commit clone of main whose PR head reaches an old main commit
        in two steps but its true merge base only through a long topic chain."""
        upstream = temporary / "upstream"
        upstream.mkdir()
        self.git(upstream, "init", "-q", "-b", "main")
        # GitHub serves any reachable commit by ID, as the classifier needs.
        self.git(upstream, "config", "uploadpack.allowAnySHA1InWant", "true")
        old = self.commit_file(upstream, "README", "root")
        merge_base = self.commit_file(upstream, "src/main_only.rs", "main")
        self.git(upstream, "checkout", "-qb", "short", old)
        self.commit_file(upstream, "crates/wire/fuzz/seeds/short", "short")
        self.git(upstream, "checkout", "-qb", "long", merge_base)
        for number in range(20):
            self.commit_file(upstream, f"crates/wire/fuzz/seeds/long{number}", "long")
        self.git(upstream, "merge", "-q", "--no-ff", "-m", "merge short", "short")
        head = self.git(upstream, "rev-parse", "HEAD")
        self.git(upstream, "checkout", "-q", "main")
        for number in range(2):
            base = self.commit_file(upstream, f"src/later{number}.rs", "later")
        self.git(temporary, "clone", "-q", "--depth=1", upstream.as_uri(), "clone")
        return upstream, temporary / "clone", base, head

    def test_shallow_pull_request_fetches_its_complete_merge_base(self):
        with tempfile.TemporaryDirectory() as temporary:
            upstream, clone, base, head = self.shallow_pull_request(Path(temporary))
            expected = heavy.changed_paths(upstream, base, head)
            self.assertNotIn("src/main_only.rs", expected)
            self.assertEqual(len(expected), 21)
            self.assertEqual(heavy.changed_paths(clone, base, head), expected)
            self.assertFalse(heavy.classify_paths(expected)[0])

    def test_shallow_pull_request_without_complete_merge_base_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, clone, base, head = self.shallow_pull_request(Path(temporary))
            # At depth 5 both sides reach the old root commit, but the true
            # merge base is still cut off behind the long chain: an older
            # merge base would wrongly add src/main_only.rs to the diff.
            with mock.patch.object(heavy, "FETCH_DEPTHS", (1, 5)):
                with self.assertRaisesRegex(heavy.ClassificationError, "no complete merge base"):
                    heavy.changed_paths(clone, base, head)
            self.git(clone, "remote", "remove", "origin")
            with self.assertRaises(heavy.ClassificationError):
                heavy.changed_paths(clone, base, head)

    def test_shallow_merge_base_candidate_cannot_hide_an_older_one(self):
        """Base and head both merge an older main commit back in. At depth 3
        the true merge base is a shallow boundary, so the older commit looks
        like a second, independent merge-base candidate. Dated last, it is the
        one Git diffs against, and the PR's revert of src/lib.rs disappears:
        a fuzz-only diff would skip the labs."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            upstream = temporary / "upstream"
            upstream.mkdir()
            self.git(upstream, "init", "-q", "-b", "main")
            self.git(upstream, "config", "uploadpack.allowAnySHA1InWant", "true")
            self.commit_file(upstream, "README", "root")
            with mock.patch.dict(os.environ, {"GIT_COMMITTER_DATE": "2030-01-01T00:00:00Z"}):
                older = self.commit_file(upstream, "src/lib.rs", "v1")
            for number in range(2, 12):
                merge_base = self.commit_file(upstream, "src/lib.rs", f"v{number}")

            def merge_older(files: dict[str, str]) -> str:
                for relative, content in files.items():
                    (upstream / relative).parent.mkdir(parents=True, exist_ok=True)
                    (upstream / relative).write_text(content)
                self.git(upstream, "add", "--", *files)
                self.git(upstream, "commit", "-qm", "tip")
                tree = self.git(upstream, "rev-parse", "HEAD^{tree}")
                return self.git(
                    upstream, "commit-tree", tree, "-p", "HEAD", "-p", older, "-m", "merge older"
                )

            head = merge_older({"src/lib.rs": "v1", "crates/wire/fuzz/seeds/pr": "seed"})
            self.git(upstream, "branch", "pr", head)
            self.git(upstream, "reset", "-q", "--hard", merge_base)
            base = merge_older({"src/base_only.rs": "base"})
            self.git(upstream, "reset", "-q", "--hard", base)
            expected = heavy.changed_paths(upstream, base, head)
            self.assertEqual(expected, ("crates/wire/fuzz/seeds/pr", "src/lib.rs"))
            self.assertTrue(heavy.classify_paths(expected)[0])
            self.git(temporary, "clone", "-q", "--depth=1", upstream.as_uri(), "clone")
            clone = temporary / "clone"
            with mock.patch.object(heavy, "FETCH_DEPTHS", (3,)):
                with self.assertRaisesRegex(heavy.ClassificationError, "no complete merge base"):
                    heavy.changed_paths(clone, base, head)
            self.assertEqual(heavy.changed_paths(clone, base, head), expected)

    def test_allowed_fuzz_roots_are_standalone_workspaces(self):
        main = json.loads(
            subprocess.check_output(
                ["cargo", "metadata", "--no-deps", "--format-version=1"],
                cwd=ROOT,
                text=True,
            )
        )
        main_members = set(main["workspace_members"])
        discovered = tuple(
            sorted(
                path.parent.relative_to(ROOT).as_posix()
                for path in ROOT.glob("crates/*/fuzz/Cargo.toml")
            )
        )
        self.assertEqual(discovered, heavy.FUZZ_ROOTS)
        for fuzz_root in discovered:
            manifest = ROOT / fuzz_root / "Cargo.toml"
            metadata = json.loads(
                subprocess.check_output(
                    [
                        "cargo",
                        "metadata",
                        "--no-deps",
                        "--format-version=1",
                        "--manifest-path",
                        str(manifest),
                    ],
                    cwd=ROOT,
                    text=True,
                )
            )
            self.assertEqual(Path(metadata["workspace_root"]), manifest.parent)
            self.assertEqual(len(metadata["workspace_members"]), 1)
            self.assertNotIn(metadata["workspace_members"][0], main_members)


if __name__ == "__main__":
    unittest.main()
