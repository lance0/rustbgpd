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
BIRD2192 = "aff89abba3b92b7637bd57e0168b8d7ae887747f160ada4973378ad72f5f3660"
DRIFTED = "f" * 64
M1_CALL = (
    "        uses: ./.github/actions/run-interop-test\n"
    "        with:\n"
    "          label: M1\n"
    "          topology: tests/interop/m1-frr.clab.yml\n"
    "          script: tests/interop/scripts/test-m1-frr.sh\n"
)
M83_BIRD_STAGE = (
    "      - name: Stage verified BIRD 2.19.2 archive\n"
    "        uses: ./.github/actions/stage-bird3-artifact\n"
    "        id: bird_archive\n"
    "        with:\n"
    '          version: "2.19.2"\n\n'
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
                f"tests/interop/Dockerfile.bird-v2192:4: digest is not in {MANIFEST}",
                (
                    "tests/interop/Dockerfile.bird-v2192",
                    f"ARG BIRD_SHA256={BIRD2192}",
                    f"ARG BIRD_SHA256={DRIFTED}",
                ),
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
                f"{INTEROP}:228: fetches without verifying a SHA-256",
                (INTEROP, "      - name: Run M1 (", UNVERIFIED_STEP + "      - name: Run M1 ("),
            )
        with self.subTest("composite action drops its checksum"):
            self.assert_red(
                ".github/actions/install-protobuf/action.yml:10: fetches without verifying a SHA-256",
                (
                    ".github/actions/install-protobuf/action.yml",
                    """printf '%s  %s\\n' "$sha256" "$archive" | sha256sum -c -""",
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
            f"{INTEROP}:228: streams network bytes into tar or a shell",
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
            f"{INTEROP}:228: streams network bytes into tar or a shell",
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
                "interop.yml:m83: builds tests/interop/Dockerfile.bird-v2192 without first staging bird3 2.19.2",
                (INTEROP, M83_BIRD_STAGE, ""),
            )
        with self.subTest("different version staged"):
            self.assert_red(
                "interop.yml:m83: builds tests/interop/Dockerfile.bird-v2192 without first staging bird3 2.19.2",
                (INTEROP, M83_BIRD_STAGE, M83_BIRD_STAGE.replace('"2.19.2"', '"3.3.2"')),
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
                "kernel-dataplane.yml:m36: has no run-interop-test call",
                (KERNEL, "        uses: ./.github/actions/run-interop-test\n", "        uses: ./.github/actions/install-containerlab\n"),
            )
        with self.subTest(seam="variant label is the job identifier"):
            self.assert_red(
                "kernel-dataplane.yml:m37-ip: no run-interop-test call labelled M37-IP",
                (KERNEL, "          label: M37+IP\n", "          label: M37\n"),
            )
        with self.subTest(seam="descriptive label satisfies the job name"):
            self.assertEqual(
                [],
                self.mutated_errors((KERNEL, "          label: M36\n", "          label: M36 crash-restart\n")),
            )

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
                    "scripts/build-packages.sh",
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
