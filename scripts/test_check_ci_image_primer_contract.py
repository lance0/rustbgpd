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
from scripts.check_ci_image_primer_contract import INTEROP, KERNEL, _list_needs, check


ROOT = Path(__file__).resolve().parents[1]

PR_FILES = {
    1523: (
        ".github/workflows/release-install-contract.yml",
        ".github/workflows/release.yml",
        "CHANGELOG.md",
        "docs/QUICKSTART.md",
        "docs/deployment.md",
        "packaging/nfpm.yaml",
        "scripts/check_release_install_contract.py",
        "scripts/test_check_release_install_contract.py",
    ),
    1524: (
        ".github/workflows/clusterfuzzlite.yml",
        ".github/workflows/fuzz.yml",
        "ROADMAP.md",
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
        "docs/FUZZING.md",
        "docs/RECEIPTS.md",
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
        "docs/INTEROP.md",
        "docs/RECEIPTS.md",
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
        "docs/QUICKSTART.md",
        "docs/cookbook/ixp-filter-pipeline.md",
        "docs/cookbook/monitoring-feed.md",
        "docs/deployment.md",
        "examples/birdwatcher-adapter/README.md",
        "examples/birdwatcher-adapter/src/main.rs",
        "packaging/nfpm.yaml",
        "scripts/build-packages.sh",
        "scripts/check_release_install_contract.py",
        "scripts/test_check_release_install_contract.py",
        "tests/birdwatcher_adapter_smoke.rs",
    ),
}


class PrimerContractTests(unittest.TestCase):
    def mutate(self, relative, old, new="", occurrence=0):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for fixture in (
                ".github/workflows",
                ".github/actions/install-grpcurl-artifact",
                ".github/actions/setup-dataplane-host",
            ):
                source = ROOT / fixture
                target = root / fixture
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(source, target)
            installer = root / ".github" / "scripts" / "install-grpcurl.sh"
            installer.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / installer.relative_to(root), installer)
            shutil.copy2(ROOT / "Dockerfile", root / "Dockerfile")
            gobgp = root / "tests" / "interop" / "Dockerfile.gobgp"
            gobgp.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / "tests" / "interop" / "Dockerfile.gobgp", gobgp)
            path = root / relative
            text = path.read_text()
            start = 0
            for _ in range(occurrence + 1):
                index = text.find(old, start)
                self.assertNotEqual(
                    -1, index, f"missing occurrence {occurrence}: {old}"
                )
                start = index + len(old)
            path.write_text(text[:index] + new + text[index + len(old) :])
            self.assertTrue(check(root), f"mutation stayed green: {relative}: {old}")

    def test_live_contract(self):
        self.assertEqual([], check(ROOT))

    def test_empty_flow_needs_is_empty(self):
        self.assertEqual([], _list_needs("    needs: []\n"))
        self.assertEqual(
            ["producer", "primer"],
            _list_needs("    needs: [producer, primer]\n"),
        )

    def test_missing_grpcurl_installer_returns_contract_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for fixture in (
                ".github/workflows",
                ".github/actions/install-grpcurl-artifact",
                ".github/actions/setup-dataplane-host",
            ):
                shutil.copytree(ROOT / fixture, root / fixture)
            shutil.copy2(ROOT / "Dockerfile", root / "Dockerfile")
            gobgp = root / "tests" / "interop" / "Dockerfile.gobgp"
            gobgp.parent.mkdir(parents=True)
            shutil.copy2(ROOT / "tests" / "interop" / "Dockerfile.gobgp", gobgp)
            self.assertIn("install-grpcurl.sh is missing", check(root))

    def test_grpcurl_installer_executable_mode_is_load_bearing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for fixture in (
                ".github/workflows",
                ".github/actions/install-grpcurl-artifact",
                ".github/actions/setup-dataplane-host",
            ):
                shutil.copytree(ROOT / fixture, root / fixture)
            shutil.copy2(ROOT / "Dockerfile", root / "Dockerfile")
            gobgp = root / "tests" / "interop" / "Dockerfile.gobgp"
            gobgp.parent.mkdir(parents=True)
            shutil.copy2(ROOT / "tests" / "interop" / "Dockerfile.gobgp", gobgp)
            installer = root / ".github" / "scripts" / "install-grpcurl.sh"
            installer.parent.mkdir(parents=True)
            shutil.copy2(ROOT / installer.relative_to(root), installer)
            installer.chmod(0o644)
            self.assertIn(
                "install-grpcurl.sh must have exact executable mode 100755",
                check(root),
            )

    def run_aggregate(self, workflow, run_labs, results):
        text = (ROOT / ".github" / "workflows" / workflow).read_text()
        block = text.rsplit("\n  check:\n", 1)[1]
        script = block.split("          python3 - <<'PY'\n", 1)[1].split(
            "\n          PY", 1
        )[0]
        script = textwrap.dedent(script)
        roster = INTEROP if workflow == "interop.yml" else KERNEL
        expected = ["classify_changes", "grpcurl_archive", "prime_dev_image", *roster]
        if workflow == "kernel-dataplane.yml":
            expected.append("netns")
        needs = {
            job: {
                "result": results.get(job, "success"),
                "outputs": {"run_labs": run_labs} if job == "classify_changes" else {},
            }
            for job in expected
        }
        return subprocess.run(
            ["python3", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "NEEDS_CONTEXT": json.dumps(needs),
                "EXPECTED_JOBS": " ".join(expected),
            },
        )

    def test_heavy_workflow_aggregate_truth_table(self):
        for workflow in ("interop.yml", "kernel-dataplane.yml"):
            with self.subTest(workflow=workflow, state="labs run"):
                self.assertEqual(0, self.run_aggregate(workflow, "true", {}).returncode)

            roster = INTEROP if workflow == "interop.yml" else KERNEL
            skipped = {
                job: "skipped" for job in ["grpcurl_archive", "prime_dev_image", *roster]
            }
            if workflow == "kernel-dataplane.yml":
                skipped["netns"] = "skipped"
            with self.subTest(workflow=workflow, state="docs only"):
                self.assertEqual(
                    0, self.run_aggregate(workflow, "false", skipped).returncode
                )

            for result in ("failure", "cancelled", "skipped"):
                with self.subTest(workflow=workflow, producer=result):
                    self.assertNotEqual(
                        0,
                        self.run_aggregate(
                            workflow, "true", {"grpcurl_archive": result}
                        ).returncode,
                    )
            with self.subTest(workflow=workflow, state="producer red consumers skipped"):
                failed = {job: "skipped" for job in roster}
                failed.update({"grpcurl_archive": "failure"})
                self.assertNotEqual(
                    0, self.run_aggregate(workflow, "true", failed).returncode
                )
            for run_labs, results in (
                ("", {}),
                ("unknown", {}),
                ("true", {"classify_changes": "failure"}),
                ("false", {"grpcurl_archive": "success"}),
            ):
                with self.subTest(workflow=workflow, state=(run_labs, results)):
                    self.assertNotEqual(
                        0,
                        self.run_aggregate(workflow, run_labs, results).returncode,
                    )

    def test_grpcurl_producers_are_load_bearing(self):
        archive = "grpcurl_1.9.1_linux_x86_64.tar.gz"
        checksum = "588c9c429476d9ed66cd3b2ae32283a6da36e0cfbb7e446f5d6a1b68dc770214"
        for workflow in ("interop.yml", "kernel-dataplane.yml"):
            relative = f".github/workflows/{workflow}"
            cases = (
                ("  grpcurl_archive:\n", "  removed_grpcurl_archive:\n", 0),
                ("needs: classify_changes", "needs: []", 0),
                (
                    "if: needs.classify_changes.outputs.run_labs == 'true'",
                    "if: false",
                    0,
                ),
                ("timeout-minutes: 10", "timeout-minutes: 9", 0),
                ("ref: ${{ github.sha }}", "ref: main", 0),
                ("actions/cache@v6", "actions/cache@main", 0),
                (f"key: grpcurl-v1.9.1-linux-x86_64-{checksum}", "key: grpcurl", 0),
                ("--prepare-archive", "--install-archive", 0),
                ("actions/upload-artifact@v7", "actions/upload-artifact@main", 0),
                ("name: grpcurl-v1.9.1-linux-x86_64", "name: grpcurl-latest", 0),
                ("if-no-files-found: error", "if-no-files-found: warn", 0),
                ("retention-days: 1", "retention-days: 30", 0),
                ("compression-level: 0", "compression-level: 6", 0),
                (
                    f"key: grpcurl-v1.9.1-linux-x86_64-{checksum}",
                    f"key: grpcurl-v1.9.1-linux-x86_64-{checksum}\n          restore-keys: grpcurl-",
                    0,
                ),
                (
                    "uses: actions/cache@v6",
                    "uses: actions/cache@v6\n        continue-on-error: true",
                    0,
                ),
            )
            for old, new, occurrence in cases:
                with self.subTest(workflow=workflow, seam=old, occurrence=occurrence):
                    self.mutate(relative, old, new, occurrence=occurrence)
            for occurrence in (0, 1):
                with self.subTest(workflow=workflow, path=occurrence):
                    self.mutate(
                        relative,
                        f"path: ${{{{ runner.temp }}}}/grpcurl-cache/{archive}",
                        "path: ${{ runner.temp }}/grpcurl-cache/wrong.tar.gz",
                        occurrence=occurrence,
                    )

    def test_grpcurl_offline_consumer_is_load_bearing(self):
        relative = ".github/actions/install-grpcurl-artifact/action.yml"
        for old, new in (
            ("actions/download-artifact@v8", "actions/download-artifact@main"),
            ("name: grpcurl-v1.9.1-linux-x86_64", "name: grpcurl-latest"),
            (
                "path: ${{ runner.temp }}/grpcurl-artifact",
                "path: ${{ runner.temp }}/wrong",
            ),
            ("--install-archive", "--prepare-archive"),
            (
                "set -euo pipefail",
                "set -euo pipefail\n        curl https://example.invalid/grpcurl",
            ),
            (
                "uses: actions/download-artifact@v8",
                "uses: actions/download-artifact@v8\n    - uses: actions/cache@v6",
            ),
        ):
            with self.subTest(seam=old):
                self.mutate(relative, old, new)

        self.mutate(
            ".github/actions/setup-dataplane-host/action.yml",
            "uses: ./.github/actions/install-grpcurl-artifact",
            "uses: ./.github/actions/install-containerlab",
        )
        self.mutate(
            ".github/workflows/interop.yml",
            "uses: ./.github/actions/install-grpcurl-artifact",
            "run: bash .github/scripts/install-grpcurl.sh",
        )

    def test_heavy_workflow_aggregate_source_is_load_bearing(self):
        for workflow, lab in (
            ("interop.yml", "m1"),
            ("kernel-dataplane.yml", "m36"),
        ):
            relative = f".github/workflows/{workflow}"
            needs_prefix = (
                "needs: [classify_changes, grpcurl_archive, prime_dev_image, "
            )
            for old, new in (
                ("if: ${{ always() }}", "if: success()"),
                ("NEEDS_CONTEXT: ${{ toJSON(needs) }}", "NEEDS_CONTEXT: '{}'"),
                (f"{needs_prefix}{lab},", needs_prefix),
                (
                    'classifier.get("result") != "success"',
                    'classifier.get("result") == "success"',
                ),
                ("result != expected_result", "False"),
                (
                    "    if: ${{ always() }}",
                    "    continue-on-error: true\n    if: ${{ always() }}",
                ),
            ):
                with self.subTest(workflow=workflow, seam=old):
                    self.mutate(relative, old, new)

    def test_classifier_workflow_wiring_is_load_bearing(self):
        for workflow in ("interop.yml", "kernel-dataplane.yml"):
            relative = f".github/workflows/{workflow}"
            for old in (
                "run: python3 scripts/classify_heavy_ci_paths.py",
                "needs: classify_changes",
                "if: needs.classify_changes.outputs.run_labs == 'true'",
            ):
                with self.subTest(workflow=workflow, seam=old):
                    self.mutate(relative, old, f"# {old}")
            for old, forbidden, indent in (
                ("runs-on: ubuntu-latest", "if: false", "    "),
                ("timeout-minutes: 1", "continue-on-error: true", "    "),
                ("id: classify", "continue-on-error: true", "        "),
            ):
                with self.subTest(workflow=workflow, forbidden=forbidden, at=old):
                    self.mutate(relative, old, f"{forbidden}\n{indent}{old}")

        for old in (
            "needs: classify_changes",
            "if: needs.classify_changes.outputs.run_labs == 'true'",
        ):
            with self.subTest(workflow="kernel netns", seam=old):
                self.mutate(
                    ".github/workflows/kernel-dataplane.yml",
                    old,
                    f"# {old}",
                    occurrence=2,
                )

    def test_destructive_workflow_seams(self):
        cases = (
            (
                ".github/workflows/ci.yml",
                "cancel-in-progress: true",
                "cancel-in-progress: false",
            ),
            (
                ".github/workflows/ci.yml",
                "group: ${{ github.workflow }}-${{ github.ref }}",
                "group: shared",
            ),
            (
                ".github/workflows/audit.yml",
                "workflow_dispatch: {}",
                "workflow_dispatch:\n    inputs: {}",
            ),
            (
                ".github/workflows/audit.yml",
                "permissions:\n  contents: read",
                "permissions:\n  contents: write",
            ),
            (
                ".github/workflows/interop.yml",
                "  prime_dev_image:\n",
                "  renamed_primer:\n",
            ),
            (".github/workflows/interop.yml", "  m1:\n", "  removed_m1:\n"),
            (".github/workflows/interop.yml", "ref: ${{ github.sha }}", "ref: main"),
            (
                ".github/workflows/interop.yml",
                "group: rustbgpd-dev-image-${{ github.sha }}",
                "group: rustbgpd-dev-image-main",
            ),
            (
                ".github/workflows/interop.yml",
                "cancel-in-progress: false",
                "cancel-in-progress: true",
            ),
            (
                ".github/workflows/interop.yml",
                "needs: [grpcurl_archive, prime_dev_image]",
                "needs: []",
            ),
            (
                ".github/workflows/interop.yml",
                "cache-from: type=gha,scope=rustbgpd-dev",
                "cache-from: type=gha",
            ),
            (
                ".github/workflows/interop.yml",
                "cache-to: type=gha,scope=rustbgpd-dev,mode=max,ignore-error=true",
                "cache-to: type=gha",
            ),
            (".github/workflows/interop.yml", "load: true", "load: false"),
            (
                ".github/workflows/interop.yml",
                "          load: true\n",
                "          load: true\n          cache-to: type=gha\n",
            ),
            (
                ".github/workflows/interop.yml",
                "uses: ./.github/actions/run-interop-test",
                "uses: ./.github/actions/install-containerlab",
            ),
            (
                ".github/workflows/kernel-dataplane.yml",
                "uses: ./.github/actions/setup-dataplane-host",
                "uses: ./.github/actions/install-containerlab",
            ),
            (
                ".github/workflows/kernel-dataplane.yml",
                "actions/checkout@v7",
                "actions/checkout@main",
            ),
            (
                ".github/workflows/kernel-dataplane.yml",
                "  netns:\n",
                "  removed-netns:\n",
            ),
            (
                ".github/workflows/kernel-dataplane.yml",
                "  netns:\n",
                "  netns:\n    needs: prime_dev_image\n",
            ),
        )
        for relative, old, new in cases:
            with self.subTest(old=old):
                self.mutate(relative, old, new)

    def test_both_primers_and_real_consumer_fail_independently(self):
        for workflow in ("interop.yml", "kernel-dataplane.yml"):
            relative = f".github/workflows/{workflow}"
            for old, new in (
                ("  prime_dev_image:\n", "  removed_primer:\n"),
                ("timeout-minutes: 30", "timeout-minutes: 29"),
                ("ref: ${{ github.sha }}", "ref: main"),
                (
                    "group: rustbgpd-dev-image-${{ github.sha }}",
                    "group: rustbgpd-dev-image-main",
                ),
                ("cancel-in-progress: false", "cancel-in-progress: true"),
                ("load: false", "load: true"),
                ("context: .", "context: elsewhere"),
                ("tags: rustbgpd:dev", "tags: other:dev"),
                ("target: dev", "target: release"),
                ("cache-from: type=gha,scope=rustbgpd-dev", "cache-from: type=gha"),
                (
                    "cache-to: type=gha,scope=rustbgpd-dev,mode=max,ignore-error=true",
                    "cache-to: type=gha",
                ),
                (
                    "actions/checkout@v7",
                    "actions/checkout@main",
                ),
                (
                    "docker/setup-buildx-action@v4",
                    "docker/setup-buildx-action@main",
                ),
                (
                    "docker/build-push-action@v7",
                    "docker/build-push-action@main",
                ),
            ):
                with self.subTest(workflow=workflow, seam=old):
                    self.mutate(relative, old, new)

        for workflow in ("ci.yml", "audit.yml", "interop.yml", "kernel-dataplane.yml"):
            relative = f".github/workflows/{workflow}"
            with self.subTest(workflow=workflow, seam="group"):
                self.mutate(
                    relative,
                    "group: ${{ github.workflow }}-${{ github.ref }}",
                    "group: shared",
                )
            with self.subTest(workflow=workflow, seam="cancel"):
                self.mutate(
                    relative, "cancel-in-progress: true", "cancel-in-progress: false"
                )

        interop = ".github/workflows/interop.yml"
        with self.subTest(workflow=interop, seam="consumer import"):
            self.mutate(
                interop,
                "cache-from: type=gha,scope=rustbgpd-dev",
                "cache-from: type=gha",
                occurrence=1,
            )
        with self.subTest(workflow=interop, seam="consumer export"):
            self.mutate(
                interop,
                "          load: true\n",
                "          load: true\n          cache-to: type=gha\n",
            )
        with self.subTest(workflow=interop, seam="consumer checkout"):
            self.mutate(
                interop,
                "actions/checkout@v7",
                "actions/checkout@main",
                occurrence=3,
            )

        kernel = ".github/workflows/kernel-dataplane.yml"
        with self.subTest(workflow=kernel, seam="consumer checkout"):
            self.mutate(
                kernel,
                "actions/checkout@v7",
                "actions/checkout@main",
                occurrence=3,
            )
        with self.subTest(workflow=kernel, seam="consumer needs"):
            self.mutate(
                kernel,
                "needs: [grpcurl_archive, prime_dev_image]",
                "needs: []",
            )

    def test_destructive_consumer_action_seams(self):
        relative = ".github/actions/setup-dataplane-host/action.yml"
        for old, new in (
            ("cache-from: type=gha,scope=rustbgpd-dev", "cache-from: type=gha"),
            ("load: true", "load: false"),
            ("tags: rustbgpd:dev", "tags: other:dev"),
            ("target: dev", "target: release"),
            ("context: .", "context: elsewhere"),
            (
                "docker/setup-buildx-action@v4",
                "docker/setup-buildx-action@main",
            ),
            (
                "docker/build-push-action@v7",
                "docker/build-push-action@main",
            ),
            (
                "cache-from: type=gha,scope=rustbgpd-dev",
                "cache-from: type=gha,scope=rustbgpd-dev\n        cache-to: type=gha",
            ),
        ):
            with self.subTest(old=old):
                self.mutate(relative, old, new)

    def test_combined_cheap_interop_job_and_m91_target_are_load_bearing(self):
        relative = ".github/workflows/interop.yml"
        for old, new in (
            ("  m26_m27_m28_m59_m91:\n", "  removed_combined_job:\n"),
            ("          label: M91\n", "          label: M90\n"),
            (
                "          topology: tests/interop/m91-rfc7606-malformed.clab.yml\n",
                "          topology: tests/interop/m90-differential.clab.yml\n",
            ),
            (
                "          script: tests/interop/scripts/test-m91-rfc7606-malformed.sh\n",
                "          script: tests/interop/scripts/test-m90-differential.sh\n",
            ),
        ):
            with self.subTest(seam=old):
                self.mutate(relative, old, new)

    def test_m92_differential_job_is_load_bearing(self):
        relative = ".github/workflows/interop.yml"
        with self.assertRaisesRegex(AssertionError, "missing M92 seam"):
            count = (ROOT / relative).read_text().count("missing M92 seam")
            self.assertGreater(count, 0, "missing M92 seam: synthetic")
        for old in (
            "        uses: ./.github/actions/install-grpcurl-artifact\n",
            "      - name: Run M92\n        uses: ./.github/actions/run-interop-test\n",
            "      - name: Run M92 negative completeness proof\n        uses: ./.github/actions/run-interop-test\n",
            '          M92_COMPLETENESS_NEGATIVE: "1"\n',
            "      - name: Build bird:2-bookworm\n        run: docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop\n",
            "      - name: Build gobgp:v4.7.0-m92\n        run: docker build -t gobgp:v4.7.0-m92 -f tests/interop/Dockerfile.gobgp-v47 tests/interop\n",
        ):
            with self.subTest(seam=old):
                count = (ROOT / relative).read_text().count(old)
                self.assertGreater(count, 0, f"missing M92 seam: {old}")
                occurrence = count - 1
                self.mutate(relative, old, occurrence=occurrence)

    def test_dockerfile_exact_source_bridge(self):
        for binary in ("rustbgpd", "rbgp", "evpn-tester", "evpn-monitor"):
            with self.subTest(binary=binary, side="builder"):
                self.mutate(
                    "Dockerfile", f"cp target/ci/{binary} /out/", "true # removed"
                )
            with self.subTest(binary=binary, side="dev"):
                self.mutate(
                    "Dockerfile",
                    f"COPY --from=builder /out/{binary} /usr/local/bin/{binary}",
                    "# removed",
                )

    def test_gobgp_release_archive_contract_is_load_bearing(self):
        relative = "tests/interop/Dockerfile.gobgp"
        cases = (
            ("ENV GOBGP_VERSION=3.37.0", "ENV GOBGP_VERSION=latest"),
            (
                'amd64) checksum="e20b2a155fe14450b9fe37e5c1a1d1bfe101eb479645f5bbea860a8fde30e522" ;;',
                'amd64) checksum="f20b2a155fe14450b9fe37e5c1a1d1bfe101eb479645f5bbea860a8fde30e522" ;;',
            ),
            (
                'arm64) checksum="0aaa2da6e4dcaaf57e3d0e64eae14946292b0a5894d80ef3b7ebde3bf52beb29" ;;',
                'arm64) checksum="1aaa2da6e4dcaaf57e3d0e64eae14946292b0a5894d80ef3b7ebde3bf52beb29" ;;',
            ),
            (
                '*) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;;',
                "*) exit 1 ;;",
            ),
            (
                'https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/${archive}',
                "https://example.invalid/${archive}",
            ),
            (
                'echo "${checksum}  /tmp/${archive}" | sha256sum --check --strict',
                "true # skipped checksum verification",
            ),
            (
                'tar --extract --gzip --file "/tmp/${archive}" --directory /usr/local/bin gobgp gobgpd',
                'tar --extract --gzip --file "/tmp/${archive}" --directory /usr/local/bin',
            ),
            (
                'test "$(gobgp --version)" = "gobgp version ${GOBGP_VERSION}"',
                "true # removed gobgp assertion",
            ),
            (
                'test "$(gobgpd --version)" = "gobgpd version ${GOBGP_VERSION}"',
                "true # removed gobgpd assertion",
            ),
            (
                "FROM debian:bookworm-slim AS gobgp-release",
                "FROM golang:1.23-bookworm AS gobgp-release",
            ),
            (
                "\nFROM debian:bookworm-slim\n",
                "\nFROM debian:trixie-slim\n",
            ),
        )
        for old, new in cases:
            with self.subTest(seam=old):
                self.mutate(relative, old, new)


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
                self.assertTrue(heavy.classify_paths(("docs/RECEIPTS.md", path))[0])
        self.assertTrue(
            heavy.classify_paths(
                ("fuzz/build-fuzzers.sh", "scripts/build-packages.sh")
            )[0]
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
