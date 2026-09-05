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
    INTEROP,
    KERNEL,
    PINS,
    VERSION_TAG,
    _list_needs,
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


class PrimerContractTests(unittest.TestCase):
    def copy_bird_dockerfiles(self, root):
        interop = root / "tests" / "interop"
        interop.mkdir(parents=True, exist_ok=True)
        for name in (
            "Dockerfile.bird3",
            "Dockerfile.bird-v2192",
            "Dockerfile.bird-v332",
        ):
            shutil.copy2(ROOT / "tests" / "interop" / name, interop / name)

    def mutate(self, relative, old, new="", occurrence=0, expect=None):
        errors = self.mutated_errors(relative, old, new, occurrence)
        self.assertTrue(errors, f"mutation stayed green: {relative}: {old}")
        if expect is not None:
            self.assertIn(expect, errors)
        return errors

    def mutated_errors(self, relative, old, new="", occurrence=0):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for fixture in (
                ".github/workflows",
                ".github/actions/install-gnmic-artifact",
                ".github/actions/install-grpcurl-artifact",
                ".github/actions/prepare-gobgp-artifact",
                ".github/actions/prepare-grpcurl-artifact",
                ".github/actions/prime-rustbgpd-dev-cache",
                ".github/actions/setup-dataplane-host",
                ".github/actions/stage-bird3-artifact",
                ".github/actions/stage-gobgp-artifact",
            ):
                source = ROOT / fixture
                target = root / fixture
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(source, target)
            harness = Path("crates/evpn-linux/tests/docker/run-netns-tests.sh")
            (root / harness).parent.mkdir(parents=True)
            shutil.copy2(ROOT / harness, root / harness)
            installer = root / ".github" / "scripts" / "install-grpcurl.sh"
            installer.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / installer.relative_to(root), installer)
            gnmic_installer = root / ".github" / "scripts" / "install-gnmic.sh"
            shutil.copy2(ROOT / gnmic_installer.relative_to(root), gnmic_installer)
            gobgp_installer = root / ".github" / "scripts" / "install-gobgp.sh"
            shutil.copy2(ROOT / gobgp_installer.relative_to(root), gobgp_installer)
            bird3_installer = root / ".github" / "scripts" / "install-bird3.sh"
            shutil.copy2(ROOT / bird3_installer.relative_to(root), bird3_installer)
            shutil.copy2(ROOT / "Dockerfile", root / "Dockerfile")
            gobgp = root / "tests" / "interop" / "Dockerfile.gobgp"
            gobgp.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / "tests" / "interop" / "Dockerfile.gobgp", gobgp)
            self.copy_bird_dockerfiles(root)
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
            return check(root)

    def stage_indexed_fixture(self, root):
        for fixture in (
            ".github/workflows",
            ".github/actions/install-gnmic-artifact",
            ".github/actions/install-grpcurl-artifact",
            ".github/actions/prepare-gobgp-artifact",
            ".github/actions/prepare-grpcurl-artifact",
            ".github/actions/prime-rustbgpd-dev-cache",
            ".github/actions/setup-dataplane-host",
            ".github/actions/stage-bird3-artifact",
            ".github/actions/stage-gobgp-artifact",
        ):
            shutil.copytree(ROOT / fixture, root / fixture)
        harness = Path("crates/evpn-linux/tests/docker/run-netns-tests.sh")
        (root / harness).parent.mkdir(parents=True)
        shutil.copy2(ROOT / harness, root / harness)
        shutil.copy2(ROOT / "Dockerfile", root / "Dockerfile")
        interop = root / "tests" / "interop"
        interop.mkdir(parents=True)
        shutil.copy2(
            ROOT / "tests" / "interop" / "Dockerfile.gobgp", interop / "Dockerfile.gobgp"
        )
        self.copy_bird_dockerfiles(root)
        scripts = root / ".github" / "scripts"
        scripts.mkdir(parents=True)
        for name in (
            "install-grpcurl.sh",
            "install-gnmic.sh",
            "install-gobgp.sh",
            "install-bird3.sh",
        ):
            shutil.copy2(ROOT / ".github" / "scripts" / name, scripts / name)
        subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)

    def test_group_writable_checkout_passes_with_executable_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.stage_indexed_fixture(root)
            for name in (
                "install-grpcurl.sh",
                "install-gnmic.sh",
                "install-gobgp.sh",
                "install-bird3.sh",
            ):
                (root / ".github" / "scripts" / name).chmod(0o775)
            self.assertEqual([], check(root))

    def test_non_executable_index_mode_fails_despite_executable_disk(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.stage_indexed_fixture(root)
            installer = ".github/scripts/install-grpcurl.sh"
            subprocess.run(
                ["git", "-C", str(root), "update-index", "--chmod=-x", installer],
                check=True,
            )
            self.assertTrue(os.access(root / installer, os.X_OK))
            self.assertIn(
                "install-grpcurl.sh must be executable (git index mode 100755)",
                check(root),
            )

    def test_live_contract(self):
        self.assertEqual([], check(ROOT))

    def test_external_action_refs_are_reviewed_version_tags(self):
        for ref in PINS:
            self.assertRegex(ref, VERSION_TAG)
        audit = ".github/workflows/audit.yml"
        ci = ".github/workflows/ci.yml"
        bird3 = ".github/actions/stage-bird3-artifact/action.yml"
        sha = "0123456789abcdef0123456789abcdef01234567"
        cases = (
            (
                audit,
                "actions/checkout@v7",
                "actions/checkout@main",
                f"{audit}: action ref is not a reviewed version tag: actions/checkout@main",
            ),
            (
                audit,
                "actions/checkout@v7",
                f"actions/checkout@{sha}",
                f"{audit}: action ref is not a reviewed version tag: actions/checkout@{sha}",
            ),
            (
                audit,
                "actions/checkout@v7",
                "actions/checkout@v8",
                f"{audit}: action ref is not in the reviewed pin set: actions/checkout@v8",
            ),
            (
                audit,
                "      - uses: actions/checkout@v7\n",
                "      - uses: actions/checkout@v7\n      - uses: actions/setup-python@v5\n",
                f"{audit}: action ref is not in the reviewed pin set: actions/setup-python@v5",
            ),
            (
                ci,
                "dtolnay/rust-toolchain@v1 # stable",
                "dtolnay/rust-toolchain@master # stable",
                f"{ci}: action ref is not a reviewed version tag: dtolnay/rust-toolchain@master",
            ),
            (
                bird3,
                "actions/download-artifact@v8",
                "actions/download-artifact@main",
                f"{bird3}: action ref is not a reviewed version tag: "
                "actions/download-artifact@main",
            ),
        )
        for relative, old, new, expect in cases:
            with self.subTest(relative=relative, ref=new.strip()):
                self.mutate(relative, old, new, expect=expect)

    def test_lab_call_structure_is_load_bearing(self):
        interop = ".github/workflows/interop.yml"
        kernel = ".github/workflows/kernel-dataplane.yml"
        m1_call = (
            "        uses: ./.github/actions/run-interop-test\n"
            "        with:\n"
            "          label: M1\n"
            "          topology: tests/interop/m1-frr.clab.yml\n"
            "          script: tests/interop/scripts/test-m1-frr.sh\n"
        )
        self.assertEqual(1, (ROOT / interop).read_text().count(m1_call))
        for old, new, expect in (
            ("          label: M1\n", "", "interop.yml:m1: run-interop-test call missing label"),
            (
                "          topology: tests/interop/m1-frr.clab.yml\n",
                "",
                "interop.yml:m1: run-interop-test call missing topology",
            ),
            (
                "          script: tests/interop/scripts/test-m1-frr.sh\n",
                "",
                "interop.yml:m1: run-interop-test call missing script",
            ),
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
                self.mutate(interop, m1_call, m1_call.replace(old, new), expect=expect)
        with self.subTest(seam="interop lab gains kernel host setup"):
            self.mutate(
                interop,
                m1_call,
                m1_call + "      - uses: ./.github/actions/setup-dataplane-host\n",
                expect="interop.yml:m1: kernel host setup in interop lab",
            )
        host_setup = "      - uses: ./.github/actions/setup-dataplane-host\n"
        with self.subTest(seam="kernel lab duplicates host setup"):
            self.mutate(
                kernel,
                host_setup,
                host_setup * 2,
                expect="kernel-dataplane.yml:m36: setup call drifted",
            )
        with self.subTest(seam="kernel lab loses its scenario call"):
            errors = self.mutate(
                kernel,
                "        uses: ./.github/actions/run-interop-test\n",
                "        uses: ./.github/actions/install-containerlab\n",
                expect="kernel-dataplane.yml:m36: has no run-interop-test call",
            )
            self.assertEqual(
                ["kernel-dataplane.yml:m36: has no run-interop-test call"],
                [error for error in errors if error.startswith("kernel-dataplane.yml:m36:")],
            )
        with self.subTest(seam="incomplete call reports one cause"):
            errors = self.mutate(
                interop,
                m1_call,
                m1_call.replace("          label: M1\n", ""),
                expect="interop.yml:m1: run-interop-test call missing label",
            )
            self.assertEqual(
                ["interop.yml:m1: run-interop-test call missing label"],
                [error for error in errors if error.startswith("interop.yml:m1:")],
            )
        with self.subTest(seam="descriptive label satisfies the roster"):
            self.assertEqual(
                [],
                self.mutated_errors(
                    kernel, "          label: M36\n", "          label: M36 crash-restart\n"
                ),
            )
        with self.subTest(seam="variant label is the job identifier"):
            self.mutate(
                kernel,
                "          label: M37+IP\n",
                "          label: M37\n",
                expect="kernel-dataplane.yml:m37-ip: no run-interop-test call labelled M37-IP",
            )

    def test_v064_producer_is_load_bearing(self):
        cache_key = (
            "key: rustbgpd-v0.64.0-linux-amd64-"
            "bd4829de08d0c50074f9ecd5c351399fae42be06d456b3880a04aa4a7cda1137"
        )
        cases = (
            ("  v064_validator:\n", "  renamed_validator:\n"),
            ("uses: actions/cache@v6", "uses: actions/cache@main"),
            (cache_key, f"{cache_key}\n          restore-keys: rustbgpd-v0.64"),
            ("--self-test", "--skipped-self-test"),
            ("--prepare-archive", "--skipped-prepare-archive"),
            (
                "uses: actions/upload-artifact@v7",
                "uses: actions/upload-artifact@main",
            ),
            ("if-no-files-found: error", "if-no-files-found: ignore"),
        )
        for old, new in cases:
            with self.subTest(seam=old):
                self.mutate(".github/workflows/ci.yml", old, new)

    def test_v064_core_tests_consumer_is_load_bearing(self):
        cases = (
            ("    needs: v064_validator\n", "    needs: []\n"),
            (
                "uses: actions/download-artifact@v8",
                "uses: actions/download-artifact@main",
            ),
            ("--install-archive", "--prepare-archive"),
        )
        for old, new in cases:
            with self.subTest(seam=old):
                self.mutate(".github/workflows/ci.yml", old, new)

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
                ".github/actions/install-gnmic-artifact",
                ".github/actions/install-grpcurl-artifact",
                ".github/actions/prepare-gobgp-artifact",
                ".github/actions/prepare-grpcurl-artifact",
                ".github/actions/prime-rustbgpd-dev-cache",
                ".github/actions/setup-dataplane-host",
                ".github/actions/stage-bird3-artifact",
                ".github/actions/stage-gobgp-artifact",
            ):
                shutil.copytree(ROOT / fixture, root / fixture)
            shutil.copy2(ROOT / "Dockerfile", root / "Dockerfile")
            gobgp = root / "tests" / "interop" / "Dockerfile.gobgp"
            gobgp.parent.mkdir(parents=True)
            shutil.copy2(ROOT / "tests" / "interop" / "Dockerfile.gobgp", gobgp)
            self.copy_bird_dockerfiles(root)
            gnmic_installer = root / ".github" / "scripts" / "install-gnmic.sh"
            gnmic_installer.parent.mkdir(parents=True)
            shutil.copy2(ROOT / gnmic_installer.relative_to(root), gnmic_installer)
            gobgp_installer = root / ".github" / "scripts" / "install-gobgp.sh"
            shutil.copy2(ROOT / gobgp_installer.relative_to(root), gobgp_installer)
            bird3_installer = root / ".github" / "scripts" / "install-bird3.sh"
            shutil.copy2(ROOT / bird3_installer.relative_to(root), bird3_installer)
            self.assertIn("install-grpcurl.sh is missing", check(root))

    def test_grpcurl_installer_executable_mode_is_load_bearing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for fixture in (
                ".github/workflows",
                ".github/actions/install-gnmic-artifact",
                ".github/actions/install-grpcurl-artifact",
                ".github/actions/prepare-gobgp-artifact",
                ".github/actions/prepare-grpcurl-artifact",
                ".github/actions/prime-rustbgpd-dev-cache",
                ".github/actions/setup-dataplane-host",
                ".github/actions/stage-bird3-artifact",
                ".github/actions/stage-gobgp-artifact",
            ):
                shutil.copytree(ROOT / fixture, root / fixture)
            shutil.copy2(ROOT / "Dockerfile", root / "Dockerfile")
            gobgp = root / "tests" / "interop" / "Dockerfile.gobgp"
            gobgp.parent.mkdir(parents=True)
            shutil.copy2(ROOT / "tests" / "interop" / "Dockerfile.gobgp", gobgp)
            self.copy_bird_dockerfiles(root)
            installer = root / ".github" / "scripts" / "install-grpcurl.sh"
            installer.parent.mkdir(parents=True)
            shutil.copy2(ROOT / installer.relative_to(root), installer)
            gnmic_installer = root / ".github" / "scripts" / "install-gnmic.sh"
            shutil.copy2(ROOT / gnmic_installer.relative_to(root), gnmic_installer)
            gobgp_installer = root / ".github" / "scripts" / "install-gobgp.sh"
            shutil.copy2(ROOT / gobgp_installer.relative_to(root), gobgp_installer)
            bird3_installer = root / ".github" / "scripts" / "install-bird3.sh"
            shutil.copy2(ROOT / bird3_installer.relative_to(root), bird3_installer)
            installer.chmod(0o644)
            self.assertIn(
                "install-grpcurl.sh must be executable (git index mode 100755)",
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
        artifacts = ["grpcurl_archive"]
        if workflow == "interop.yml":
            artifacts.append("gnmic_archive")
        artifacts.append("gobgp_archive")
        if workflow == "interop.yml":
            artifacts.extend(("bird2192_archive", "bird332_archive"))
        else:
            artifacts.append("bird3_archive")
        expected = ["classify_changes", *artifacts, "prime_dev_image", *roster]
        if workflow == "kernel-dataplane.yml":
            expected.append("netns")
        needs = {
            job: {
                "result": results.get(job, "success"),
                "outputs": {"run_labs": run_labs} if job == "classify_changes" else {},
            }
            for job in expected
        }
        if workflow == "kernel-dataplane.yml" and needs["m43"]["result"] == "success":
            # A live m43 republishes its TCP-AO probe verdict; the aggregate
            # requires it whenever the labs ran.
            needs["m43"]["outputs"] = {"tcp_ao_supported": "true"}
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
            artifacts = ["grpcurl_archive"]
            if workflow == "interop.yml":
                artifacts.append("gnmic_archive")
            artifacts.append("gobgp_archive")
            if workflow == "interop.yml":
                artifacts.extend(("bird2192_archive", "bird332_archive"))
            else:
                artifacts.append("bird3_archive")
            skipped = {
                job: "skipped" for job in [*artifacts, "prime_dev_image", *roster]
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
            if workflow == "interop.yml":
                with self.subTest(workflow=workflow, state="gnmic producer red"):
                    self.assertNotEqual(
                        0,
                        self.run_aggregate(
                            workflow,
                            "true",
                            {
                                "gnmic_archive": "failure",
                                "m54": "skipped",
                                "m56": "skipped",
                            },
                        ).returncode,
                    )
            gobgp_consumers = (
                ("m74", "m75", "m81", "m82")
                if workflow == "interop.yml"
                else ("m65", "m71", "m72")
            )
            with self.subTest(workflow=workflow, state="gobgp producer red"):
                gobgp_red = {job: "skipped" for job in gobgp_consumers}
                gobgp_red["gobgp_archive"] = "failure"
                self.assertNotEqual(
                    0,
                    self.run_aggregate(workflow, "true", gobgp_red).returncode,
                )
            if workflow == "kernel-dataplane.yml":
                with self.subTest(workflow=workflow, state="bird3 producer red"):
                    self.assertNotEqual(
                        0,
                        self.run_aggregate(
                            workflow,
                            "true",
                            {"bird3_archive": "failure", "m43": "skipped"},
                        ).returncode,
                    )
            else:
                for producer, consumer in (
                    ("bird2192_archive", "m83"),
                    ("bird332_archive", "m101"),
                ):
                    with self.subTest(workflow=workflow, producer=producer):
                        self.assertNotEqual(
                            0,
                            self.run_aggregate(
                                workflow,
                                "true",
                                {producer: "failure", consumer: "skipped"},
                            ).returncode,
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
                (
                    "name: Prepare exact grpcurl archive",
                    "name: Prepare approximate grpcurl archive",
                    0,
                ),
                ("runs-on: ubuntu-latest", "runs-on: ubuntu-24.04", 1),
                ("timeout-minutes: 10", "timeout-minutes: 9", 0),
                ("ref: ${{ github.sha }}", "ref: main", 0),
                (
                    "uses: ./.github/actions/prepare-grpcurl-artifact",
                    "uses: ./.github/actions/install-grpcurl-artifact",
                    0,
                ),
                (
                    "uses: ./.github/actions/prepare-grpcurl-artifact",
                    "uses: ./.github/actions/prepare-grpcurl-artifact\n"
                    "        with:\n"
                    "          mode: permissive",
                    0,
                ),
                (
                    "uses: ./.github/actions/prepare-grpcurl-artifact",
                    "uses: ./.github/actions/prepare-grpcurl-artifact\n"
                    "      - uses: actions/cache@v6",
                    0,
                ),
            )
            for old, new, occurrence in cases:
                with self.subTest(workflow=workflow, seam=old, occurrence=occurrence):
                    self.mutate(relative, old, new, occurrence=occurrence)

    def test_grpcurl_producer_action_is_load_bearing(self):
        relative = ".github/actions/prepare-grpcurl-artifact/action.yml"
        archive = "grpcurl_1.9.1_linux_x86_64.tar.gz"
        checksum = "588c9c429476d9ed66cd3b2ae32283a6da36e0cfbb7e446f5d6a1b68dc770214"
        cases = (
            ('using: "composite"', 'using: "docker"'),
            ("actions/cache@v6", "actions/cache@main"),
            (f"key: grpcurl-v1.9.1-linux-x86_64-{checksum}", "key: grpcurl"),
            ("shell: bash", "shell: sh"),
            ("--prepare-archive", "--install-archive"),
            ("actions/upload-artifact@v7", "actions/upload-artifact@main"),
            ("name: grpcurl-v1.9.1-linux-x86_64", "name: grpcurl-latest"),
            ("if-no-files-found: error", "if-no-files-found: warn"),
            ("retention-days: 1", "retention-days: 30"),
            ("compression-level: 0", "compression-level: 6"),
            (
                f"key: grpcurl-v1.9.1-linux-x86_64-{checksum}",
                f"key: grpcurl-v1.9.1-linux-x86_64-{checksum}\n"
                "        restore-keys: grpcurl-",
            ),
            (
                "uses: actions/cache@v6",
                "uses: actions/cache@v6\n      continue-on-error: true",
            ),
            (
                "runs:\n",
                "inputs:\n  mode:\n    required: false\nruns:\n",
            ),
            (
                "runs:\n",
                "outputs:\n  archive:\n    value: latest\nruns:\n",
            ),
            (
                ".github/scripts/install-grpcurl.sh \\",
                "curl https://example.invalid/grpcurl\n"
                "        .github/scripts/install-grpcurl.sh \\",
            ),
        )
        for old, new in cases:
            with self.subTest(seam=old):
                self.mutate(relative, old, new)
        for occurrence in (0, 1):
            with self.subTest(path=occurrence):
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

    def test_gnmic_producer_and_offline_consumers_are_load_bearing(self):
        workflow = ".github/workflows/interop.yml"
        for old, new in (
            ("  gnmic_archive:\n", "  removed_gnmic_archive:\n"),
            (
                "key: gnmic-v0.46.0-linux-x86_64-a3ded2f355a615df73900f31b9791f41e796e9c5c63b171e1ce041e8139ee00e",
                "key: gnmic-latest",
            ),
            ("name: gnmic-v0.46.0-linux-x86_64", "name: gnmic-latest"),
            (
                "needs: [grpcurl_archive, gnmic_archive, prime_dev_image]",
                "needs: [grpcurl_archive, prime_dev_image]",
            ),
            (
                "uses: ./.github/actions/install-gnmic-artifact",
                "run: curl https://example.invalid/gnmic | sudo tar -xz",
            ),
        ):
            with self.subTest(seam=old):
                self.mutate(workflow, old, new)
        for seam, replacement in (
            ("actions/cache@v6", "actions/cache@main"),
            ("--prepare-archive", "--install-archive"),
            ("actions/upload-artifact@v7", "actions/upload-artifact@main"),
        ):
            with self.subTest(seam=f"gnmic producer {seam}"):
                self.mutate(workflow, seam, replacement)
        exact_path = (
            "path: ${{ runner.temp }}/gnmic-cache/"
            "gnmic_0.46.0_Linux_x86_64.tar.gz"
        )
        for occurrence in (0, 1):
            with self.subTest(seam="gnmic exact path", occurrence=occurrence):
                self.mutate(
                    workflow,
                    exact_path,
                    "path: ${{ runner.temp }}/gnmic-cache/wrong.tar.gz",
                    occurrence=occurrence,
                )

        action = ".github/actions/install-gnmic-artifact/action.yml"
        for old, new in (
            ("actions/download-artifact@v8", "actions/download-artifact@main"),
            ("name: gnmic-v0.46.0-linux-x86_64", "name: gnmic-latest"),
            ("--install-archive", "--prepare-archive"),
            (
                "set -euo pipefail",
                "set -euo pipefail\n        curl https://example.invalid/gnmic",
            ),
        ):
            with self.subTest(seam=old):
                self.mutate(action, old, new)

        installer = ".github/scripts/install-gnmic.sh"
        for old, new in (
            ('readonly GNMIC_VERSION="0.46.0"', 'readonly GNMIC_VERSION="latest"'),
            (
                "a3ded2f355a615df73900f31b9791f41e796e9c5c63b171e1ce041e8139ee00e",
                "0" * 64,
            ),
            ("curl -fsSL", "curl -sL"),
            ("--connect-timeout 10", "--connect-timeout 0"),
        ):
            with self.subTest(seam=old):
                self.mutate(installer, old, new)

    def test_gobgp_producer_and_stage_consumers_are_load_bearing(self):
        checksum = "e20b2a155fe14450b9fe37e5c1a1d1bfe101eb479645f5bbea860a8fde30e522"
        for workflow in ("interop.yml", "kernel-dataplane.yml"):
            relative = f".github/workflows/{workflow}"
            for old, new in (
                ("  gobgp_archive:\n", "  removed_gobgp_archive:\n"),
                (
                    "uses: ./.github/actions/prepare-gobgp-artifact",
                    "uses: ./.github/actions/stage-gobgp-artifact",
                ),
                (
                    "uses: ./.github/actions/prepare-gobgp-artifact",
                    "uses: ./.github/actions/prepare-gobgp-artifact\n"
                    "        with:\n"
                    "          mode: permissive",
                ),
                (
                    "uses: ./.github/actions/prepare-gobgp-artifact",
                    "uses: ./.github/actions/prepare-gobgp-artifact\n"
                    "      - uses: actions/cache@v6",
                ),
                (
                    "needs: [grpcurl_archive, gobgp_archive, prime_dev_image]",
                    "needs: [grpcurl_archive, prime_dev_image]",
                ),
                (
                    "uses: ./.github/actions/stage-gobgp-artifact",
                    "run: curl https://example.invalid/gobgp -o /tmp/gobgp.tar.gz",
                ),
            ):
                with self.subTest(workflow=workflow, seam=old):
                    self.mutate(relative, old, new)

        producer = ".github/actions/prepare-gobgp-artifact/action.yml"
        verified_archive = (
            '          "$RUNNER_TEMP/gobgp-cache/'
            'gobgp_3.37.0_linux_amd64.tar.gz"\n'
        )
        for old, new in (
            ('using: "composite"', 'using: "docker"'),
            ("actions/cache@v6", "actions/cache@main"),
            (f"key: gobgp-v3.37.0-linux-amd64-{checksum}", "key: gobgp-latest"),
            ("shell: bash", "shell: sh"),
            ("--prepare-archive", "--stage-archive"),
            ("actions/upload-artifact@v7", "actions/upload-artifact@main"),
            ("name: gobgp-v3.37.0-linux-amd64", "name: gobgp-latest"),
            ("if-no-files-found: error", "if-no-files-found: warn"),
            ("retention-days: 1", "retention-days: 30"),
            ("compression-level: 0", "compression-level: 6"),
            (
                f"key: gobgp-v3.37.0-linux-amd64-{checksum}",
                f"key: gobgp-v3.37.0-linux-amd64-{checksum}\n"
                "        restore-keys: gobgp-",
            ),
            (
                "uses: actions/cache@v6",
                "uses: actions/cache@v6\n      continue-on-error: true",
            ),
            (
                "runs:\n",
                "inputs:\n  mode:\n    required: false\nruns:\n",
            ),
            (
                "runs:\n",
                "outputs:\n  archive:\n    value: latest\nruns:\n",
            ),
            (
                ".github/scripts/install-gobgp.sh \\",
                "curl https://example.invalid/gobgp\n"
                "        .github/scripts/install-gobgp.sh \\",
            ),
            (
                verified_archive + "\n    - name: Upload verified gobgp archive",
                verified_archive
                + "\n    - name: Replace verified archive\n"
                + "      shell: bash\n"
                + '      run: cp "$RUNNER_TEMP/unverified.tar.gz" '
                + '"$RUNNER_TEMP/gobgp-cache/"*.tar.gz\n'
                + "\n"
                + "    - name: Upload verified gobgp archive",
            ),
        ):
            with self.subTest(seam=f"gobgp producer action {old}"):
                self.mutate(producer, old, new)
        exact_path = (
            "path: ${{ runner.temp }}/gobgp-cache/"
            "gobgp_3.37.0_linux_amd64.tar.gz"
        )
        for occurrence in (0, 1):
            with self.subTest(seam="gobgp exact path", occurrence=occurrence):
                self.mutate(
                    producer,
                    exact_path,
                    "path: ${{ runner.temp }}/gobgp-cache/wrong.tar.gz",
                    occurrence=occurrence,
                )

        stage_then_build = (
            "      - name: Stage verified GoBGP archive\n"
            "        uses: ./.github/actions/stage-gobgp-artifact\n"
            "\n"
            "      - name: Build gobgp:interop\n"
            "        run: docker build -t gobgp:interop"
            " -f tests/interop/Dockerfile.gobgp tests/interop\n"
        )
        build_then_stage = (
            "      - name: Build gobgp:interop\n"
            "        run: docker build -t gobgp:interop"
            " -f tests/interop/Dockerfile.gobgp tests/interop\n"
            "\n"
            "      - name: Stage verified GoBGP archive\n"
            "        uses: ./.github/actions/stage-gobgp-artifact\n"
        )
        with self.subTest(seam="stage precedes build"):
            self.mutate(
                ".github/workflows/interop.yml", stage_then_build, build_then_stage
            )

        action = ".github/actions/stage-gobgp-artifact/action.yml"
        for old, new in (
            ("actions/download-artifact@v8", "actions/download-artifact@main"),
            ("name: gobgp-v3.37.0-linux-amd64", "name: gobgp-latest"),
            ("--stage-archive", "--prepare-archive"),
            (
                "set -euo pipefail",
                "set -euo pipefail\n        curl https://example.invalid/gobgp",
            ),
        ):
            with self.subTest(seam=old):
                self.mutate(action, old, new)

        installer = ".github/scripts/install-gobgp.sh"
        for old, new in (
            ('readonly GOBGP_VERSION="3.37.0"', 'readonly GOBGP_VERSION="latest"'),
            (checksum, "0" * 64),
            ("curl -fsSL", "curl -sL"),
            ("--connect-timeout 10", "--connect-timeout 0"),
        ):
            with self.subTest(seam=old):
                self.mutate(installer, old, new)

    def test_shared_job_contracts_reject_additive_permissions(self):
        producer = (
            "  gobgp_archive:\n"
            "    needs: classify_changes\n"
            "    if: needs.classify_changes.outputs.run_labs == 'true'\n"
            "    name: Prepare exact gobgp archive\n"
            "    runs-on: ubuntu-latest\n"
            "    timeout-minutes: 10\n"
            "    steps:\n"
        )
        primer = (
            "  prime_dev_image:\n"
            "    needs: classify_changes\n"
            "    if: needs.classify_changes.outputs.run_labs == 'true'\n"
            "    name: Prime rustbgpd:dev build cache\n"
            "    runs-on: ubuntu-latest\n"
            "    timeout-minutes: 30\n"
            "    concurrency:\n"
            "      group: rustbgpd-dev-image-${{ github.sha }}\n"
            "      cancel-in-progress: false\n"
            "    steps:\n"
        )
        for workflow in ("interop.yml", "kernel-dataplane.yml"):
            relative = f".github/workflows/{workflow}"
            for job, envelope in (
                ("gobgp_archive", producer),
                ("prime_dev_image", primer),
            ):
                widened = envelope.replace(
                    "    steps:\n",
                    "    permissions: write-all\n    steps:\n",
                )
                with self.subTest(workflow=workflow, job=job):
                    self.mutate(relative, envelope, widened)

    def test_shared_job_steps_reject_additive_behavior(self):
        gobgp_call = (
            "      - name: Restore, prepare, and upload exact gobgp archive\n"
            "        uses: ./.github/actions/prepare-gobgp-artifact"
        )
        primer_call = (
            "      - name: Prime rustbgpd:dev build cache\n"
            "        uses: ./.github/actions/prime-rustbgpd-dev-cache"
        )
        for workflow in ("interop.yml", "kernel-dataplane.yml"):
            relative = f".github/workflows/{workflow}"
            cases = (
                (
                    "pre-gobgp helper change",
                    gobgp_call,
                    "      - name: Alter GoBGP helper\n"
                    "        run: printf '\\nexit 0\\n' >> "
                    ".github/scripts/install-gobgp.sh\n\n"
                    + gobgp_call,
                ),
                (
                    "pre-primer Dockerfile change",
                    primer_call,
                    "      - name: Alter Dockerfile before priming\n"
                    "        run: printf '\\nRUN true\\n' >> Dockerfile\n\n"
                    + primer_call,
                ),
            )
            for seam, old, new in cases:
                with self.subTest(workflow=workflow, seam=seam):
                    self.mutate(relative, old, new)

            for job, call in (
                ("gobgp_archive", gobgp_call),
                ("primer", primer_call),
            ):
                for field in (
                    "        if: false",
                    "        env:\n          CI_PROOF_MODE: altered",
                    "        with:\n          mode: altered",
                ):
                    with self.subTest(workflow=workflow, job=job, field=field):
                        self.mutate(relative, call, f"{call}\n{field}")

    def test_bird3_producer_and_stage_consumer_are_load_bearing(self):
        checksum = "21297d7a02edd700ae82de5a630055a9cb88a99e2e7e45551bc7d6c1e5b4de2c"
        relative = ".github/workflows/kernel-dataplane.yml"
        for old, new in (
            ("  bird3_archive:\n", "  removed_bird3_archive:\n"),
            (f"key: bird3-v3.3.2-source-{checksum}", "key: bird3-latest"),
            ("name: bird3-v3.3.2-source", "name: bird3-latest"),
            (
                "needs: [grpcurl_archive, bird3_archive, prime_dev_image]",
                "needs: [grpcurl_archive, prime_dev_image]",
            ),
            (
                "uses: ./.github/actions/stage-bird3-artifact",
                "run: curl https://example.invalid/bird3 -o /tmp/bird.tar.gz",
            ),
            ("cache-from: type=gha,scope=bird3-tcpao", "cache-from: type=gha"),
            (
                "cache-to: type=gha,mode=max,scope=bird3-tcpao,ignore-error=true",
                "cache-to: type=gha",
            ),
        ):
            with self.subTest(seam=old):
                self.mutate(relative, old, new)
        for seam, replacement in (
            ("actions/cache@v6", "actions/cache@main"),
            ("--prepare-archive", "--stage-archive"),
            ("actions/upload-artifact@v7", "actions/upload-artifact@main"),
        ):
            with self.subTest(seam=f"bird3 producer {seam}"):
                self.mutate(relative, seam, replacement)
        exact_path = (
            "path: ${{ runner.temp }}/bird3-cache/bird-3.3.2.tar.gz"
        )
        for occurrence in (0, 1):
            with self.subTest(seam="bird3 exact path", occurrence=occurrence):
                self.mutate(
                    relative,
                    exact_path,
                    "path: ${{ runner.temp }}/bird3-cache/wrong.tar.gz",
                    occurrence=occurrence,
                )

        stage_step = (
            "      - name: Stage verified BIRD 3 archive\n"
            "        if: steps.tcp_ao.outputs.supported == 'true'\n"
            "        uses: ./.github/actions/stage-bird3-artifact\n"
        )
        build_step = (
            "      - name: Build BIRD 3.3.2 TCP-AO image\n"
            "        if: steps.tcp_ao.outputs.supported == 'true'\n"
            "        uses: docker/build-push-action@v7\n"
            "        with:\n"
            "          context: tests/interop\n"
            "          file: tests/interop/Dockerfile.bird3\n"
            "          load: true\n"
            "          tags: bird:3.3.2-tcpao\n"
            "          cache-from: type=gha,scope=bird3-tcpao\n"
            "          cache-to: type=gha,mode=max,scope=bird3-tcpao,ignore-error=true\n"
        )
        with self.subTest(seam="stage precedes build"):
            self.mutate(
                relative,
                f"{stage_step}\n{build_step}",
                f"{build_step}\n{stage_step}",
            )

        action = ".github/actions/stage-bird3-artifact/action.yml"
        for old, new in (
            ("actions/download-artifact@v8", "actions/download-artifact@main"),
            ('default: "bird3-v3.3.2-source"', 'default: "bird3-latest"'),
            ("--stage-archive", "--prepare-archive"),
            (
                "set -euo pipefail",
                "set -euo pipefail\n        curl https://example.invalid/bird3",
            ),
        ):
            with self.subTest(seam=old):
                self.mutate(action, old, new)

        installer = ".github/scripts/install-bird3.sh"
        for old, new in (
            ('BIRD3_VERSION="3.3.2"', 'BIRD3_VERSION="latest"'),
            (checksum, "0" * 64),
            ("curl -fsSL", "curl -sL"),
            ("--connect-timeout 10", "--connect-timeout 0"),
        ):
            with self.subTest(seam=old):
                self.mutate(installer, old, new)

    def test_required_interop_bird_producers_are_load_bearing(self):
        relative = ".github/workflows/interop.yml"
        specs = (
            (
                "bird2192_archive",
                "2.19.2",
                "aff89abba3b92b7637bd57e0168b8d7ae887747f160ada4973378ad72f5f3660",
                "bird2192-cache",
                "bird2192-v2.19.2-source",
            ),
            (
                "bird332_archive",
                "3.3.2",
                "21297d7a02edd700ae82de5a630055a9cb88a99e2e7e45551bc7d6c1e5b4de2c",
                "bird332-cache",
                "bird332-v3.3.2-source",
            ),
        )
        for job, version, checksum, cache_dir, artifact in specs:
            archive = f"bird-{version}.tar.gz"
            cache_key = f"{artifact}-{checksum}"
            for old, new in (
                (f"  {job}:\n", f"  removed_{job}:\n"),
                (f"key: {cache_key}", "key: bird-latest"),
                (f"--version {version}", "--version latest"),
                (f"--sha256 {checksum}", "--sha256 " + "0" * 64),
                (f"name: {artifact}", "name: bird-latest"),
            ):
                with self.subTest(job=job, seam=old):
                    self.mutate(relative, old, new)
            upload_tail = (
                f"          name: {artifact}\n"
                f"          path: ${{{{ runner.temp }}}}/{cache_dir}/{archive}\n"
                "          if-no-files-found: error\n"
                "          retention-days: 1\n"
                "          compression-level: 0\n"
            )
            with self.subTest(job=job, seam="compression zero"):
                self.mutate(
                    relative,
                    upload_tail,
                    upload_tail.replace("compression-level: 0", "compression-level: 9"),
                )
            exact_path = (
                f"path: ${{{{ runner.temp }}}}/{cache_dir}/{archive}"
            )
            for occurrence in (0, 1):
                with self.subTest(job=job, seam="exact path", occurrence=occurrence):
                    self.mutate(
                        relative,
                        exact_path,
                        f"path: ${{{{ runner.temp }}}}/{cache_dir}/wrong.tar.gz",
                        occurrence=occurrence,
                    )
            with self.subTest(job=job, seam="no restore keys"):
                self.mutate(
                    relative,
                    f"          key: {cache_key}\n",
                    f"          key: {cache_key}\n          restore-keys: bird-\n",
                )

    def test_parameterized_bird_stage_action_is_load_bearing(self):
        relative = ".github/actions/stage-bird3-artifact/action.yml"
        for old, new in (
            ("name: ${{ inputs.artifact-name }}", "name: bird3-v3.3.2-source"),
            ('--version "${{ inputs.version }}"', "--version 3.3.2"),
            ('--sha256 "${{ inputs.sha256 }}"', "--sha256 " + "0" * 64),
            (
                '"$RUNNER_TEMP/bird3-artifact/bird-${{ inputs.version }}.tar.gz"',
                '"$RUNNER_TEMP/bird3-artifact/bird-3.3.2.tar.gz"',
            ),
            ('"${{ inputs.stage-directory }}"', "tests/interop/bird3-archive"),
        ):
            with self.subTest(seam=old):
                self.mutate(relative, old, new)

    def test_m83_m101_bird_archive_dockerfiles_are_load_bearing(self):
        specs = (
            (
                "tests/interop/Dockerfile.bird-v2192",
                "2.19.2",
                "aff89abba3b92b7637bd57e0168b8d7ae887747f160ada4973378ad72f5f3660",
            ),
            (
                "tests/interop/Dockerfile.bird-v332",
                "3.3.2",
                "21297d7a02edd700ae82de5a630055a9cb88a99e2e7e45551bc7d6c1e5b4de2c",
            ),
        )
        for relative, version, checksum in specs:
            for old, new in (
                (f"ARG BIRD_VERSION={version}", "ARG BIRD_VERSION=latest"),
                (f"ARG BIRD_SHA256={checksum}", "ARG BIRD_SHA256=" + "0" * 64),
                (
                    "COPY bird3-archive/ /tmp/bird-archive/",
                    "RUN mkdir -p /tmp/bird-archive",
                ),
                ('if [ ! -f "${target}" ]; then', "if true; then"),
                (
                    'if [ "${attempt}" -ge 3 ]; then',
                    'if [ "${attempt}" -ge 999 ]; then',
                ),
                (
                    'echo "${BIRD_SHA256}  ${target}" | sha256sum --check --strict',
                    "true # checksum skipped",
                ),
                (
                    'tar -xzf "${target}" -C /tmp/bird --strip-components=1',
                    'tar -xzf "${target}" -C /tmp/bird',
                ),
            ):
                with self.subTest(dockerfile=relative, seam=old):
                    self.mutate(relative, old, new)

    def test_gnmic_installer_executable_mode_is_load_bearing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for fixture in (
                ".github/workflows",
                ".github/actions/install-gnmic-artifact",
                ".github/actions/install-grpcurl-artifact",
                ".github/actions/prepare-gobgp-artifact",
                ".github/actions/prepare-grpcurl-artifact",
                ".github/actions/prime-rustbgpd-dev-cache",
                ".github/actions/setup-dataplane-host",
                ".github/actions/stage-bird3-artifact",
                ".github/actions/stage-gobgp-artifact",
            ):
                shutil.copytree(ROOT / fixture, root / fixture)
            shutil.copy2(ROOT / "Dockerfile", root / "Dockerfile")
            gobgp = root / "tests" / "interop" / "Dockerfile.gobgp"
            gobgp.parent.mkdir(parents=True)
            shutil.copy2(ROOT / "tests" / "interop" / "Dockerfile.gobgp", gobgp)
            self.copy_bird_dockerfiles(root)
            scripts = root / ".github" / "scripts"
            scripts.mkdir(parents=True)
            for name in (
                "install-grpcurl.sh",
                "install-gnmic.sh",
                "install-gobgp.sh",
                "install-bird3.sh",
            ):
                shutil.copy2(ROOT / ".github" / "scripts" / name, scripts / name)
            (scripts / "install-gnmic.sh").chmod(0o644)
            self.assertIn(
                "install-gnmic.sh must be executable (git index mode 100755)",
                check(root),
            )

    def test_gobgp_installer_executable_mode_is_load_bearing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for fixture in (
                ".github/workflows",
                ".github/actions/install-gnmic-artifact",
                ".github/actions/install-grpcurl-artifact",
                ".github/actions/prepare-gobgp-artifact",
                ".github/actions/prepare-grpcurl-artifact",
                ".github/actions/prime-rustbgpd-dev-cache",
                ".github/actions/setup-dataplane-host",
                ".github/actions/stage-bird3-artifact",
                ".github/actions/stage-gobgp-artifact",
            ):
                shutil.copytree(ROOT / fixture, root / fixture)
            shutil.copy2(ROOT / "Dockerfile", root / "Dockerfile")
            gobgp = root / "tests" / "interop" / "Dockerfile.gobgp"
            gobgp.parent.mkdir(parents=True)
            shutil.copy2(ROOT / "tests" / "interop" / "Dockerfile.gobgp", gobgp)
            self.copy_bird_dockerfiles(root)
            scripts = root / ".github" / "scripts"
            scripts.mkdir(parents=True)
            for name in (
                "install-grpcurl.sh",
                "install-gnmic.sh",
                "install-gobgp.sh",
                "install-bird3.sh",
            ):
                shutil.copy2(ROOT / ".github" / "scripts" / name, scripts / name)
            (scripts / "install-gobgp.sh").chmod(0o644)
            self.assertIn(
                "install-gobgp.sh must be executable (git index mode 100755)",
                check(root),
            )

    def test_bird3_installer_executable_mode_is_load_bearing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for fixture in (
                ".github/workflows",
                ".github/actions/install-gnmic-artifact",
                ".github/actions/install-grpcurl-artifact",
                ".github/actions/prepare-gobgp-artifact",
                ".github/actions/prepare-grpcurl-artifact",
                ".github/actions/prime-rustbgpd-dev-cache",
                ".github/actions/setup-dataplane-host",
                ".github/actions/stage-bird3-artifact",
                ".github/actions/stage-gobgp-artifact",
            ):
                shutil.copytree(ROOT / fixture, root / fixture)
            shutil.copy2(ROOT / "Dockerfile", root / "Dockerfile")
            gobgp = root / "tests" / "interop" / "Dockerfile.gobgp"
            gobgp.parent.mkdir(parents=True)
            shutil.copy2(ROOT / "tests" / "interop" / "Dockerfile.gobgp", gobgp)
            self.copy_bird_dockerfiles(root)
            scripts = root / ".github" / "scripts"
            scripts.mkdir(parents=True)
            for name in (
                "install-grpcurl.sh",
                "install-gnmic.sh",
                "install-gobgp.sh",
                "install-bird3.sh",
            ):
                shutil.copy2(ROOT / ".github" / "scripts" / name, scripts / name)
            (scripts / "install-bird3.sh").chmod(0o644)
            self.assertIn(
                "install-bird3.sh must be executable (git index mode 100755)",
                check(root),
            )

    def test_heavy_workflow_aggregate_source_is_load_bearing(self):
        for workflow, lab in (
            ("interop.yml", "m1"),
            ("kernel-dataplane.yml", "m36"),
        ):
            relative = f".github/workflows/{workflow}"
            needs_prefix = (
                "needs: [classify_changes, grpcurl_archive, "
                + ("gnmic_archive, " if workflow == "interop.yml" else "")
                + "gobgp_archive, "
                + (
                    "bird2192_archive,\n      bird332_archive, "
                    if workflow == "interop.yml"
                    else ""
                )
                + ("bird3_archive, " if workflow == "kernel-dataplane.yml" else "")
                + "prime_dev_image, "
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

    def test_kernel_netns_selector_contract_is_load_bearing(self):
        workflow = ".github/workflows/kernel-dataplane.yml"
        harness = "crates/evpn-linux/tests/docker/run-netns-tests.sh"
        cases = (
            (harness, "    -e EVPN_LINUX_NETNS=1", "    -e RUST_BACKTRACE=1"),
            (harness, "    -e EVPN_LINUX_NETNS=1", ")\n-e EVPN_LINUX_NETNS=1\nDOCKER_ARGS+=("),
            (harness, "    -e EVPN_LINUX_NETNS=1\n    -e RUST_BACKTRACE=1", "    -e EVPN_LINUX_NETNS=1\n    -e EVPN_LINUX_NETNS=0\n    -e RUST_BACKTRACE=1"),
            (workflow, "run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh link_carrier", "run: true"),
            (workflow, "        run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh link_carrier", "        # run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh link_carrier"),
            (harness, 'ac_gate)            TEST_BIN="netns_ac_gate"', 'ac_gate)            TEST_BIN="netns_link_carrier"'),
            (harness, 'ac_gate)            TEST_BIN="netns_ac_gate"; FILTER=""', 'ac_gate)            TEST_BIN="netns_ac_gate"; FILTER=""; TEST_BIN="netns_link_carrier"'),
            (harness, 'ac_gate)            TEST_BIN="netns_ac_gate"; FILTER=""', 'ac_gate)            false; TEST_BIN="netns_ac_gate"; FILTER=""'),
            (harness, 'nexthop_raw)        TEST_BIN="netns_nexthop_raw"', 'nexthop_raw)        TEST_BIN="netns_ac_gate"'),
            (harness, "l2_foreign_takeover_row_survives_withdrawal_and_shutdown", "wrong_l2_filter"),
            (workflow, "run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh foreign_state_nhid", "run: true"),
            (harness, "linux_dataplane_programs_remote_mac_with_extern_learn", "wrong_remote_mac_filter"),
            (workflow, "run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh dataplane_remote_mac", "run: true"),
            (harness, "linux_dataplane_attributes_vlan_local_mac_observations", "wrong_vlan_attribution_filter"),
            (workflow, "run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh vlan_local_mac_attribution", "run: true"),
            (workflow, "        if: steps.vrf.outputs.vrf-available == 'true'\n        run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh foreign_state_l3", "        run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh foreign_state_l3"),
            (workflow, "        if: steps.vrf.outputs.vrf-available == 'true'\n        run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh foreign_state_l3", "        # if: steps.vrf.outputs.vrf-available == 'true'\n        run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh foreign_state_l3"),
            (harness, "linux_dataplane_route_event_wakes_within_2s", "wrong_route_event_filter"),
            (harness, "linux_dataplane_installs_and_withdraws_l3_triple", "wrong_l3_cycle_filter"),
            (workflow, "        if: steps.vrf.outputs.vrf-available == 'true'\n        run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh l3_single_path_cycle", "        run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh l3_single_path_cycle"),
            (harness, "linux_dataplane_foreign_route_survives_l3_cycle", "wrong_foreign_route_filter"),
            (workflow, "        if: steps.vrf.outputs.vrf-available == 'true'\n        run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh l3_foreign_route_cycle", "        run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh l3_foreign_route_cycle"),
        )
        for relative, old, new in cases:
            with self.subTest(seam=old):
                self.mutate(relative, old, new)
        with tempfile.TemporaryDirectory() as temporary:
            self.stage_indexed_fixture(root := Path(temporary))
            (root / harness).unlink()
            workflow_path = root / workflow
            workflow_path.write_text(workflow_path.read_text().replace("        run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh link_carrier", "        run: true"))
            self.assertEqual(
                [
                    "netns harness is missing",
                    "kernel-dataplane.yml:netns must invoke link_carrier once",
                    "netns harness must append the successful selector receipt",
                ],
                check(root),
            )

    def test_kernel_netns_receipt_contract_is_load_bearing(self):
        workflow = ".github/workflows/kernel-dataplane.yml"
        harness = "crates/evpn-linux/tests/docker/run-netns-tests.sh"
        cases = (
            (workflow, "name: netns-selector-receipt", "name: incomplete-receipt"),
            (workflow, 'cat "$RUNNER_TEMP/netns-selector-summary.md" >> "$GITHUB_STEP_SUMMARY"', "true"),
            (workflow, "--vrf-available \"${VRF_AVAILABLE:-false}\"", "--vrf-available true"),
            (harness, "printf '%s\\n' \"$SELECTOR\" >> \"$NETNS_SELECTOR_RECEIPT\"", "true"),
        )
        for relative, old, new in cases:
            with self.subTest(seam=old):
                self.mutate(relative, old, new)

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
                "uses: ./.github/actions/prime-rustbgpd-dev-cache",
                "uses: docker/build-push-action@v7",
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
                (
                    "uses: ./.github/actions/prime-rustbgpd-dev-cache",
                    "uses: docker/build-push-action@v7",
                ),
                (
                    "uses: ./.github/actions/prime-rustbgpd-dev-cache",
                    "uses: ./.github/actions/prime-rustbgpd-dev-cache\n"
                    "      - uses: docker/build-push-action@v7",
                ),
                (
                    "actions/checkout@v7",
                    "actions/checkout@main",
                ),
            ):
                with self.subTest(workflow=workflow, seam=old):
                    self.mutate(relative, old, new)

        primer_action = ".github/actions/prime-rustbgpd-dev-cache/action.yml"
        for old, new in (
            ('using: "composite"', 'using: "docker"'),
            ("load: false", "load: true"),
            ("load: false", "load: false\n        no-cache: true"),
            ("context: .", "context: elsewhere"),
            ("tags: rustbgpd:dev", "tags: other:dev"),
            ("target: dev", "target: release"),
            ("cache-from: type=gha,scope=rustbgpd-dev", "cache-from: type=gha"),
            (
                "cache-to: type=gha,scope=rustbgpd-dev,mode=max,ignore-error=true",
                "cache-to: type=gha",
            ),
            (
                "docker/setup-buildx-action@v4",
                "docker/setup-buildx-action@main",
            ),
            (
                "docker/build-push-action@v7",
                "docker/build-push-action@main",
            ),
            (
                "uses: docker/build-push-action@v7",
                "uses: docker/build-push-action@v7\n      continue-on-error: true",
            ),
            (
                "runs:\n",
                "inputs:\n  mode:\n    required: false\nruns:\n",
            ),
            (
                "runs:\n",
                "outputs:\n  image:\n    value: latest\nruns:\n",
            ),
        ):
            with self.subTest(action=primer_action, seam=old):
                self.mutate(primer_action, old, new)

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

    def test_m85_bird2192_job_is_load_bearing(self):
        relative = ".github/workflows/interop.yml"
        workflow = (ROOT / relative).read_text()
        job_start = workflow.index("  m85:\n")

        m85_needs = (
            "  m85:\n"
            "    needs: [grpcurl_archive, bird2192_archive, prime_dev_image]\n"
        )
        self.assertEqual(1, workflow.count(m85_needs), "M85 needs seam must be unique")
        self.mutate(
            relative,
            m85_needs,
            "  m85:\n    needs: [grpcurl_archive, prime_dev_image]\n",
        )

        for old in (
            "      - name: Stage verified BIRD 2.19.2 archive\n",
            '          version: "2.19.2"\n',
            "          sha256: aff89abba3b92b7637bd57e0168b8d7ae887747f160ada4973378ad72f5f3660\n",
            "          artifact-name: bird2192-v2.19.2-source\n",
            "      - name: Build bird:v2.19.2-m85\n",
            "          file: tests/interop/Dockerfile.bird-v2192\n",
            "          tags: bird:v2.19.2-m85\n",
            "          cache-from: type=gha,scope=bird2192-m85\n",
            "          cache-to: type=gha,mode=max,scope=bird2192-m85,ignore-error=true\n",
            "          label: M85\n",
            "          topology: tests/interop/m85-rr-bird.clab.yml\n",
            "          script: tests/interop/scripts/test-m85-rr-bird.sh\n",
            "          label: M93\n",
            "          topology: tests/interop/m93-required-families-bird.clab.yml\n",
            "          script: tests/interop/scripts/test-m93-required-families-bird.sh\n",
            "          label: M95\n",
            "          topology: tests/interop/m95-rfc8212-presence-frr-bird.clab.yml\n",
            "          script: tests/interop/scripts/test-m95-rfc8212-presence.sh\n",
        ):
            with self.subTest(seam=old):
                occurrence = workflow[:job_start].count(old)
                self.assertGreater(
                    workflow[job_start:].count(old), 0, f"missing M85 seam: {old}"
                )
                self.mutate(relative, old, occurrence=occurrence)

        job_name = (
            "    name: M85/M93/M95 — RR core, required families, and RFC 8212 "
            "presence transitions against BIRD 2.19.2\n"
        )
        self.mutate(relative, job_name, job_name + "      # bird:2-bookworm\n")

    def test_m83_exact_incumbent_images_are_load_bearing(self):
        relative = ".github/workflows/interop.yml"
        m83_needs = (
            "  m83:\n"
            "    needs: [grpcurl_archive, bird2192_archive, prime_dev_image]\n"
        )
        workflow = (ROOT / relative).read_text()
        self.assertEqual(1, workflow.count(m83_needs), "M83 needs seam must be unique")
        self.mutate(
            relative,
            m83_needs,
            "  m83:\n    needs: [grpcurl_archive, prime_dev_image]\n",
        )

        for old in (
            "      - name: Stage verified BIRD 2.19.2 archive\n",
            '          version: "2.19.2"\n',
            "          sha256: aff89abba3b92b7637bd57e0168b8d7ae887747f160ada4973378ad72f5f3660\n",
            "          artifact-name: bird2192-v2.19.2-source\n",
            "          file: tests/interop/Dockerfile.bird-v2192\n",
            "          tags: bird:v2.19.2-m83\n",
            "          cache-from: type=gha,scope=bird2192-m83\n",
            "          cache-to: type=gha,mode=max,scope=bird2192-m83,ignore-error=true\n",
            "          --build-arg GOBGP_VERSION=4.8.0\n",
            "          --build-arg GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03\n",
            "          -t gobgp:v4.8.0-m83 -f tests/interop/Dockerfile.gobgp-v47 tests/interop\n",
            "    name: M83 — route-server profile, multi-stack (BIRD 2.19.2 + GoBGP 4.8.0 + FRR 10.7.0 + RTR)\n",
            "      - name: Pull digest-pinned FRR 10.7.0 image\n",
            "        run: docker pull quay.io/frrouting/frr@sha256:a0ed0e4f8727631c8303dd9a4e8199b47464a17a5253135a2c622286aeaec46b\n",
        ):
            with self.subTest(seam=old):
                count = (ROOT / relative).read_text().count(old)
                self.assertGreater(count, 0, f"missing M83 seam: {old}")
                self.mutate(relative, old)

    def test_m76_gobgp48_job_is_load_bearing(self):
        relative = ".github/workflows/interop.yml"
        workflow = (ROOT / relative).read_text()
        m76_header = (
            "  m76:\n"
            "    needs: [grpcurl_archive, prime_dev_image]\n"
            "    name: M76 — ORR divergent-best (GoBGP 4.8.0)\n"
        )
        self.assertEqual(1, workflow.count(m76_header), "M76 header must be unique")
        self.mutate(relative, m76_header, m76_header.replace("4.8.0", "4.6.0"))

        build = (
            "      - name: Build gobgp:v4.8.0-m76\n"
            "        run: |\n"
            "          docker build --build-arg TARGETARCH=amd64 \\\n"
            "          --build-arg GOBGP_VERSION=4.8.0 \\\n"
            "          --build-arg GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03 \\\n"
            "          -t gobgp:v4.8.0-m76 -f tests/interop/Dockerfile.gobgp-v47 tests/interop\n"
        )
        self.assertEqual(1, workflow.count(build), "M76 GoBGP build must be unique")
        for old, new in (
            ("TARGETARCH=amd64", "TARGETARCH=arm64"),
            ("GOBGP_VERSION=4.8.0", "GOBGP_VERSION=4.7.0"),
            (
                "GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03",
                "GOBGP_SHA256=wrong",
            ),
            ("gobgp:v4.8.0-m76", "gobgp:bgpls"),
            ("Dockerfile.gobgp-v47", "Dockerfile.gobgp-bgpls"),
        ):
            with self.subTest(seam=old):
                self.mutate(relative, build, build.replace(old, new))

        run = (
            "      - name: Run M76 (deploy + test + destroy with retry)\n"
            "        uses: ./.github/actions/run-interop-test\n"
            "        with:\n"
            "          label: M76\n"
            "          topology: tests/interop/m76-orr-divergent-best-gobgp.clab.yml\n"
            "          script: tests/interop/scripts/test-m76-orr-divergent-best-gobgp.sh\n"
        )
        self.assertEqual(1, workflow.count(run), "M76 run block must be unique")
        for old, new in (
            ("label: M76", "label: M75"),
            ("m76-orr-divergent-best-gobgp.clab.yml", "m75-rtc-vpnv4-filter-gobgp.clab.yml"),
            ("test-m76-orr-divergent-best-gobgp.sh", "test-m75-rtc-vpnv4-filter-gobgp.sh"),
        ):
            with self.subTest(seam=old):
                self.mutate(relative, run, run.replace(old, new))

    def test_m77_gobgp48_job_is_load_bearing(self):
        relative = ".github/workflows/interop.yml"
        workflow = (ROOT / relative).read_text()
        m77_header = (
            "  m77:\n"
            "    needs: [grpcurl_archive, prime_dev_image]\n"
            "    name: M77 — VPNv4/VPNv6/RTC GR+LLGR + BGP-LS GR (GoBGP 4.8.0)\n"
        )
        self.assertEqual(1, workflow.count(m77_header), "M77 header must be unique")
        self.mutate(relative, m77_header, m77_header.replace("4.8.0", "4.6.0"))

        build = (
            "      - name: Build gobgp:v4.8.0-m77\n"
            "        run: |\n"
            "          docker build --build-arg TARGETARCH=amd64 \\\n"
            "          --build-arg GOBGP_VERSION=4.8.0 \\\n"
            "          --build-arg GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03 \\\n"
            "          -t gobgp:v4.8.0-m77 -f tests/interop/Dockerfile.gobgp-v47 tests/interop\n"
        )
        self.assertEqual(1, workflow.count(build), "M77 GoBGP build must be unique")
        for old, new in (
            ("TARGETARCH=amd64", "TARGETARCH=arm64"),
            ("GOBGP_VERSION=4.8.0", "GOBGP_VERSION=4.7.0"),
            (
                "GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03",
                "GOBGP_SHA256=wrong",
            ),
            ("gobgp:v4.8.0-m77", "gobgp:bgpls"),
            ("Dockerfile.gobgp-v47", "Dockerfile.gobgp-bgpls"),
        ):
            with self.subTest(seam=old):
                self.mutate(relative, build, build.replace(old, new))

        run = (
            "      - name: Run M77 (deploy + test + destroy with retry)\n"
            "        uses: ./.github/actions/run-interop-test\n"
            "        with:\n"
            "          label: M77\n"
            "          topology: tests/interop/m77-gr-llgr-rr-gobgp.clab.yml\n"
            "          script: tests/interop/scripts/test-m77-gr-llgr-rr-gobgp.sh\n"
        )
        self.assertEqual(1, workflow.count(run), "M77 run block must be unique")
        for old, new in (
            ("label: M77", "label: M76"),
            ("m77-gr-llgr-rr-gobgp.clab.yml", "m76-orr-divergent-best-gobgp.clab.yml"),
            ("test-m77-gr-llgr-rr-gobgp.sh", "test-m76-orr-divergent-best-gobgp.sh"),
        ):
            with self.subTest(seam=old):
                self.mutate(relative, run, run.replace(old, new))

    def test_m99_rfc9072_raw_capture_job_is_load_bearing(self):
        relative = ".github/workflows/interop.yml"
        for old in (
            "  m99:\n",
            "      - name: Ensure host raw-capture tools\n",
            "          if ! command -v tshark >/dev/null || ! command -v nsenter >/dev/null \\\n",
            "            || ! command -v jq >/dev/null; then\n",
            "            sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y tshark util-linux jq\n",
            "          tshark --version\n",
            "          nsenter --version\n",
            "          label: M99\n",
            "          topology: tests/interop/m99-rfc9072-extended-open-frr.clab.yml\n",
            "          script: tests/interop/scripts/test-m99-rfc9072-extended-open.sh\n",
            '          max_attempts: "1"\n',
        ):
            with self.subTest(seam=old):
                self.mutate(relative, old)

    def test_m100_partial_flag_receiver_job_is_load_bearing(self):
        relative = ".github/workflows/interop.yml"
        unique_blocks = (
            (
                "  m100:\n"
                "    needs: [grpcurl_archive, bird2192_archive]\n",
                "  m100:\n    needs: [grpcurl_archive]\n",
            ),
            (
                "      - name: Build bird:v2.19.2-m100\n"
                "        uses: docker/build-push-action@v7\n"
                "        with:\n"
                "          context: tests/interop\n"
                "          file: tests/interop/Dockerfile.bird-v2192\n"
                "          load: true\n"
                "          tags: bird:v2.19.2-m100\n"
                "          cache-from: type=gha,scope=bird2192-m100\n"
                "          cache-to: type=gha,mode=max,scope=bird2192-m100,ignore-error=true\n",
                "",
            ),
            (
                "      - name: Build bmpsink:m100 fixture image\n"
                "        run: docker build -t bmpsink:m100 -f tests/interop/Dockerfile.bmpsink tests/interop\n",
                "",
            ),
            (
                "      - name: Pull exact receiver images\n"
                "        run: |\n"
                "          docker pull ghcr.io/lance0/rustbgpd@sha256:cc6207fe950ee15f6793ca0119d531067c7b358b6c6193b0fda929495714c9da\n"
                "          docker pull openbgpd/openbgpd@sha256:b2e94bd1538102a89cff96867993eabb6dbb27720de4ab7b588860880e3e3bf9\n"
                "          docker pull quay.io/frrouting/frr@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c\n",
                "",
            ),
            (
                "      - name: Run M100 offline diagnostic contract\n"
                "        run: python3 tests/interop/scripts/m100_partial_raw_peer.py --self-test\n",
                "",
            ),
            (
                "      - name: Run M100 (single-attempt 20-cell receiver differential)\n"
                "        env:\n"
                '          CLEANUP: "1"\n'
                "          M100_ARTIFACT_DIR: ${{ runner.temp }}/m100\n"
                "        uses: ./.github/actions/run-interop-test\n"
                "        with:\n"
                "          label: M100\n"
                "          topology: tests/interop/m100-partial-receiver.clab.yml\n"
                "          script: tests/interop/scripts/test-m100-partial-receiver.sh\n"
                '          max_attempts: "1"\n',
                "",
            ),
            (
                "      - name: Upload M100 successful-run evidence\n"
                "        uses: actions/upload-artifact@v7\n"
                "        with:\n"
                "          name: m100-partial-receiver-${{ github.sha }}\n"
                "          path: ${{ runner.temp }}/m100\n"
                "          if-no-files-found: error\n"
                "          retention-days: 14\n",
                "",
            ),
        )
        for old, new in unique_blocks:
            with self.subTest(seam=old.splitlines()[0]):
                self.assertEqual(1, (ROOT / relative).read_text().count(old))
                self.mutate(relative, old, new)

        stage = (
            "      - name: Stage verified BIRD 2.19.2 archive\n"
            "        uses: ./.github/actions/stage-bird3-artifact\n"
            "        with:\n"
            '          version: "2.19.2"\n'
            "          sha256: aff89abba3b92b7637bd57e0168b8d7ae887747f160ada4973378ad72f5f3660\n"
            "          artifact-name: bird2192-v2.19.2-source\n"
        )
        self.assertEqual(4, (ROOT / relative).read_text().count(stage))
        self.mutate(relative, stage, occurrence=2)

        job_name = "    name: M100 — released-daemon Partial-flag receiver differential\n"
        self.mutate(
            relative,
            job_name,
            job_name + "    # rustbgpd:dev must not enter this released-image lane\n",
        )

    def test_m101_bird332_real_wire_job_is_load_bearing(self):
        relative = ".github/workflows/interop.yml"
        for old in (
            "  m101:\n",
            "    needs: [grpcurl_archive, bird332_archive, prime_dev_image]\n",
            "      - name: Stage verified BIRD 3.3.2 archive\n",
            '          version: "3.3.2"\n',
            "          sha256: 21297d7a02edd700ae82de5a630055a9cb88a99e2e7e45551bc7d6c1e5b4de2c\n",
            "          artifact-name: bird332-v3.3.2-source\n",
            "      - name: Build checksum-pinned BIRD 3.3.2 image\n",
            "          file: tests/interop/Dockerfile.bird-v332\n",
            "          tags: bird:v3.3.2-m101\n",
            "          cache-from: type=gha,scope=bird332-m101\n",
            "          cache-to: type=gha,mode=max,scope=bird332-m101,ignore-error=true\n",
            "      - name: Pull digest-pinned FRR 10.3.1 image\n",
            "        run: docker pull quay.io/frrouting/frr@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c\n",
            "          label: M101\n",
            "          topology: tests/interop/m101-routeserver-bird332.clab.yml\n",
            "          script: tests/interop/scripts/test-m101-routeserver-bird332.sh\n",
            '          max_attempts: "1"\n',
        ):
            with self.subTest(seam=old):
                count = (ROOT / relative).read_text().count(old)
                self.assertGreater(count, 0, f"missing M101 seam: {old}")
                self.mutate(relative, old, occurrence=count - 1)

        digest_pull = (
            "docker pull quay.io/frrouting/frr@sha256:"
            "f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c"
        )
        count = (ROOT / relative).read_text().count(digest_pull)
        self.mutate(
            relative,
            digest_pull,
            "docker pull quay.io/frrouting/frr:10.3.1",
            occurrence=count - 1,
        )

    def test_m102_openbgpd92_route_server_job_is_load_bearing(self):
        relative = ".github/workflows/interop.yml"
        for old in (
            "  m102:\n",
            "    needs: [grpcurl_archive, prime_dev_image]\n",
            "      - name: Verify and pull digest-pinned OpenBGPD 9.2 image\n",
            "          OPENBGPD_AMD64_MANIFEST: sha256:3178027d7ca916eacec247c66472a1f95a17d83d4616fe4f118318a912ab8beb\n",
            "          OPENBGPD_CONFIG: sha256:06317b65d9fadc80f68c5c8e7c82815b0643577fd5441bd55038e43771b5807e\n",
            "          docker pull \"$OPENBGPD_IMAGE\"\n",
            "      - name: Build bmpsink:m102 capture sidecar\n",
            "        run: docker build -t bmpsink:m102 -f tests/interop/Dockerfile.bmpsink tests/interop\n",
            '          CLEANUP: "1"\n',
            "          label: M102\n",
            "          topology: tests/interop/m102-routeserver-openbgpd92.clab.yml\n",
            "          script: tests/interop/scripts/test-m102-routeserver-openbgpd92.sh\n",
            '          max_attempts: "1"\n',
        ):
            with self.subTest(seam=old):
                count = (ROOT / relative).read_text().count(old)
                self.assertGreater(count, 0, f"missing M102 seam: {old}")
                self.mutate(relative, old, occurrence=count - 1)
        job_name = "    name: M102 — OpenBGPD 9.2 route-server member proof\n"
        self.mutate(
            relative,
            job_name,
            job_name
            + "      # sudo apt-get install tshark util-linux is forbidden here\n",
        )

    def test_m103_gobgp48_differential_job_is_load_bearing(self):
        relative = ".github/workflows/interop.yml"
        workflow = (ROOT / relative).read_text()
        job_start = workflow.index("\n  m103:\n") + 1
        job_end = workflow.index("\n  m104:\n")
        job = workflow[job_start:job_end]
        for old in (
            "  m103:\n",
            "      - name: Build gobgp:v4.8.0-m103\n",
            "          docker build --build-arg TARGETARCH=amd64\n",
            "          --build-arg GOBGP_VERSION=4.8.0\n",
            "          --build-arg GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03\n",
            "          -t gobgp:v4.8.0-m103 -f tests/interop/Dockerfile.gobgp-v47 tests/interop\n",
            "      - name: Run M103 (single-attempt GoBGP 4.8 differential)\n",
            "          label: M103\n",
            "          topology: tests/interop/m103-gobgp-v48-rs-differential.clab.yml\n",
            "          script: tests/interop/scripts/test-m103-gobgp-v48-rs-differential.sh\n",
            "      - name: Run M103 negative completeness proof (single attempt)\n",
            '          M103_COMPLETENESS_NEGATIVE: "1"\n',
            "          label: M103-negative\n",
            '          M103_ARTIFACT_DIR: ${{ runner.temp }}/m103-normal\n',
            '          M103_ARTIFACT_DIR: ${{ runner.temp }}/m103-negative\n',
            "      - name: Upload M103 normal successful-run evidence\n",
            "      - name: Upload M103 negative successful-run evidence\n",
            '          name: m103-gobgp-v48-normal-${{ github.sha }}\n',
            '          name: m103-gobgp-v48-negative-${{ github.sha }}\n',
            '          path: ${{ runner.temp }}/m103-normal\n',
            '          path: ${{ runner.temp }}/m103-negative\n',
        ):
            with self.subTest(seam=old):
                self.assertIn(old, job, f"missing M103 seam: {old}")
                self.mutate(relative, old, occurrence=workflow[:job_start].count(old))

        max_attempt = '          max_attempts: "1"\n'
        count = (ROOT / relative).read_text().count(max_attempt)
        self.assertGreaterEqual(count, 2)
        self.mutate(relative, max_attempt, occurrence=count - 1)
        for old in (
            "        uses: actions/upload-artifact@v7\n",
            "          if-no-files-found: error\n",
            "          retention-days: 14\n",
        ):
            count = (ROOT / relative).read_text().count(old)
            self.assertGreaterEqual(count, 2)
            self.mutate(relative, old, occurrence=count - 1)

    def test_m104_current_arouteserver_differential_job_is_load_bearing(self):
        relative = ".github/workflows/interop.yml"
        workflow = (ROOT / relative).read_text()
        job_start = workflow.index("\n  m104:\n") + 1
        job_end = workflow.index("\n  m107:\n")
        job = workflow[job_start:job_end]
        for old in (
            "  m104:\n",
            "    needs: [grpcurl_archive, bird2192_archive, prime_dev_image]\n",
            "      - name: Verify and pull exact ARouteServer 1.23.2 image\n",
            "          AROUTESERVER_IMAGE: pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66\n",
            "          AROUTESERVER_CONFIG: sha256:4a08ef740f00a119f5897b0f834da9ff172a282c93d47fdff636c3b50c9aec93\n",
            '          manifest_json=$(docker buildx imagetools inspect --raw "$AROUTESERVER_IMAGE")\n',
            "            application/vnd.docker.distribution.manifest.v2+json\n",
            '            \'import importlib.metadata; print(importlib.metadata.version("arouteserver"))\')" = \\\n',
            "      - name: Build bird:v2.19.2-m104\n",
            "          tags: bird:v2.19.2-m104\n",
            "          cache-from: type=gha,scope=bird2192-m104\n",
            "          cache-to: type=gha,mode=max,scope=bird2192-m104,ignore-error=true\n",
            "      - name: Build gobgp:v4.8.0-m104\n",
            "      - uses: ./.github/actions/install-protobuf\n",
            "          -t gobgp:v4.8.0-m104 -f tests/interop/Dockerfile.gobgp-v47 tests/interop\n",
            "      - name: Run immutable M90 context proof (exact 23/23)\n",
            "          M90_ARS_IMAGE: pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66\n",
            "          output=$(bash tests/interop/m90-differential/prove-context-ingestion.sh)\n",
            "          grep -Fq 'PROOF PASS: 23 checks' <<<\"$output\"\n",
            "      - name: Run M104 offline destructive contract\n",
            "          --self-test-offline-contract\n",
            "      - name: Run M104 (single-attempt current-daemon differential)\n",
            "          M104_EXPECTED_GIT_SHA: ${{ github.sha }}\n",
            "          label: M104\n",
            "          topology: tests/interop/m104-arouteserver-current-rs-differential.clab.yml\n",
            "          script: tests/interop/scripts/test-m104-arouteserver-current-rs-differential.sh\n",
        ):
            with self.subTest(seam=old):
                self.assertIn(old, job, f"missing M104 seam: {old}")
                self.mutate(relative, old, occurrence=workflow[:job_start].count(old))

        stage = (
            "      - name: Stage verified BIRD 2.19.2 archive\n"
            "        uses: ./.github/actions/stage-bird3-artifact\n"
            "        with:\n"
            '          version: "2.19.2"\n'
            "          sha256: aff89abba3b92b7637bd57e0168b8d7ae887747f160ada4973378ad72f5f3660\n"
            "          artifact-name: bird2192-v2.19.2-source\n"
        )
        count = (ROOT / relative).read_text().count(stage)
        self.assertGreaterEqual(count, 2)
        self.mutate(relative, stage, occurrence=count - 1)

        max_attempt = '          max_attempts: "1"\n'
        count = (ROOT / relative).read_text().count(max_attempt)
        self.assertGreaterEqual(count, 1)
        self.mutate(relative, max_attempt, occurrence=count - 1)

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
                "COPY gobgp-archive/ /tmp/gobgp-archive/",
                "RUN mkdir -p /tmp/gobgp-archive",
            ),
            (
                'if [ ! -f "/tmp/gobgp-archive/${archive}" ]; then',
                "if true; then",
            ),
            (
                'https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/${archive}',
                "https://example.invalid/${archive}",
            ),
            (
                'if [ "${attempt}" -ge 3 ]; then',
                'if [ "${attempt}" -ge 9999 ]; then',
            ),
            (
                'echo "${checksum}  /tmp/gobgp-archive/${archive}" | sha256sum --check --strict',
                "true # skipped checksum verification",
            ),
            (
                'tar --extract --gzip --file "/tmp/gobgp-archive/${archive}" --directory /usr/local/bin gobgp gobgpd',
                'tar --extract --gzip --file "/tmp/gobgp-archive/${archive}" --directory /usr/local/bin',
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

    def test_bird3_source_archive_contract_is_load_bearing(self):
        relative = "tests/interop/Dockerfile.bird3"
        checksum = "21297d7a02edd700ae82de5a630055a9cb88a99e2e7e45551bc7d6c1e5b4de2c"
        cases = (
            ("ARG BIRD_VERSION=3.3.2", "ARG BIRD_VERSION=latest"),
            (
                f'checksum="{checksum}"',
                f'checksum="{checksum[::-1]}"',
            ),
            (
                "COPY bird3-archive/ /tmp/bird3-archive/",
                "RUN mkdir -p /tmp/bird3-archive",
            ),
            (
                'if [ ! -f "/tmp/bird3-archive/${archive}" ]; then',
                "if true; then",
            ),
            (
                "https://bird.nic.cz/download/bird-${BIRD_VERSION}.tar.gz",
                "https://example.invalid/bird-${BIRD_VERSION}.tar.gz",
            ),
            (
                'if [ "${attempt}" -ge 3 ]; then',
                'if [ "${attempt}" -ge 9999 ]; then',
            ),
            (
                'echo "${checksum}  /tmp/bird3-archive/${archive}" | sha256sum --check --strict',
                "true # skipped checksum verification",
            ),
            (
                'tar -xzf "/tmp/bird3-archive/${archive}" --strip-components=1',
                'tar -xzf "/tmp/bird3-archive/${archive}"',
            ),
            (
                '    echo "${checksum}  /tmp/bird3-archive/${archive}" | sha256sum --check --strict; \\\n'
                '    tar -xzf "/tmp/bird3-archive/${archive}" --strip-components=1; \\\n',
                '    tar -xzf "/tmp/bird3-archive/${archive}" --strip-components=1; \\\n'
                '    echo "${checksum}  /tmp/bird3-archive/${archive}" | sha256sum --check --strict; \\\n',
            ),
            ("bird --version", "true # removed bird assertion"),
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
