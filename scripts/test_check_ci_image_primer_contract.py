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
BIRD332 = "21297d7a02edd700ae82de5a630055a9cb88a99e2e7e45551bc7d6c1e5b4de2c"
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
    "        with:\n"
    '          version: "2.19.2"\n'
    f"          sha256: {BIRD2192}\n\n"
)
M74_STAGE = (
    "      - name: Stage verified GoBGP archive\n"
    "        uses: ./.github/actions/stage-gobgp-artifact\n\n"
)
M74_BUILD = (
    "      - name: Build gobgp:interop\n"
    "        run: docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop\n\n"
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
        with self.subTest("workflow copy drifts"):
            self.assert_red(
                f"{INTEROP}:1008: digest is not in {MANIFEST}",
                (INTEROP, f"sha256: {BIRD2192}", f"sha256: {DRIFTED}"),
            )
        with self.subTest("Dockerfile copy drifts"):
            self.assert_red(
                f"tests/interop/Dockerfile.bird-v2192:4: digest is not in {MANIFEST}",
                (
                    "tests/interop/Dockerfile.bird-v2192",
                    f"ARG BIRD_SHA256={BIRD2192}",
                    f"ARG BIRD_SHA256={DRIFTED}",
                ),
            )
        with self.subTest("manifest bumped: every stale copy is named"):
            errors = self.mutated_errors((MANIFEST, BIRD332, DRIFTED))
            self.assertIn(f"{MANIFEST}: bird-3.3.2.tar.gz has no copy in the CI surfaces", errors)
            stale = {error.split(":", 1)[0] for error in errors if "is not in" in error}
            self.assertEqual(
                {
                    INTEROP,
                    KERNEL,
                    ".github/actions/stage-bird3-artifact/action.yml",
                    ".github/scripts/install-bird3.sh",
                    "tests/interop/Dockerfile.bird3",
                    "tests/interop/Dockerfile.bird-v332",
                },
                stale,
            )
        with self.subTest("manifest entry with no copy"):
            self.assert_red(
                f"{MANIFEST}: bird-9.9.9.tar.gz has no copy in the CI surfaces",
                (MANIFEST, "\n", f"\n{DRIFTED}  bird-9.9.9.tar.gz\n"),
            )

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

    def test_installer_scripts_verify_what_they_fetch(self):
        installer = ".github/scripts/install-bird3.sh"
        with self.subTest("checksum verification removed"):
            self.assert_red(
                f"{installer}: fetches without verifying a SHA-256",
                (installer, "sha256sum --check --status", "cat"),
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
        with self.subTest("action default no longer matches the Dockerfile"):
            self.assert_red(
                "kernel-dataplane.yml:m43: builds tests/interop/Dockerfile.bird3 without first staging bird3 3.3.2",
                (".github/actions/stage-bird3-artifact/action.yml", 'default: "3.3.2"', 'default: "3.3.3"'),
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
            (clab, "actions/cache@v4", "actions/cache@main", "not a reviewed version tag: actions/cache@main"),
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
