#!/usr/bin/env python3

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from scripts import classify_heavy_ci_paths as heavy
from scripts.check_ci_image_primer_contract import check


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
                ".github/actions/setup-dataplane-host",
            ):
                source = ROOT / fixture
                target = root / fixture
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(source, target)
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
                    occurrence=1,
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
            (".github/workflows/interop.yml", "needs: prime_dev_image", "needs: []"),
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
                occurrence=1,
            )

        kernel = ".github/workflows/kernel-dataplane.yml"
        with self.subTest(workflow=kernel, seam="consumer checkout"):
            self.mutate(
                kernel,
                "actions/checkout@v7",
                "actions/checkout@main",
                occurrence=1,
            )
        with self.subTest(workflow=kernel, seam="consumer needs"):
            self.mutate(kernel, "needs: prime_dev_image", "needs: []")

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
