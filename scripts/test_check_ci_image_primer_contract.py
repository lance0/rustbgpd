#!/usr/bin/env python3

import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.check_ci_image_primer_contract import check
from scripts.validate_ci_image_cache_handoff import validate_log


ROOT = Path(__file__).resolve().parents[1]


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
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
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
                    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                    "actions/checkout@main",
                ),
                (
                    "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c",
                    "docker/setup-buildx-action@main",
                ),
                (
                    "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a",
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
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "actions/checkout@main",
                occurrence=1,
            )

        kernel = ".github/workflows/kernel-dataplane.yml"
        with self.subTest(workflow=kernel, seam="consumer checkout"):
            self.mutate(
                kernel,
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
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
                "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c",
                "docker/setup-buildx-action@main",
            ),
            (
                "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a",
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

    def test_dockerfile_cache_handoff_is_load_bearing(self):
        target_mount = (
            "    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \\\n"
        )
        cases = (
            (
                "FROM builder-deps AS builder",
                "FROM chef AS builder",
                0,
            ),
            (
                target_mount,
                target_mount
                + "    --mount=type=cache,target=/build/target,sharing=locked \\\n",
                0,
            ),
            (
                target_mount,
                target_mount
                + "    --mount=type=cache,target=/build/target,sharing=locked \\\n",
                1,
            ),
            (
                "cargo chef cook --workspace --profile ci --recipe-path recipe.json",
                "true # cook removed",
                0,
            ),
            (
                "cargo build --workspace --profile ci",
                "true # source build removed",
                0,
            ),
            ("    rm -rf target\n", "", 0),
            (
                "    cp target/ci/evpn-monitor /out/ && \\\n"
                "    rm -rf target\n",
                "    rm -rf target && \\\n"
                "    cp target/ci/evpn-monitor /out/\n",
                0,
            ),
            (
                "--mount=type=cache,target=/build/target,sharing=locked",
                "--mount=type=cache,target=/build/release-target,sharing=locked",
                0,
            ),
        )
        for old, new, occurrence in cases:
            with self.subTest(seam=old, occurrence=occurrence):
                self.mutate("Dockerfile", old, new, occurrence)

    def test_cache_handoff_build_log_validator(self):
        good = """\
#10 [builder-deps 2/2] RUN --mount=x cargo chef cook --workspace --profile ci --recipe-path recipe.json
#10 CACHED
#12 [builder 2/2] RUN --mount=x cargo build --workspace --profile ci && cp outputs
#12 0.100    Compiling rustbgpd-wire v0.16.1 (/build/crates/wire)
#12 DONE 1.0s
"""
        crates = {"rustbgpd-wire"}
        self.assertEqual([], validate_log(good, crates))

        uncached_cook = good.replace("#10 CACHED", "#10 DONE 1.0s")
        self.assertTrue(validate_log(uncached_cook, crates))

        all_cached = good.replace(
            "#12 0.100    Compiling rustbgpd-wire v0.16.1 (/build/crates/wire)\n"
            "#12 DONE 1.0s",
            "#12 CACHED",
        )
        self.assertTrue(validate_log(all_cached, crates))

        external = good.replace(
            "#12 DONE 1.0s",
            "#12 0.200    Compiling tokio v1.50.0\n#12 DONE 1.0s",
        )
        errors = validate_log(external, crates)
        self.assertTrue(any("tokio" in error for error in errors))

        step_id_collision = """\
#20 [builder-deps 2/2] RUN --mount=x cargo chef cook --workspace --profile ci --recipe-path recipe.json
#20 CACHED
#1 [builder 2/2] RUN --mount=x cargo build --workspace --profile ci && cp outputs
#1 0.100    Compiling rustbgpd-wire v0.16.1 (/build/crates/wire)
#1 DONE 1.0s
#10 0.200    Compiling tokio v1.50.0
"""
        self.assertEqual([], validate_log(step_id_collision, crates))


if __name__ == "__main__":
    unittest.main()
