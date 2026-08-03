#!/usr/bin/env python3
"""Fail closed when the shared CI image-primer contract drifts."""

from __future__ import annotations

import collections
import hashlib
import re
import sys
from pathlib import Path

INTEROP = (
    "m1 m13 m80 m15 m10 m14 m17 m73 m74 m75 m76 m77 m78 m79 m22 "
    "m24 m81 m82 m83 m85 m94 m86 m25 m29 m30 m34 m35 m35b m35c m41 "
    "m44 m54 m55 m56 m45 m57 m63 m64"
).split()
KERNEL = (
    "m36 m37 m37-ip m38 m39 m39b m48 m60 m61 m62 m40 m42 m50 m52 "
    "m58 m53 m51 m43 m46 m47 m49 m69 m70 m65 m71 m72 m66 m67 m68"
).split()
WORKFLOWS = ("ci.yml", "audit.yml", "interop.yml", "kernel-dataplane.yml")
GROUP = "group: ${{ github.workflow }}-${{ github.ref }}"
PRIMER_GROUP = "group: rustbgpd-dev-image-${{ github.sha }}"
IMPORT = "cache-from: type=gha,scope=rustbgpd-dev"
EXPORT = "cache-to: type=gha,scope=rustbgpd-dev,mode=max,ignore-error=true"
CHECKOUT = "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7"
BUILDX = (
    "uses: docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # v4"
)
BUILD_PUSH = (
    "uses: docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a # v7"
)
GOBGP_VERSION = "3.37.0"
GOBGP_CHECKSUMS = {
    "amd64": "e20b2a155fe14450b9fe37e5c1a1d1bfe101eb479645f5bbea860a8fde30e522",
    "arm64": "0aaa2da6e4dcaaf57e3d0e64eae14946292b0a5894d80ef3b7ebde3bf52beb29",
}
NETNS_SELECTOR_HASH = "0278940b2953d00c57398b3545141144afb4f0e7673b20cffe2599521c37b9ff"
NETNS_COMPILE_ONCE_HASH = "384d95c6b7449ba345be55aea4ed890c78958467f4140abf327e80be39309d76"
NETNS_WORKFLOW_SELECTORS = tuple(
    "fdb_nhg rustbgpd_prepare fib_runtime bfd_runtime dataplane_vlan_fdb "
    "macip_vlan_attribution svd_fdb_vni managed_bridge managed_vxlan "
    "managed_svd_vxlan managed_vlan_upper managed_ready l3_multipath "
    "managed_ip_vrf_ready l3_all_active_writer".split()
)
NETNS_SECCOMP_HASH = "2c2fc7d46458574b4fe2d820cb82697b3ff9e4a31083de518bdb2993b0ed9fcb"

TRIGGER_HASHES = {
    "ci.yml": "65951f4c4d1d6c4d3aae2c33705d14cdc144b3efd8bcc01653049e6d7f2fb5f8",
    "audit.yml": "1829597143324f5361dfdfece50ddeffd6f7d5934b72198f1837fbdf25339fd3",
    "interop.yml": "5a02c2699d26443c537ba1560fd1b16c595498e9148b2f99be975ae79b3b9492",
    "kernel-dataplane.yml": "6a5d9f010df1a4b97bed98beb1e27a7284bdcf3c19befe71263a15a186c73b86",
}
PERMISSION_HASHES = {
    "ci.yml": "ef1c6c32bd7afe22841015d36a48ee18816a0a8eb0e9a1a0af951ce1ff7cd183",
    "audit.yml": "6f1d70d72bad231d43c575acef6946580e439c879794ed2ea1f4a40340245172",
    "interop.yml": "6f1d70d72bad231d43c575acef6946580e439c879794ed2ea1f4a40340245172",
    "kernel-dataplane.yml": "6f1d70d72bad231d43c575acef6946580e439c879794ed2ea1f4a40340245172",
}
CALL_HASHES = {
    "interop.yml": "079176e73f3ca4a329613132ca3863f27400b162091b2d4802e97931001db135",
    "kernel-dataplane.yml": "decf4a7ba46c4a89f420de248790ef1badbfaba81371ae7c291ad9c9943add03",
}
PINS = collections.Counter(
    {
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7": 77,
        "dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c # stable": 3,
        "Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2": 5,
        "dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c # 1.95": 2,
        "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # v4": 42,
        "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a # v7": 43,
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7": 1,
        "rustsec/audit-check@69366f33c96575abad1ee0dba8212993eecbe998 # v2.0.0": 1,
        "EmbarkStudios/cargo-deny-action@3c6349835b2b7b196a839186cb8b78e02f7b5f25 # v2.1.1": 1,
    }
)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _top_block(text: str, key: str) -> str:
    match = re.search(rf"(?ms)^{re.escape(key)}:\n.*?(?=^[A-Za-z][\w-]*:|\Z)", text)
    return match.group(0).rstrip() if match else ""


def _jobs(text: str) -> dict[str, str]:
    body = text.split("\njobs:\n", 1)[1] if "\njobs:\n" in text else ""
    matches = list(re.finditer(r"(?m)^  ([\w-]+):\n", body))
    return {
        m.group(1): body[
            m.end() : matches[i + 1].start() if i + 1 < len(matches) else len(body)
        ]
        for i, m in enumerate(matches)
    }


def check(root: Path) -> list[str]:
    errors: list[str] = []
    workflow_dir = root / ".github" / "workflows"
    texts = {name: (workflow_dir / name).read_text() for name in WORKFLOWS}
    for name, text in texts.items():
        if GROUP not in _top_block(
            text, "concurrency"
        ) or "cancel-in-progress: true" not in _top_block(text, "concurrency"):
            errors.append(f"{name}: workflow cancellation contract drifted")
        if _hash(_top_block(text, "on")) != TRIGGER_HASHES[name]:
            errors.append(f"{name}: triggers drifted")
        permissions = "\n".join(
            re.findall(r"(?ms)^permissions:\n.*?(?=^[A-Za-z][\w-]*:|\Z)", text)
        )
        if _hash(permissions) != PERMISSION_HASHES[name]:
            errors.append(f"{name}: permissions drifted")

    for name, roster, setup in (
        ("interop.yml", INTEROP, False),
        ("kernel-dataplane.yml", KERNEL, True),
    ):
        jobs = _jobs(texts[name])
        expected = ["prime_dev_image", *roster] + (["netns"] if setup else [])
        if list(jobs) != expected:
            errors.append(f"{name}: exact job roster/order drifted")
        primer = jobs.get("prime_dev_image", "")
        for seam in (
            "timeout-minutes: 30",
            PRIMER_GROUP,
            "cancel-in-progress: false",
            CHECKOUT,
            "ref: ${{ github.sha }}",
            BUILDX,
            BUILD_PUSH,
            "context: .",
            "load: false",
            "tags: rustbgpd:dev",
            "target: dev",
            IMPORT,
            EXPORT,
        ):
            if seam not in primer:
                errors.append(f"{name}: primer missing {seam}")
        if "load: true" in primer:
            errors.append(f"{name}: primer must export cache, not load an image")
        for job_name in roster:
            job = jobs.get(job_name, "")
            if "needs: prime_dev_image" not in job:
                errors.append(f"{name}:{job_name}: missing primer dependency")
            if CHECKOUT not in job:
                errors.append(f"{name}:{job_name}: pinned checkout drifted")
            if setup:
                if "uses: ./.github/actions/setup-dataplane-host" not in job:
                    errors.append(f"{name}:{job_name}: setup call drifted")
            else:
                for seam in (IMPORT, "load: true", "tags: rustbgpd:dev", "target: dev"):
                    if seam not in job:
                        errors.append(f"{name}:{job_name}: consumer missing {seam}")
                if "cache-to:" in job:
                    errors.append(f"{name}:{job_name}: consumer exports a cache")
        calls = "\n".join(
            line.strip()
            for line in texts[name].splitlines()
            if re.search(
                r"(setup-dataplane-host|run-interop-test|label:|topology:|script:)",
                line,
            )
        )
        if _hash(calls) != CALL_HASHES[name]:
            errors.append(f"{name}: existing test/setup calls drifted")
    kernel_jobs = _jobs(texts["kernel-dataplane.yml"])
    netns_job = kernel_jobs.get("netns", "")
    if "needs: prime_dev_image" in netns_job:
        errors.append("kernel-dataplane.yml:netns must remain independent")

    runner = (
        root / "crates" / "evpn-linux" / "tests" / "docker" / "run-netns-tests.sh"
    ).read_text()
    selector_body = runner.split('case "${1:-all}" in', 1)[-1].split("\nesac", 1)[0]
    if _hash(selector_body) != NETNS_SELECTOR_HASH:
        errors.append("run-netns-tests.sh: selector semantics drifted")

    validation_marker = 'RUSTBGPD_COMPILE_ONCE="${RUSTBGPD_COMPILE_ONCE:-0}"'
    validation = validation_marker + runner.split(validation_marker, 1)[-1].split(
        "\n\nSECCOMP_ARGS=()", 1
    )[0]
    if _hash(validation) != NETNS_COMPILE_ONCE_HASH:
        errors.append("run-netns-tests.sh: compile-once validation drifted")

    workflow_selectors = tuple(
        re.findall(
            r"run: bash crates/evpn-linux/tests/docker/run-netns-tests\.sh ([\w-]+)",
            netns_job,
        )
    )
    if workflow_selectors != NETNS_WORKFLOW_SELECTORS:
        errors.append("kernel-dataplane.yml:netns selector calls/order drifted")

    prepare = (
        'sh -c "cargo clean -p rustbgpd-api && ' 'cargo test -p rustbgpd --no-run"'
    )
    runtime = 'cargo test -p rustbgpd "$RUSTBGPD_TEST_FILTER"'
    standalone = (
        'sh -c "cargo clean -p rustbgpd-api && cargo test -p rustbgpd '
        "'${RUSTBGPD_TEST_FILTER}' -- --test-threads=1 --nocapture\""
    )
    if runner.count(prepare) != 1:
        errors.append("run-netns-tests.sh: rustbgpd prepare command drifted")
    if runner.count(standalone) != 1:
        errors.append("run-netns-tests.sh: standalone FIB/BFD clean-build drifted")
    if runner.count("cargo clean -p rustbgpd-api") != 2:
        errors.append("run-netns-tests.sh: rustbgpd-api clean roster drifted")
    if runner.count("cargo test -p rustbgpd --no-run") != 1:
        errors.append("run-netns-tests.sh: rustbgpd must be compiled exactly once")
    if runner.count(runtime) != 1:
        errors.append("run-netns-tests.sh: FIB/BFD prepared-artifact reuse drifted")

    docker_args = runner.split("\nDOCKER_ARGS=(\n", 1)[-1].split("\n)\n", 1)[0]
    effective_docker_args = tuple(
        line.strip()
        for line in docker_args.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    expected_docker_args = (
        "--rm",
        "--cap-add=NET_ADMIN",
        "--cap-add=SYS_ADMIN",
        "--security-opt apparmor=unconfined",
        '"${SECCOMP_ARGS[@]}"',
        "-e EVPN_LINUX_NETNS=1",
        "-e RUST_BACKTRACE=1",
        "-e CARGO_TERM_COLOR=always",
        '-v "${REPO_ROOT}:/work"',
        '-v "${CARGO_CACHE_VOL}:/usr/local/cargo/registry"',
        '-v "${TARGET_CACHE_VOL}:/work/target"',
        "-w /work",
    )
    if effective_docker_args != expected_docker_args:
        errors.append(
            "run-netns-tests.sh: container cleanup/privileges/volumes drifted"
        )
    for seam in (
        "RUSTBGPD_PREPARE=0",
        'RUSTBGPD_COMPILE_ONCE="${RUSTBGPD_COMPILE_ONCE:-0}"',
        'if [ "$RUSTBGPD_PREPARE" = "1" ]; then',
        'elif [ -n "$RUSTBGPD_TEST_FILTER" ]; then',
        'CARGO_CACHE_VOL="${CARGO_CACHE_VOL:-rustbgpd-netns-tests-cargo}"',
        'TARGET_CACHE_VOL="${TARGET_CACHE_VOL:-rustbgpd-netns-tests-target}"',
        'SECCOMP_ARGS+=("--security-opt=seccomp=$SECCOMP_PROFILE_RESOLVED")',
    ):
        if runner.count(seam) != 1:
            errors.append(f"run-netns-tests.sh: harness seam drifted: {seam}")
    if "TARGET_CACHE_VOL:" in netns_job or "docker volume rm" in netns_job:
        errors.append("kernel-dataplane.yml:netns named target-volume lifetime drifted")

    seccomp_path = "crates/evpn-linux/tests/docker/seccomp-deny-af-inet6.json"
    compile_once = 'RUSTBGPD_COMPILE_ONCE: "1"'
    for step_name in (
        "Prepare rustbgpd runtime netns test binaries",
        "ADR-0061 FIB runtime netns test",
        "ADR-0067 BFD runtime netns test",
    ):
        step = netns_job.split(f"- name: {step_name}", 1)[-1].split(
            "\n      - name:", 1
        )[0]
        if compile_once not in step:
            errors.append(f"kernel-dataplane.yml:netns {step_name} opt-in drifted")
    if netns_job.count(compile_once) != 3:
        errors.append("kernel-dataplane.yml:netns compile-once opt-in roster drifted")
    bfd_step = netns_job.split("- name: ADR-0067 BFD runtime", 1)[-1].split(
        "\n      - name:", 1
    )[0]
    if (
        netns_job.count(f"SECCOMP_PROFILE: {seccomp_path}") != 1
        or f"SECCOMP_PROFILE: {seccomp_path}" not in bfd_step
    ):
        errors.append("kernel-dataplane.yml:netns BFD seccomp profile drifted")
    if _hash((root / seccomp_path).read_text()) != NETNS_SECCOMP_HASH:
        errors.append("seccomp-deny-af-inet6.json: AF_INET6 denial drifted")

    action = (
        root / ".github" / "actions" / "setup-dataplane-host" / "action.yml"
    ).read_text()
    build = action.split("- name: Build rustbgpd:dev", 1)[-1]
    if BUILDX not in action:
        errors.append(f"setup-dataplane-host: consumer missing {BUILDX}")
    for seam in (
        BUILD_PUSH,
        "context: .",
        IMPORT,
        "load: true",
        "tags: rustbgpd:dev",
        "target: dev",
    ):
        if seam not in build:
            errors.append(f"setup-dataplane-host: consumer missing {seam}")
    if "cache-to:" in build:
        errors.append("setup-dataplane-host: consumer must not export cache")

    pins = collections.Counter()
    for text in [*texts.values(), action]:
        for value in re.findall(r"^\s*(?:- )?uses:\s*(.+)$", text, re.MULTILINE):
            if not value.strip().startswith("./"):
                pins[value.strip()] += 1
    if pins != PINS:
        errors.append("external action pins/counts drifted")

    dockerfile = (root / "Dockerfile").read_text()
    builder = dockerfile.split("FROM chef AS builder\n", 1)[-1].split("\nFROM ", 1)[0]
    dev = dockerfile.split("FROM debian:bookworm-slim AS dev\n", 1)[-1].split(
        "\nFROM ", 1
    )[0]
    binaries = ("rustbgpd", "rbgp", "evpn-tester", "evpn-monitor")
    for binary in binaries:
        if f"cp target/ci/{binary} /out/" not in builder:
            errors.append(
                f"Dockerfile: builder does not bridge target/ci/{binary} to /out"
            )
        if f"COPY --from=builder /out/{binary} /usr/local/bin/{binary}" not in dev:
            errors.append(f"Dockerfile: dev does not copy builder /out/{binary}")

    gobgp = (root / "tests" / "interop" / "Dockerfile.gobgp").read_text()
    for seam in (
        "FROM debian:bookworm-slim AS gobgp-release",
        "ARG TARGETARCH",
        f"ENV GOBGP_VERSION={GOBGP_VERSION}",
        'archive="gobgp_${GOBGP_VERSION}_linux_${TARGETARCH}.tar.gz"',
        '*) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;;',
        'https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/${archive}',
        'echo "${checksum}  /tmp/${archive}" | sha256sum --check --strict',
        'tar --extract --gzip --file "/tmp/${archive}" --directory /usr/local/bin gobgp gobgpd',
        'test "$(gobgp --version)" = "gobgp version ${GOBGP_VERSION}"',
        'test "$(gobgpd --version)" = "gobgpd version ${GOBGP_VERSION}"',
    ):
        if seam not in gobgp:
            errors.append(f"Dockerfile.gobgp: pinned release seam missing: {seam}")
    if gobgp.count("FROM debian:bookworm-slim") != 2:
        errors.append("Dockerfile.gobgp: rolling bookworm stage roster drifted")
    for arch, checksum in GOBGP_CHECKSUMS.items():
        if f'{arch}) checksum="{checksum}" ;;' not in gobgp:
            errors.append(f"Dockerfile.gobgp: {arch} checksum drifted")
    if re.search(r"(?:@latest|releases/(?:latest|download/latest)|GOBGP_VERSION=latest)", gobgp):
        errors.append("Dockerfile.gobgp: floating GoBGP release is forbidden")
    if "go install github.com/osrg/gobgp" in gobgp or "FROM golang:" in gobgp:
        errors.append("Dockerfile.gobgp: source build replaced pinned release archives")
    return errors


if __name__ == "__main__":
    failures = check(Path(__file__).resolve().parents[1])
    if failures:
        print("CI image-primer contract check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        raise SystemExit(1)
    print("CI image-primer contract OK")
