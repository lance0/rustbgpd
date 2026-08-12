#!/usr/bin/env python3
"""Fail closed when the shared CI image-primer contract drifts."""

from __future__ import annotations

import collections
import hashlib
import re
import stat
import sys
from pathlib import Path

INTEROP = (
    "m1 m13 m80 m15 m10 m14 m17 m73 m74 m75 m76 m77 m78 m79 m22 "
    "m24 m81 m82 m83 m85 m94 m86 m25 m29 m30 m34 m35 m35b m35c m41 "
    "m44 m54 m55 m56 m45 m57 m63 m64 m26_m27_m28_m59_m91 m92"
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
CHECKOUT = "uses: actions/checkout@v7"
BUILDX = "uses: docker/setup-buildx-action@v4"
BUILD_PUSH = "uses: docker/build-push-action@v7"
CLASSIFIER_NEEDS = "needs: classify_changes"
CLASSIFIER_IF = "if: needs.classify_changes.outputs.run_labs == 'true'"
CLASSIFIER_SEAMS = (
    "    runs-on: ubuntu-latest",
    "    timeout-minutes: 1",
    "      run_labs: ${{ steps.classify.outputs.run_labs }}",
    "      - uses: actions/checkout@v7",
    "          fetch-depth: 0",
    "        id: classify",
    "          EVENT_NAME: ${{ github.event_name }}",
    "          BASE_SHA: ${{ github.event.pull_request.base.sha }}",
    "          HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
    "        run: python3 scripts/classify_heavy_ci_paths.py",
)
GOBGP_VERSION = "3.37.0"
GOBGP_CHECKSUMS = {
    "amd64": "e20b2a155fe14450b9fe37e5c1a1d1bfe101eb479645f5bbea860a8fde30e522",
    "arm64": "0aaa2da6e4dcaaf57e3d0e64eae14946292b0a5894d80ef3b7ebde3bf52beb29",
}
V064_SHA256 = "bd4829de08d0c50074f9ecd5c351399fae42be06d456b3880a04aa4a7cda1137"
V064_ARCHIVE = "rustbgpd-linux-amd64.tar.gz"
V064_ARTIFACT = "rustbgpd-v0.64.0-linux-amd64"
V064_CACHE_KEY = f"rustbgpd-v0.64.0-linux-amd64-{V064_SHA256}"
GRPCURL_SHA256 = "588c9c429476d9ed66cd3b2ae32283a6da36e0cfbb7e446f5d6a1b68dc770214"
GRPCURL_ARCHIVE = "grpcurl_1.9.1_linux_x86_64.tar.gz"
GRPCURL_ARTIFACT = "grpcurl-v1.9.1-linux-x86_64"
GRPCURL_CACHE_KEY = f"grpcurl-v1.9.1-linux-x86_64-{GRPCURL_SHA256}"
GRPCURL_ACTION = "uses: ./.github/actions/install-grpcurl-artifact"

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
    "interop.yml": "baf8da4607ed5e36ea6d2a656f05df3c87449456159dd4c847d51588ff0a96b5",
    "kernel-dataplane.yml": "decf4a7ba46c4a89f420de248790ef1badbfaba81371ae7c291ad9c9943add03",
}
PINS = collections.Counter(
    {
        "actions/checkout@v7": 84,
        "dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c # stable": 3,
        "Swatinem/rust-cache@v2": 5,
        "dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c # 1.95": 2,
        "docker/setup-buildx-action@v4": 44,
        "docker/build-push-action@v7": 45,
        "actions/cache@v6": 3,
        "actions/upload-artifact@v7": 4,
        "actions/download-artifact@v8": 3,
        "rustsec/audit-check@v2.0.0": 1,
        "EmbarkStudios/cargo-deny-action@v2": 1,
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


def _has_line(block: str, line: str) -> bool:
    return re.search(rf"(?m)^{re.escape(line)}$", block) is not None


def _list_needs(block: str) -> list[str]:
    flow = re.search(r"(?ms)^    needs: \[(.*?)\]\n", block)
    if flow:
        values = (value.strip() for value in flow.group(1).split(","))
        return [value for value in values if value]
    match = re.search(r"(?m)^    needs:\n((?:      - [\w-]+\n)+)", block)
    if not match:
        return []
    return re.findall(r"(?m)^      - ([\w-]+)$", match.group(1))


def _expected_jobs(block: str) -> list[str]:
    match = re.search(
        r"(?ms)^      EXPECTED_JOBS: >-\n(.*?)^    steps:\n", block
    )
    return match.group(1).split() if match else []


def check(root: Path) -> list[str]:
    errors: list[str] = []
    grpcurl_installer = root / ".github" / "scripts" / "install-grpcurl.sh"
    if not grpcurl_installer.is_file():
        errors.append("install-grpcurl.sh is missing")
    elif stat.S_IMODE(grpcurl_installer.stat().st_mode) != 0o755:
        errors.append("install-grpcurl.sh must have exact executable mode 100755")
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

    ci_jobs = _jobs(texts["ci.yml"])
    producer = ci_jobs.get("v064_validator", "")
    producer_seams = (
        "name: prepare exact v0.64 config migration validator",
        "runs-on: ubuntu-latest",
        "timeout-minutes: 10",
        CHECKOUT,
        "uses: actions/cache@v6",
        f"path: ${{{{ runner.temp }}}}/rustbgpd-v064-cache/{V064_ARCHIVE}",
        f"key: {V064_CACHE_KEY}",
        "--self-test",
        "--prepare-archive",
        "uses: actions/upload-artifact@v7",
        f"name: {V064_ARTIFACT}",
        "if-no-files-found: error",
        "retention-days: 1",
        "compression-level: 0",
    )
    for seam in producer_seams:
        if seam not in producer:
            errors.append(f"ci.yml:v064_validator missing {seam}")
    for forbidden in ("restore-keys:", "continue-on-error:"):
        if forbidden in producer:
            errors.append(f"ci.yml:v064_validator permits {forbidden}")
    if producer.count("uses: actions/cache@v6") != 1:
        errors.append("ci.yml:v064_validator must have one cache producer")
    if producer.count("uses: actions/upload-artifact@v7") != 1:
        errors.append("ci.yml:v064_validator must upload one same-run artifact")

    for job_name in ("core", "core_tests"):
        consumer = ci_jobs.get(job_name, "")
        for seam in (
            "needs: v064_validator",
            "uses: actions/download-artifact@v8",
            f"name: {V064_ARTIFACT}",
            f"path: ${{{{ runner.temp }}}}/rustbgpd-v064-artifact",
            "--install-archive",
            f'"$RUNNER_TEMP/rustbgpd-v064-artifact/{V064_ARCHIVE}"',
            '"$RUNNER_TEMP/rustbgpd-v064"',
        ):
            if seam not in consumer:
                errors.append(f"ci.yml:{job_name} missing validator seam {seam}")
        if consumer.count("uses: actions/download-artifact@v8") != 1:
            errors.append(f"ci.yml:{job_name} must download one validator artifact")
        for forbidden in (
            "--prepare-archive",
            "actions/cache@",
            "actions/upload-artifact@",
            "releases/download/v0.64.0",
            "restore-keys:",
            "continue-on-error:",
        ):
            if forbidden in consumer:
                errors.append(
                    f"ci.yml:{job_name} validator consumer permits {forbidden}"
                )

    aggregate = ci_jobs.get("check", "")
    for seam in (
        "needs: [v064_validator, core, core_tests, scale_receipts]",
        "V064_VALIDATOR_RESULT: ${{ needs.v064_validator.result }}",
        "printf 'v064_validator=%s\\n' \"$V064_VALIDATOR_RESULT\"",
        '[[ "$V064_VALIDATOR_RESULT" != "success"',
    ):
        if seam not in aggregate:
            errors.append(f"ci.yml:check missing validator result seam {seam}")

    for name, roster, setup in (
        ("interop.yml", INTEROP, False),
        ("kernel-dataplane.yml", KERNEL, True),
    ):
        jobs = _jobs(texts[name])
        heavy = [*roster] + (["netns"] if setup else [])
        expected = [
            "classify_changes",
            "grpcurl_archive",
            "prime_dev_image",
            *heavy,
            "check",
        ]
        if list(jobs) != expected:
            errors.append(f"{name}: exact job roster/order drifted")
        classifier = jobs.get("classify_changes", "")
        kind = "interop" if name == "interop.yml" else "kernel"
        if not _has_line(classifier, f"    name: Classify {kind} heavy-lab paths"):
            errors.append(f"{name}: classifier check name drifted")
        for seam in CLASSIFIER_SEAMS:
            if not _has_line(classifier, seam):
                errors.append(f"{name}: classifier missing {seam}")
        for forbidden in ("continue-on-error:", "if:"):
            if re.search(rf"(?m)^ +{re.escape(forbidden)}", classifier):
                errors.append(f"{name}: classifier permits active {forbidden}")
        grpcurl_producer = jobs.get("grpcurl_archive", "")
        for seam in (CLASSIFIER_NEEDS, CLASSIFIER_IF):
            if not _has_line(grpcurl_producer, f"    {seam}"):
                errors.append(
                    f"{name}:grpcurl_archive missing job-level {seam}"
                )
        for seam in (
            "name: Prepare exact grpcurl archive",
            "runs-on: ubuntu-latest",
            "timeout-minutes: 10",
            CHECKOUT,
            "ref: ${{ github.sha }}",
            "uses: actions/cache@v6",
            f"path: ${{{{ runner.temp }}}}/grpcurl-cache/{GRPCURL_ARCHIVE}",
            f"key: {GRPCURL_CACHE_KEY}",
            "--prepare-archive",
            f'"$RUNNER_TEMP/grpcurl-cache/{GRPCURL_ARCHIVE}"',
            "uses: actions/upload-artifact@v7",
            f"name: {GRPCURL_ARTIFACT}",
            "if-no-files-found: error",
            "retention-days: 1",
            "compression-level: 0",
        ):
            if seam not in grpcurl_producer:
                errors.append(f"{name}:grpcurl_archive missing {seam}")
        for forbidden in (
            "restore-keys:",
            "continue-on-error:",
            "actions/download-artifact@",
            "--install-archive",
        ):
            if forbidden in grpcurl_producer:
                errors.append(f"{name}:grpcurl_archive permits {forbidden}")
        if grpcurl_producer.count("uses: actions/cache@v6") != 1:
            errors.append(f"{name}:grpcurl_archive must restore one exact cache")
        if grpcurl_producer.count("--prepare-archive") != 1:
            errors.append(f"{name}:grpcurl_archive must prepare one archive")
        if grpcurl_producer.count("uses: actions/upload-artifact@v7") != 1:
            errors.append(f"{name}:grpcurl_archive must upload one artifact")
        exact_path = (
            f"path: ${{{{ runner.temp }}}}/grpcurl-cache/{GRPCURL_ARCHIVE}"
        )
        if grpcurl_producer.count(exact_path) != 2:
            errors.append(f"{name}:grpcurl_archive cache/artifact paths drifted")
        if grpcurl_producer.count(f"key: {GRPCURL_CACHE_KEY}") != 1:
            errors.append(f"{name}:grpcurl_archive cache key drifted")
        if grpcurl_producer.count(f"name: {GRPCURL_ARTIFACT}") != 1:
            errors.append(f"{name}:grpcurl_archive artifact name drifted")
        primer = jobs.get("prime_dev_image", "")
        for seam in (CLASSIFIER_NEEDS, CLASSIFIER_IF):
            if not _has_line(primer, f"    {seam}"):
                errors.append(f"{name}: primer missing job-level {seam}")
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
            if not _has_line(
                job, "    needs: [grpcurl_archive, prime_dev_image]"
            ):
                errors.append(
                    f"{name}:{job_name}: missing exact grpcurl/primer dependencies"
                )
            if CHECKOUT not in job:
                errors.append(f"{name}:{job_name}: pinned checkout drifted")
            if setup:
                if "uses: ./.github/actions/setup-dataplane-host" not in job:
                    errors.append(f"{name}:{job_name}: setup call drifted")
                if GRPCURL_ACTION in job:
                    errors.append(f"{name}:{job_name}: bypasses shared host setup")
            else:
                if job.count(GRPCURL_ACTION) != 1:
                    errors.append(
                        f"{name}:{job_name}: must consume one grpcurl artifact"
                    )
                for seam in (IMPORT, "load: true", "tags: rustbgpd:dev", "target: dev"):
                    if seam not in job:
                        errors.append(f"{name}:{job_name}: consumer missing {seam}")
                if "cache-to:" in job:
                    errors.append(f"{name}:{job_name}: consumer exports a cache")
        aggregate = jobs.get("check", "")
        aggregate_needs = ["classify_changes", "grpcurl_archive", "prime_dev_image", *heavy]
        if _list_needs(aggregate) != aggregate_needs:
            errors.append(f"{name}:check exact dependency roster drifted")
        if _expected_jobs(aggregate) != aggregate_needs:
            errors.append(f"{name}:check runtime expected roster drifted")
        for seam in (
            "name: check",
            "runs-on: ubuntu-latest",
            "timeout-minutes: 5",
            "if: ${{ always() }}",
            "NEEDS_CONTEXT: ${{ toJSON(needs) }}",
            'classifier.get("result") != "success"',
            'run_labs not in {"true", "false"}',
            'expected_result = "success" if run_labs == "true" else "skipped"',
            'result != expected_result',
            "sys.exit(1)",
        ):
            if seam not in aggregate:
                errors.append(f"{name}:check missing aggregate seam {seam}")
        for forbidden in ("continue-on-error:", "if: success()"):
            if forbidden in aggregate:
                errors.append(f"{name}:check permits {forbidden}")
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
    m92 = _jobs(texts["interop.yml"]).get("m92", "")
    required = {
        GRPCURL_ACTION: 1,
        "docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop": 1,
        "docker build -t gobgp:v4.7.0-m92 -f tests/interop/Dockerfile.gobgp-v47 tests/interop": 1,
        "uses: ./.github/actions/run-interop-test": 2,
        "topology: tests/interop/m92-gobgp-v47-rs-differential.clab.yml": 2,
        "script: tests/interop/scripts/test-m92-gobgp-v47-rs-differential.sh": 2,
        "label: M92\n": 1,
        "label: M92-negative\n": 1,
        'M92_COMPLETENESS_NEGATIVE: "1"': 1,
    }
    if any(m92.count(seam) != count for seam, count in required.items()):
        errors.append("interop.yml:m92: differential job semantics drifted")
    negative = m92.split("- name: Run M92 negative completeness proof", 1)
    if len(negative) != 2 or 'M92_COMPLETENESS_NEGATIVE: "1"' in negative[0]:
        errors.append("interop.yml:m92: negative environment scope drifted")
    interop_classifier = _jobs(texts["interop.yml"]).get("classify_changes", "")
    kernel_jobs = _jobs(texts["kernel-dataplane.yml"])
    interop_classifier = interop_classifier.replace("interop heavy-lab", "heavy-lab")
    kernel_classifier = kernel_jobs.get("classify_changes", "").replace(
        "kernel heavy-lab", "heavy-lab"
    )
    if interop_classifier != kernel_classifier:
        errors.append("heavy workflows must share an identical classifier job")
    netns = kernel_jobs.get("netns", "")
    for seam in (CLASSIFIER_NEEDS, CLASSIFIER_IF):
        if not _has_line(netns, f"    {seam}"):
            errors.append(f"kernel-dataplane.yml:netns missing job-level {seam}")
    if "needs: prime_dev_image" in netns:
        errors.append("kernel-dataplane.yml:netns must remain independent")
    if "grpcurl_archive" in netns or GRPCURL_ACTION in netns:
        errors.append("kernel-dataplane.yml:netns must remain grpcurl-independent")

    action = (
        root / ".github" / "actions" / "setup-dataplane-host" / "action.yml"
    ).read_text()
    grpcurl_action = (
        root / ".github" / "actions" / "install-grpcurl-artifact" / "action.yml"
    ).read_text()
    for seam in (
        "uses: actions/download-artifact@v8",
        f"name: {GRPCURL_ARTIFACT}",
        "path: ${{ runner.temp }}/grpcurl-artifact",
        "--install-archive",
        f'"$RUNNER_TEMP/grpcurl-artifact/{GRPCURL_ARCHIVE}"',
        "/usr/local/bin",
    ):
        if seam not in grpcurl_action:
            errors.append(f"install-grpcurl-artifact missing {seam}")
    if grpcurl_action.count("uses: actions/download-artifact@v8") != 1:
        errors.append("install-grpcurl-artifact must download one same-run artifact")
    if grpcurl_action.count("--install-archive") != 1:
        errors.append("install-grpcurl-artifact must perform one offline install")
    for forbidden in (
        "--prepare-archive",
        "actions/cache@",
        "actions/upload-artifact@",
        "restore-keys:",
        "continue-on-error:",
        "releases/download/",
    ):
        if forbidden in grpcurl_action:
            errors.append(f"install-grpcurl-artifact permits {forbidden}")
    if re.search(r"(?m)^\s*curl\s", grpcurl_action):
        errors.append("install-grpcurl-artifact permits curl")
    # split(...)[-1] returns the whole file when the step name drifts, which
    # turns every seam check below into a file-wide search that passes
    # vacuously. Scope the region only once the anchor is known to be present.
    build_step = "- name: Build rustbgpd:dev"
    if build_step not in action:
        errors.append(
            f"setup-dataplane-host: build step name drifted from {build_step!r}"
        )
    build = action.split(build_step, 1)[-1] if build_step in action else ""
    if BUILDX not in action:
        errors.append(f"setup-dataplane-host: consumer missing {BUILDX}")
    if action.count(GRPCURL_ACTION) != 1:
        errors.append("setup-dataplane-host must consume one grpcurl artifact")
    if "bash .github/scripts/install-grpcurl.sh" in action:
        errors.append("setup-dataplane-host retains legacy grpcurl install")
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

    if texts["interop.yml"].count(GRPCURL_ACTION) != len(INTEROP):
        errors.append("interop.yml: grpcurl consumer inventory drifted")
    if texts["kernel-dataplane.yml"].count(GRPCURL_ACTION) != 0:
        errors.append("kernel-dataplane.yml: grpcurl must flow through host setup")
    grpcurl_surfaces = "\n".join(
        (texts["interop.yml"], texts["kernel-dataplane.yml"], action, grpcurl_action)
    )
    if "bash .github/scripts/install-grpcurl.sh" in grpcurl_surfaces:
        errors.append("legacy grpcurl installer invocation remains")
    if "fullstorydev/grpcurl/releases" in grpcurl_surfaces:
        errors.append("grpcurl release URL escaped the producer helper")

    pins = collections.Counter()
    for text in [*texts.values(), action, grpcurl_action]:
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
        "https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/${archive}",
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
    if re.search(
        r"(?:@latest|releases/(?:latest|download/latest)|GOBGP_VERSION=latest)", gobgp
    ):
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
