#!/usr/bin/env python3
"""Fail closed when the shared CI image-primer contract drifts."""

from __future__ import annotations

import collections
import hashlib
import re
import stat
import subprocess
import sys
from pathlib import Path

INTEROP = (
    "m1 m13 m80 m15 m10 m14 m17 m73 m74 m75 m76 m77 m78 m79 m22 "
    "m24 m81 m82 m83 m85 m94 m86 m25 m29 m30 m34 m35 m35b m35c m41 "
    "m44 m54 m55 m56 m45 m57 m63 m64 m26_m27_m28_m59_m91 m92 m84"
).split()
KERNEL = (
    "m36 m37 m37-ip m38 m39 m39b m48 m60 m61 m62 m40 m42 m50 m52 "
    "m58 m53 m51 m43 m47 m69 m70 m65 m71 m72 m66 m67 m68"
).split()
NETNS_MAPPINGS = {
    "link_carrier": ('TEST_BIN="netns_link_carrier"', 'FILTER=""'),
    "ac_gate": ('TEST_BIN="netns_ac_gate"', 'FILTER=""'),
    "nexthop_raw": ('TEST_BIN="netns_nexthop_raw"', 'FILTER=""'),
    "foreign_state_l2": (
        'TEST_BIN="netns_foreign_state"',
        'FILTER="l2_foreign_takeover_row_survives_withdrawal_and_shutdown"',
    ),
    "foreign_state_nhid": (
        'TEST_BIN="netns_foreign_state"',
        'FILTER="nhid_reserved_range_foreign_object_not_clobbered_adopted_or_reaped"',
    ),
    "foreign_state_l3": (
        'TEST_BIN="netns_foreign_state"',
        'FILTER="l3_foreign_takeover_triple_survives_withdrawal_and_shutdown"',
    ),
    "l3_route_event": (
        'TEST_BIN="netns_l3_install"',
        'FILTER="linux_dataplane_route_event_wakes_within_2s"',
    ),
}
NETNS_VRF_SELECTORS = {"foreign_state_l3", "l3_route_event"}
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
GNMIC_SHA256 = "a3ded2f355a615df73900f31b9791f41e796e9c5c63b171e1ce041e8139ee00e"
GNMIC_ARCHIVE = "gnmic_0.46.0_Linux_x86_64.tar.gz"
GNMIC_ARTIFACT = "gnmic-v0.46.0-linux-x86_64"
GNMIC_CACHE_KEY = f"gnmic-v0.46.0-linux-x86_64-{GNMIC_SHA256}"
GNMIC_ACTION = "uses: ./.github/actions/install-gnmic-artifact"
GOBGP_ARCHIVE = f"gobgp_{GOBGP_VERSION}_linux_amd64.tar.gz"
GOBGP_ARTIFACT = f"gobgp-v{GOBGP_VERSION}-linux-amd64"
GOBGP_CACHE_KEY = f"{GOBGP_ARTIFACT}-{GOBGP_CHECKSUMS['amd64']}"
GOBGP_ACTION = "uses: ./.github/actions/stage-gobgp-artifact"
GOBGP_BUILD = (
    "docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop"
)
BIRD3_VERSION = "3.3.1"
BIRD3_SHA256 = "d5a8d651d6184c18252954932bb249dfee1fd213b3665cdd86226ac45edc0190"
BIRD3_ARCHIVE = f"bird-{BIRD3_VERSION}.tar.gz"
BIRD3_ARTIFACT = f"bird3-v{BIRD3_VERSION}-source"
BIRD3_CACHE_KEY = f"{BIRD3_ARTIFACT}-{BIRD3_SHA256}"
BIRD3_ACTION = "uses: ./.github/actions/stage-bird3-artifact"
BIRD3_BUILD = "file: tests/interop/Dockerfile.bird3"
BIRD3_CACHE_SEAMS = (
    "cache-from: type=gha,scope=bird3-tcpao",
    "cache-to: type=gha,mode=max,scope=bird3-tcpao,ignore-error=true",
)

TRIGGER_HASHES = {
    "ci.yml": "65951f4c4d1d6c4d3aae2c33705d14cdc144b3efd8bcc01653049e6d7f2fb5f8",
    "audit.yml": "1829597143324f5361dfdfece50ddeffd6f7d5934b72198f1837fbdf25339fd3",
    "interop.yml": "5a02c2699d26443c537ba1560fd1b16c595498e9148b2f99be975ae79b3b9492",
    "kernel-dataplane.yml": "9e0df830852bce65597b12ac831509f6ecd500a1bcb85417394dac2f1e3c72a9",
}
PERMISSION_HASHES = {
    "ci.yml": "ef1c6c32bd7afe22841015d36a48ee18816a0a8eb0e9a1a0af951ce1ff7cd183",
    "audit.yml": "6f1d70d72bad231d43c575acef6946580e439c879794ed2ea1f4a40340245172",
    "interop.yml": "6f1d70d72bad231d43c575acef6946580e439c879794ed2ea1f4a40340245172",
    "kernel-dataplane.yml": "6f1d70d72bad231d43c575acef6946580e439c879794ed2ea1f4a40340245172",
}
CALL_HASHES = {
    "interop.yml": "59a909cca623733c8407b8bc706443ee54d6a2451169af0f73a81faed8badd6e",
    "kernel-dataplane.yml": "310ed2344bd6ff3f766580f704cc77fec4be0a2103a943e2ad837f497af346c3",
}
PINS = collections.Counter(
    {
        "actions/checkout@v7": 87,
        "dtolnay/rust-toolchain@v1 # stable": 3,
        "Swatinem/rust-cache@v2": 5,
        "dtolnay/rust-toolchain@v1 # 1.95": 2,
        "docker/setup-buildx-action@v4": 45,
        "docker/build-push-action@v7": 46,
        "actions/cache@v6": 7,
        "actions/upload-artifact@v7": 9,
        "actions/download-artifact@v8": 6,
        "rustsec/audit-check@v2.0.0": 1,
        "EmbarkStudios/cargo-deny-action@v2": 1,
    }
)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _installer_executable(root: Path, installer: Path) -> bool:
    """True when the installer is executable where the repo records it.

    The repo property is the git index mode (100755); on-disk group-write
    from umask 002 checkouts is a checkout artifact, not contract drift.
    Outside a git checkout (unittest fixtures) fall back to the on-disk
    executable bits so a genuinely non-executable installer still fails.
    """
    proc = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-s",
            "--",
            installer.relative_to(root).as_posix(),
        ],
        capture_output=True,
        text=True,
    )
    fields = proc.stdout.split()
    if proc.returncode == 0 and fields:
        return fields[0] == "100755"
    mode = stat.S_IMODE(installer.stat().st_mode)
    return mode & 0o111 == 0o111


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
    elif not _installer_executable(root, grpcurl_installer):
        errors.append("install-grpcurl.sh must be executable (git index mode 100755)")
    gnmic_installer = root / ".github" / "scripts" / "install-gnmic.sh"
    if not gnmic_installer.is_file():
        errors.append("install-gnmic.sh is missing")
    elif not _installer_executable(root, gnmic_installer):
        errors.append("install-gnmic.sh must be executable (git index mode 100755)")
    gnmic_installer_text = (
        gnmic_installer.read_text() if gnmic_installer.is_file() else ""
    )
    for seam in (
        'readonly GNMIC_VERSION="0.46.0"',
        f'readonly GNMIC_SHA256="{GNMIC_SHA256}"',
        'readonly GNMIC_ASSET="gnmic_${GNMIC_VERSION}_Linux_x86_64.tar.gz"',
        "https://github.com/openconfig/gnmic/releases/download/v${GNMIC_VERSION}/${GNMIC_ASSET}",
        "readonly GNMIC_ATTEMPTS=3",
        "curl -fsSL",
        "--connect-timeout 10",
        "--max-time 120",
        "--prepare-archive",
        "--install-archive",
        "--self-test",
    ):
        if seam not in gnmic_installer_text:
            errors.append(f"install-gnmic.sh missing {seam}")
    if gnmic_installer_text.count("openconfig/gnmic/releases/download/") != 1:
        errors.append("install-gnmic.sh release URL inventory drifted")
    if re.search(r"curl[^\n]*\|\s*(?:sudo\s+)?tar", gnmic_installer_text):
        errors.append("install-gnmic.sh streams network bytes into tar")
    gobgp_installer = root / ".github" / "scripts" / "install-gobgp.sh"
    if not gobgp_installer.is_file():
        errors.append("install-gobgp.sh is missing")
    elif not _installer_executable(root, gobgp_installer):
        errors.append("install-gobgp.sh must be executable (git index mode 100755)")
    gobgp_installer_text = (
        gobgp_installer.read_text() if gobgp_installer.is_file() else ""
    )
    for seam in (
        f'readonly GOBGP_VERSION="{GOBGP_VERSION}"',
        f'readonly GOBGP_SHA256="{GOBGP_CHECKSUMS["amd64"]}"',
        'readonly GOBGP_ASSET="gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz"',
        "https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/${GOBGP_ASSET}",
        "readonly GOBGP_ATTEMPTS=3",
        "curl -fsSL",
        "--connect-timeout 10",
        "--max-time 120",
        "--prepare-archive",
        "--stage-archive",
        "--self-test",
        "unexpected ${binary} version",
    ):
        if seam not in gobgp_installer_text:
            errors.append(f"install-gobgp.sh missing {seam}")
    if gobgp_installer_text.count("osrg/gobgp/releases/download/") != 1:
        errors.append("install-gobgp.sh release URL inventory drifted")
    if re.search(r"curl[^\n]*\|\s*(?:sudo\s+)?tar", gobgp_installer_text):
        errors.append("install-gobgp.sh streams network bytes into tar")
    bird3_installer = root / ".github" / "scripts" / "install-bird3.sh"
    if not bird3_installer.is_file():
        errors.append("install-bird3.sh is missing")
    elif not _installer_executable(root, bird3_installer):
        errors.append("install-bird3.sh must be executable (git index mode 100755)")
    bird3_installer_text = (
        bird3_installer.read_text() if bird3_installer.is_file() else ""
    )
    for seam in (
        f'readonly BIRD3_VERSION="{BIRD3_VERSION}"',
        f'readonly BIRD3_SHA256="{BIRD3_SHA256}"',
        'readonly BIRD3_ASSET="bird-${BIRD3_VERSION}.tar.gz"',
        "https://bird.nic.cz/download/${BIRD3_ASSET}",
        "readonly BIRD3_ATTEMPTS=3",
        "curl -fsSL",
        "--connect-timeout 10",
        "--max-time 120",
        "--prepare-archive",
        "--stage-archive",
        "--self-test",
        "unexpected bird3 source version",
    ):
        if seam not in bird3_installer_text:
            errors.append(f"install-bird3.sh missing {seam}")
    if bird3_installer_text.count("bird.nic.cz/download/") != 1:
        errors.append("install-bird3.sh download URL inventory drifted")
    if re.search(r"curl[^\n]*\|\s*(?:sudo\s+)?tar", bird3_installer_text):
        errors.append("install-bird3.sh streams network bytes into tar")
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
        artifact_jobs = (
            ["grpcurl_archive"]
            + ([] if setup else ["gnmic_archive"])
            + ["gobgp_archive"]
            + (["bird3_archive"] if setup else [])
        )
        gobgp_consumers = (
            {"m65", "m71", "m72"} if setup else {"m74", "m75", "m81", "m82", "m83"}
        )
        expected = [
            "classify_changes",
            *artifact_jobs,
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
        if not setup:
            gnmic_producer = jobs.get("gnmic_archive", "")
            for seam in (CLASSIFIER_NEEDS, CLASSIFIER_IF):
                if not _has_line(gnmic_producer, f"    {seam}"):
                    errors.append(f"{name}:gnmic_archive missing job-level {seam}")
            for seam in (
                "name: Prepare exact gnmic archive",
                "runs-on: ubuntu-latest",
                "timeout-minutes: 10",
                CHECKOUT,
                "ref: ${{ github.sha }}",
                "uses: actions/cache@v6",
                f"path: ${{{{ runner.temp }}}}/gnmic-cache/{GNMIC_ARCHIVE}",
                f"key: {GNMIC_CACHE_KEY}",
                "--prepare-archive",
                f'"$RUNNER_TEMP/gnmic-cache/{GNMIC_ARCHIVE}"',
                "uses: actions/upload-artifact@v7",
                f"name: {GNMIC_ARTIFACT}",
                "if-no-files-found: error",
                "retention-days: 1",
                "compression-level: 0",
            ):
                if seam not in gnmic_producer:
                    errors.append(f"{name}:gnmic_archive missing {seam}")
            for forbidden in (
                "restore-keys:",
                "continue-on-error:",
                "actions/download-artifact@",
                "--install-archive",
            ):
                if forbidden in gnmic_producer:
                    errors.append(f"{name}:gnmic_archive permits {forbidden}")
            if gnmic_producer.count("uses: actions/cache@v6") != 1:
                errors.append(f"{name}:gnmic_archive must restore one exact cache")
            if gnmic_producer.count("uses: actions/upload-artifact@v7") != 1:
                errors.append(f"{name}:gnmic_archive must upload one artifact")
            exact_gnmic_path = (
                f"path: ${{{{ runner.temp }}}}/gnmic-cache/{GNMIC_ARCHIVE}"
            )
            if gnmic_producer.count(exact_gnmic_path) != 2:
                errors.append(f"{name}:gnmic_archive cache/artifact paths drifted")
        gobgp_producer = jobs.get("gobgp_archive", "")
        for seam in (CLASSIFIER_NEEDS, CLASSIFIER_IF):
            if not _has_line(gobgp_producer, f"    {seam}"):
                errors.append(f"{name}:gobgp_archive missing job-level {seam}")
        for seam in (
            "name: Prepare exact gobgp archive",
            "runs-on: ubuntu-latest",
            "timeout-minutes: 10",
            CHECKOUT,
            "ref: ${{ github.sha }}",
            "uses: actions/cache@v6",
            f"path: ${{{{ runner.temp }}}}/gobgp-cache/{GOBGP_ARCHIVE}",
            f"key: {GOBGP_CACHE_KEY}",
            "--prepare-archive",
            f'"$RUNNER_TEMP/gobgp-cache/{GOBGP_ARCHIVE}"',
            "uses: actions/upload-artifact@v7",
            f"name: {GOBGP_ARTIFACT}",
            "if-no-files-found: error",
            "retention-days: 1",
            "compression-level: 0",
        ):
            if seam not in gobgp_producer:
                errors.append(f"{name}:gobgp_archive missing {seam}")
        for forbidden in (
            "restore-keys:",
            "continue-on-error:",
            "actions/download-artifact@",
            "--stage-archive",
        ):
            if forbidden in gobgp_producer:
                errors.append(f"{name}:gobgp_archive permits {forbidden}")
        if gobgp_producer.count("uses: actions/cache@v6") != 1:
            errors.append(f"{name}:gobgp_archive must restore one exact cache")
        if gobgp_producer.count("--prepare-archive") != 1:
            errors.append(f"{name}:gobgp_archive must prepare one archive")
        if gobgp_producer.count("uses: actions/upload-artifact@v7") != 1:
            errors.append(f"{name}:gobgp_archive must upload one artifact")
        exact_gobgp_path = (
            f"path: ${{{{ runner.temp }}}}/gobgp-cache/{GOBGP_ARCHIVE}"
        )
        if gobgp_producer.count(exact_gobgp_path) != 2:
            errors.append(f"{name}:gobgp_archive cache/artifact paths drifted")
        if setup:
            bird3_producer = jobs.get("bird3_archive", "")
            for seam in (CLASSIFIER_NEEDS, CLASSIFIER_IF):
                if not _has_line(bird3_producer, f"    {seam}"):
                    errors.append(f"{name}:bird3_archive missing job-level {seam}")
            for seam in (
                "name: Prepare exact bird3 archive",
                "runs-on: ubuntu-latest",
                "timeout-minutes: 10",
                CHECKOUT,
                "ref: ${{ github.sha }}",
                "uses: actions/cache@v6",
                f"path: ${{{{ runner.temp }}}}/bird3-cache/{BIRD3_ARCHIVE}",
                f"key: {BIRD3_CACHE_KEY}",
                "--prepare-archive",
                f'"$RUNNER_TEMP/bird3-cache/{BIRD3_ARCHIVE}"',
                "uses: actions/upload-artifact@v7",
                f"name: {BIRD3_ARTIFACT}",
                "if-no-files-found: error",
                "retention-days: 1",
                "compression-level: 0",
            ):
                if seam not in bird3_producer:
                    errors.append(f"{name}:bird3_archive missing {seam}")
            for forbidden in (
                "restore-keys:",
                "continue-on-error:",
                "actions/download-artifact@",
                "--stage-archive",
            ):
                if forbidden in bird3_producer:
                    errors.append(f"{name}:bird3_archive permits {forbidden}")
            if bird3_producer.count("uses: actions/cache@v6") != 1:
                errors.append(f"{name}:bird3_archive must restore one exact cache")
            if bird3_producer.count("--prepare-archive") != 1:
                errors.append(f"{name}:bird3_archive must prepare one archive")
            if bird3_producer.count("uses: actions/upload-artifact@v7") != 1:
                errors.append(f"{name}:bird3_archive must upload one artifact")
            exact_bird3_path = (
                f"path: ${{{{ runner.temp }}}}/bird3-cache/{BIRD3_ARCHIVE}"
            )
            if bird3_producer.count(exact_bird3_path) != 2:
                errors.append(f"{name}:bird3_archive cache/artifact paths drifted")
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
            if not setup and job_name in ("m54", "m56"):
                expected_needs = (
                    "    needs: [grpcurl_archive, gnmic_archive, prime_dev_image]"
                )
            elif setup and job_name == "m43":
                expected_needs = (
                    "    needs: [grpcurl_archive, bird3_archive, prime_dev_image]"
                )
            elif job_name in gobgp_consumers:
                expected_needs = (
                    "    needs: [grpcurl_archive, gobgp_archive, prime_dev_image]"
                )
            else:
                expected_needs = "    needs: [grpcurl_archive, prime_dev_image]"
            if not _has_line(job, expected_needs):
                errors.append(
                    f"{name}:{job_name}: missing exact artifact/primer dependencies"
                )
            expected_gobgp = 1 if job_name in gobgp_consumers else 0
            if job.count(GOBGP_ACTION) != expected_gobgp:
                errors.append(f"{name}:{job_name}: gobgp stage consumer drifted")
            if job.count(GOBGP_BUILD) != expected_gobgp:
                errors.append(
                    f"{name}:{job_name}: gobgp:interop build inventory drifted"
                )
            if expected_gobgp and not (
                0 <= job.find(GOBGP_ACTION) < job.find(GOBGP_BUILD)
            ):
                errors.append(
                    f"{name}:{job_name}: gobgp build precedes the staged artifact"
                )
            expected_bird3 = 1 if setup and job_name == "m43" else 0
            if job.count(BIRD3_ACTION) != expected_bird3:
                errors.append(f"{name}:{job_name}: bird3 stage consumer drifted")
            if job.count(BIRD3_BUILD) != expected_bird3:
                errors.append(
                    f"{name}:{job_name}: bird3 image build inventory drifted"
                )
            if expected_bird3 and not (
                0 <= job.find(BIRD3_ACTION) < job.find(BIRD3_BUILD)
            ):
                errors.append(
                    f"{name}:{job_name}: bird3 build precedes the staged artifact"
                )
            if expected_bird3:
                for seam in BIRD3_CACHE_SEAMS:
                    if seam not in job:
                        errors.append(
                            f"{name}:{job_name}: bird3 buildx layer cache missing {seam}"
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
                expected_gnmic = 1 if job_name in ("m54", "m56") else 0
                if job.count(GNMIC_ACTION) != expected_gnmic:
                    errors.append(f"{name}:{job_name}: gnmic consumer drifted")
        aggregate = jobs.get("check", "")
        aggregate_needs = [
            "classify_changes",
            *artifact_jobs,
            "prime_dev_image",
            *heavy,
        ]
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
    harness_path = root / "crates/evpn-linux/tests/docker/run-netns-tests.sh"
    harness = harness_path.read_text() if harness_path.is_file() else ""
    harness_missing = not harness
    if harness_missing:
        errors.append("netns harness is missing")
    docker_args = re.search(r"(?ms)^DOCKER_ARGS=\(\n(.*?)^\)\n", harness)
    netns_env = re.findall(r"(?m)^\s*-e\s+(EVPN_LINUX_NETNS=\S+)\s*$", docker_args.group(1)) if docker_args else []
    if not harness_missing and (
        harness.count("-e EVPN_LINUX_NETNS=1") != 1
        or not docker_args
        or netns_env != ["EVPN_LINUX_NETNS=1"]
    ):
        errors.append("netns harness must export EVPN_LINUX_NETNS=1 exactly once")
    steps = re.split(r"(?m)(?=^      - name: )", netns)
    for selector, mapping in NETNS_MAPPINGS.items():
        case = re.search(rf"(?m)^    {re.escape(selector)}\)(.*?) ;;$", harness)
        segments = [part.strip() for part in case.group(1).split(";")] if case else []
        if not harness_missing and segments != list(mapping):
            errors.append(f"netns harness mapping drifted for {selector}")
        command = f"run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh {selector}"
        matched = [step for step in steps if _has_line(step, f"        {command}")]
        if len(matched) != 1:
            errors.append(f"kernel-dataplane.yml:netns must invoke {selector} once")
            continue
        gated = _has_line(
            matched[0], "        if: steps.vrf.outputs.vrf-available == 'true'"
        )
        if gated != (selector in NETNS_VRF_SELECTORS):
            errors.append(f"kernel-dataplane.yml:netns {selector} VRF gate drifted")
    receipt_seams = (
        'receipt="$RUNNER_TEMP/netns-selector-receipt.log"',
        ': > "$receipt"',
        "printf 'NETNS_SELECTOR_RECEIPT=%s\\n' \"$receipt\" >> \"$GITHUB_ENV\"",
        "if: always()\n        env:\n          VRF_AVAILABLE:",
        "python3 scripts/check_netns_selector_receipt.py",
        '--vrf-available "${VRF_AVAILABLE:-false}"',
        'cat "$RUNNER_TEMP/netns-selector-summary.md" >> "$GITHUB_STEP_SUMMARY"',
        "uses: actions/upload-artifact@v7",
        "name: netns-selector-receipt",
        "path: ${{ runner.temp }}/netns-selector-receipt.json",
        "if-no-files-found: error",
    )
    for seam in receipt_seams:
        if seam not in netns:
            errors.append(f"kernel-dataplane.yml:netns receipt seam drifted: {seam}")
    if netns.count("if: always()") != 2:
        errors.append("kernel-dataplane.yml:netns receipt finalizer and upload must always run")
    if 'printf \'%s\\n\' "$SELECTOR" >> "$NETNS_SELECTOR_RECEIPT"' not in harness:
        errors.append("netns harness must append the successful selector receipt")

    action = (
        root / ".github" / "actions" / "setup-dataplane-host" / "action.yml"
    ).read_text()
    grpcurl_action = (
        root / ".github" / "actions" / "install-grpcurl-artifact" / "action.yml"
    ).read_text()
    gnmic_action = (
        root / ".github" / "actions" / "install-gnmic-artifact" / "action.yml"
    ).read_text()
    gobgp_action = (
        root / ".github" / "actions" / "stage-gobgp-artifact" / "action.yml"
    ).read_text()
    bird3_action = (
        root / ".github" / "actions" / "stage-bird3-artifact" / "action.yml"
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
    for seam in (
        "uses: actions/download-artifact@v8",
        f"name: {GNMIC_ARTIFACT}",
        "path: ${{ runner.temp }}/gnmic-artifact",
        "--install-archive",
        f'"$RUNNER_TEMP/gnmic-artifact/{GNMIC_ARCHIVE}"',
        "/usr/local/bin",
    ):
        if seam not in gnmic_action:
            errors.append(f"install-gnmic-artifact missing {seam}")
    if gnmic_action.count("uses: actions/download-artifact@v8") != 1:
        errors.append("install-gnmic-artifact must download one same-run artifact")
    if gnmic_action.count("--install-archive") != 1:
        errors.append("install-gnmic-artifact must perform one offline install")
    for forbidden in (
        "--prepare-archive",
        "actions/cache@",
        "actions/upload-artifact@",
        "restore-keys:",
        "continue-on-error:",
        "releases/download/",
        "curl ",
    ):
        if forbidden in gnmic_action:
            errors.append(f"install-gnmic-artifact permits {forbidden}")
    for seam in (
        "uses: actions/download-artifact@v8",
        f"name: {GOBGP_ARTIFACT}",
        "path: ${{ runner.temp }}/gobgp-artifact",
        "--stage-archive",
        f'"$RUNNER_TEMP/gobgp-artifact/{GOBGP_ARCHIVE}"',
        "tests/interop/gobgp-archive",
    ):
        if seam not in gobgp_action:
            errors.append(f"stage-gobgp-artifact missing {seam}")
    if gobgp_action.count("uses: actions/download-artifact@v8") != 1:
        errors.append("stage-gobgp-artifact must download one same-run artifact")
    if gobgp_action.count("--stage-archive") != 1:
        errors.append("stage-gobgp-artifact must perform one offline stage")
    for forbidden in (
        "--prepare-archive",
        "actions/cache@",
        "actions/upload-artifact@",
        "restore-keys:",
        "continue-on-error:",
        "releases/download/",
        "curl ",
    ):
        if forbidden in gobgp_action:
            errors.append(f"stage-gobgp-artifact permits {forbidden}")
    for seam in (
        "uses: actions/download-artifact@v8",
        f"name: {BIRD3_ARTIFACT}",
        "path: ${{ runner.temp }}/bird3-artifact",
        "--stage-archive",
        f'"$RUNNER_TEMP/bird3-artifact/{BIRD3_ARCHIVE}"',
        "tests/interop/bird3-archive",
    ):
        if seam not in bird3_action:
            errors.append(f"stage-bird3-artifact missing {seam}")
    if bird3_action.count("uses: actions/download-artifact@v8") != 1:
        errors.append("stage-bird3-artifact must download one same-run artifact")
    if bird3_action.count("--stage-archive") != 1:
        errors.append("stage-bird3-artifact must perform one offline stage")
    for forbidden in (
        "--prepare-archive",
        "actions/cache@",
        "actions/upload-artifact@",
        "restore-keys:",
        "continue-on-error:",
        "bird.nic.cz",
        "curl ",
    ):
        if forbidden in bird3_action:
            errors.append(f"stage-bird3-artifact permits {forbidden}")
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
    if texts["interop.yml"].count(GNMIC_ACTION) != 2:
        errors.append("interop.yml: gnmic consumer inventory drifted")
    if texts["kernel-dataplane.yml"].count(GNMIC_ACTION) != 0:
        errors.append("kernel-dataplane.yml: gnmic must remain interop-only")
    grpcurl_surfaces = "\n".join(
        (texts["interop.yml"], texts["kernel-dataplane.yml"], action, grpcurl_action)
    )
    if "bash .github/scripts/install-grpcurl.sh" in grpcurl_surfaces:
        errors.append("legacy grpcurl installer invocation remains")
    if "fullstorydev/grpcurl/releases" in grpcurl_surfaces:
        errors.append("grpcurl release URL escaped the producer helper")
    gnmic_surfaces = "\n".join((texts["interop.yml"], gnmic_action))
    if "openconfig/gnmic/releases" in gnmic_surfaces:
        errors.append("gnmic release URL escaped the producer helper")
    if re.search(r"curl\s.*gnmic|curl\s.*\|\s*(?:sudo\s+)?tar", gnmic_surfaces):
        errors.append("interop.yml retains a streaming gnmic download")
    if texts["interop.yml"].count(GOBGP_ACTION) != 5:
        errors.append("interop.yml: gobgp stage consumer inventory drifted")
    if texts["kernel-dataplane.yml"].count(GOBGP_ACTION) != 3:
        errors.append("kernel-dataplane.yml: gobgp stage consumer inventory drifted")
    gobgp_surfaces = "\n".join(
        (texts["interop.yml"], texts["kernel-dataplane.yml"], gobgp_action)
    )
    if "osrg/gobgp/releases" in gobgp_surfaces:
        errors.append("gobgp release URL escaped the installer/Dockerfile")
    if texts["interop.yml"].count(BIRD3_ACTION) != 0:
        errors.append("interop.yml: bird3 stage must remain kernel-only")
    if texts["kernel-dataplane.yml"].count(BIRD3_ACTION) != 1:
        errors.append("kernel-dataplane.yml: bird3 stage consumer inventory drifted")
    bird3_surfaces = "\n".join(
        (texts["interop.yml"], texts["kernel-dataplane.yml"], bird3_action)
    )
    if "bird.nic.cz" in bird3_surfaces:
        errors.append("bird.nic.cz URL escaped the installer/Dockerfile")

    pins = collections.Counter()
    for text in [
        *texts.values(),
        action,
        grpcurl_action,
        gnmic_action,
        gobgp_action,
        bird3_action,
    ]:
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
        "COPY gobgp-archive/ /tmp/gobgp-archive/",
        'archive="gobgp_${GOBGP_VERSION}_linux_${TARGETARCH}.tar.gz"',
        '*) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;;',
        'if [ ! -f "/tmp/gobgp-archive/${archive}" ]; then',
        "https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/${archive}",
        'if [ "${attempt}" -ge 3 ]; then',
        'echo "${checksum}  /tmp/gobgp-archive/${archive}" | sha256sum --check --strict',
        'tar --extract --gzip --file "/tmp/gobgp-archive/${archive}" --directory /usr/local/bin gobgp gobgpd',
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

    bird3 = (root / "tests" / "interop" / "Dockerfile.bird3").read_text()
    for seam in (
        f"ARG BIRD_VERSION={BIRD3_VERSION}",
        "COPY bird3-archive/ /tmp/bird3-archive/",
        f'checksum="{BIRD3_SHA256}"',
        'archive="bird-${BIRD_VERSION}.tar.gz"',
        'if [ ! -f "/tmp/bird3-archive/${archive}" ]; then',
        "https://bird.nic.cz/download/bird-${BIRD_VERSION}.tar.gz",
        'if [ "${attempt}" -ge 3 ]; then',
        'echo "${checksum}  /tmp/bird3-archive/${archive}" | sha256sum --check --strict',
        'tar -xzf "/tmp/bird3-archive/${archive}" --strip-components=1',
        "bird --version",
    ):
        if seam not in bird3:
            errors.append(f"Dockerfile.bird3: pinned source seam missing: {seam}")
    if bird3.count("bird.nic.cz") != 1:
        errors.append("Dockerfile.bird3: download URL inventory drifted")
    if not (
        0
        <= bird3.find("sha256sum --check --strict")
        < bird3.find('tar -xzf "/tmp/bird3-archive/${archive}"')
    ):
        errors.append("Dockerfile.bird3: extraction precedes checksum verification")
    if re.search(r"BIRD_VERSION=latest|/download/latest", bird3):
        errors.append("Dockerfile.bird3: floating BIRD release is forbidden")
    return errors


if __name__ == "__main__":
    failures = check(Path(__file__).resolve().parents[1])
    if failures:
        print("CI image-primer contract check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        raise SystemExit(1)
    print("CI image-primer contract OK")
