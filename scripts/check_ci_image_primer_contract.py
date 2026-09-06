#!/usr/bin/env python3
"""Fail closed when the shared CI image-primer contract drifts."""

from __future__ import annotations

import hashlib
import re
import stat
import subprocess
import sys
from pathlib import Path

INTEROP = (
    "m1 m13 m80 m15 m10 m14 m17 m73 m74 m75 m76 m77 m78 m79 m22 "
    "m24 m81 m82 m83 m85 m94 m86 m25 m29 m30 m34 m35 m35b m35c m41 "
    "m44 m54 m55 m56 m45 m57 m63 m64 m26_m27_m28_m59_m91 m92 m84 m99 m100 m101 m102 m103 m104 m107"
).split()
KERNEL = (
    "m36 m37 m37-ip m38 m39 m39b m109 m48 m60 m61 m62 m40 m42 m50 m52 "
    "m58 m53 m51 m108 m43 m47 m69 m70 m65 m71 m72 m66 m67 m68"
).split()
NETNS_MAPPINGS = {
    "dataplane_remote_mac": (
        'TEST_BIN="netns_dataplane"',
        'FILTER="linux_dataplane_programs_remote_mac_with_extern_learn"',
    ),
    "vlan_local_mac_attribution": (
        'TEST_BIN="netns_dataplane"',
        'FILTER="linux_dataplane_attributes_vlan_local_mac_observations"',
    ),
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
    "l3_single_path_cycle": (
        'TEST_BIN="netns_l3_install"',
        'FILTER="linux_dataplane_installs_and_withdraws_l3_triple"',
    ),
    "l3_foreign_route_cycle": (
        'TEST_BIN="netns_l3_install"',
        'FILTER="linux_dataplane_foreign_route_survives_l3_cycle"',
    ),
}
NETNS_VRF_SELECTORS = {
    "foreign_state_l3",
    "l3_route_event",
    "l3_single_path_cycle",
    "l3_foreign_route_cycle",
}
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
PREPARE_GRPCURL_ACTION = "uses: ./.github/actions/prepare-grpcurl-artifact"
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
BIRD3_VERSION = "3.3.2"
BIRD3_SHA256 = "21297d7a02edd700ae82de5a630055a9cb88a99e2e7e45551bc7d6c1e5b4de2c"
BIRD3_ARCHIVE = f"bird-{BIRD3_VERSION}.tar.gz"
BIRD3_ARTIFACT = f"bird3-v{BIRD3_VERSION}-source"
BIRD3_CACHE_KEY = f"{BIRD3_ARTIFACT}-{BIRD3_SHA256}"
BIRD3_ACTION = "uses: ./.github/actions/stage-bird3-artifact"
BIRD3_BUILD = "file: tests/interop/Dockerfile.bird3"
BIRD3_CACHE_SEAMS = (
    "cache-from: type=gha,scope=bird3-tcpao",
    "cache-to: type=gha,mode=max,scope=bird3-tcpao,ignore-error=true",
)
BIRD2192_VERSION = "2.19.2"
BIRD2192_SHA256 = "aff89abba3b92b7637bd57e0168b8d7ae887747f160ada4973378ad72f5f3660"
BIRD2192_ARCHIVE = f"bird-{BIRD2192_VERSION}.tar.gz"
BIRD2192_ARTIFACT = f"bird2192-v{BIRD2192_VERSION}-source"
BIRD2192_CACHE_KEY = f"{BIRD2192_ARTIFACT}-{BIRD2192_SHA256}"
BIRD332_VERSION = "3.3.2"
BIRD332_SHA256 = "21297d7a02edd700ae82de5a630055a9cb88a99e2e7e45551bc7d6c1e5b4de2c"
BIRD332_ARCHIVE = f"bird-{BIRD332_VERSION}.tar.gz"
BIRD332_ARTIFACT = f"bird332-v{BIRD332_VERSION}-source"
BIRD332_CACHE_KEY = BIRD3_CACHE_KEY
BIRD332_CACHE_DIR = "bird3-cache"
FRR1070_IMAGE = (
    "quay.io/frrouting/frr@sha256:"
    "a0ed0e4f8727631c8303dd9a4e8199b47464a17a5253135a2c622286aeaec46b"
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
# External actions are pinned by reviewed version tag: no branch refs and no
# bare commit SHAs. Adding an action or moving to a new major edits this set.
PINS = frozenset(
    {
        "actions/cache@v6",
        "actions/checkout@v7",
        "actions/download-artifact@v8",
        "actions/upload-artifact@v7",
        "docker/build-push-action@v7",
        "docker/setup-buildx-action@v4",
        "dtolnay/rust-toolchain@v1",
        "EmbarkStudios/cargo-deny-action@v2",
        "rustsec/audit-check@v2.0.0",
        "Swatinem/rust-cache@v2",
    }
)
VERSION_TAG = re.compile(r"@v\d+(?:\.\d+){0,2}$")
LAB_CALL = re.compile(
    r"(?ms)^        uses: \./\.github/actions/run-interop-test\n(.*?)(?=^      - |\Z)"
)
LAB_CALL_INPUT = re.compile(r"(?m)^          (label|topology|script): (.+)$")
SETUP_HOST_ACTION = "uses: ./.github/actions/setup-dataplane-host"

GOBGP_PRODUCER_JOB_CONTRACT = (
    "    needs: classify_changes",
    "    if: needs.classify_changes.outputs.run_labs == 'true'",
    "    name: Prepare exact gobgp archive",
    "    runs-on: ubuntu-latest",
    "    timeout-minutes: 10",
    "    steps:",
    "      - uses: actions/checkout@v7",
    "        with:",
    "          ref: ${{ github.sha }}",
    "      - name: Restore, prepare, and upload exact gobgp archive",
    "        uses: ./.github/actions/prepare-gobgp-artifact",
)
PRIME_DEV_IMAGE_JOB_CONTRACT = (
    "    needs: classify_changes",
    "    if: needs.classify_changes.outputs.run_labs == 'true'",
    "    name: Prime rustbgpd:dev build cache",
    "    runs-on: ubuntu-latest",
    "    timeout-minutes: 30",
    "    concurrency:",
    "      group: rustbgpd-dev-image-${{ github.sha }}",
    "      cancel-in-progress: false",
    "    steps:",
    "      - uses: actions/checkout@v7",
    "        with:",
    "          ref: ${{ github.sha }}",
    "      - name: Prime rustbgpd:dev build cache",
    "        uses: ./.github/actions/prime-rustbgpd-dev-cache",
)
PREPARE_GOBGP_ACTION_CONTRACT = (
    'name: "Prepare exact GoBGP artifact"',
    (
        'description: "Restore, verify, and upload the pinned GoBGP archive '
        'for heavy CI lanes."'
    ),
    "runs:",
    '  using: "composite"',
    "  steps:",
    "    - name: Restore exact gobgp archive cache",
    "      uses: actions/cache@v6",
    "      with:",
    f"        path: ${{{{ runner.temp }}}}/gobgp-cache/{GOBGP_ARCHIVE}",
    f"        key: {GOBGP_CACHE_KEY}",
    "    - name: Prepare exact gobgp archive",
    "      shell: bash",
    "      run: |",
    "        .github/scripts/install-gobgp.sh \\",
    "          --prepare-archive \\",
    f'          "$RUNNER_TEMP/gobgp-cache/{GOBGP_ARCHIVE}"',
    "    - name: Upload verified gobgp archive",
    "      uses: actions/upload-artifact@v7",
    "      with:",
    f"        name: {GOBGP_ARTIFACT}",
    f"        path: ${{{{ runner.temp }}}}/gobgp-cache/{GOBGP_ARCHIVE}",
    "        if-no-files-found: error",
    "        retention-days: 1",
    "        compression-level: 0",
)
PRIME_DEV_IMAGE_ACTION_CONTRACT = (
    'name: "Prime rustbgpd:dev build cache"',
    (
        'description: "Warm the fixed heavy-lane image cache without loading '
        'a local image."'
    ),
    "runs:",
    '  using: "composite"',
    "  steps:",
    "    - name: Set up Docker Buildx",
    "      uses: docker/setup-buildx-action@v4",
    "    - name: Prime rustbgpd:dev build cache",
    "      uses: docker/build-push-action@v7",
    "      with:",
    "        context: .",
    "        load: false",
    "        tags: rustbgpd:dev",
    "        target: dev",
    "        cache-from: type=gha,scope=rustbgpd-dev",
    "        cache-to: type=gha,scope=rustbgpd-dev,mode=max,ignore-error=true",
)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _canonical_yaml_contract(text: str) -> tuple[str, ...]:
    """Return behavior-bearing YAML lines with exact order and indentation."""
    return tuple(
        line.rstrip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


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


def _lab_token(label: str) -> str:
    """Scenario token of a lab label: ``M37+IP`` -> ``m37``, ``M43 crash-restart`` -> ``m43``."""
    return re.split(r"[ +-]", label, maxsplit=1)[0].lower()


def _check_lab_calls(name: str, job_name: str, job: str, errors: list[str]) -> None:
    """Every lab job drives its own scenarios through complete run-interop-test calls."""
    prefix = f"{name}:{job_name}"
    calls = LAB_CALL.findall(job)
    if not calls:
        errors.append(f"{prefix}: has no run-interop-test call")
        return
    labels: set[str] = set()
    for call in calls:
        inputs = dict(LAB_CALL_INPUT.findall(call))
        missing = [key for key in ("label", "topology", "script") if key not in inputs]
        if missing:
            errors.append(f"{prefix}: run-interop-test call missing {', '.join(missing)}")
            return
        label = inputs["label"]
        # A space starts a descriptive suffix (``M43 crash-restart``); ``+`` and ``-``
        # join scenario variants (``M37+IP`` is the m37-ip job's own identifier).
        labels.add(label.split(" ", 1)[0].replace("+", "-").upper())
        token = _lab_token(label)
        if not inputs["topology"].startswith(f"tests/interop/{token}-"):
            errors.append(f"{prefix}: {label} topology drifted: {inputs['topology']}")
        if not inputs["script"].startswith(f"tests/interop/scripts/test-{token}-"):
            errors.append(f"{prefix}: {label} script drifted: {inputs['script']}")
    for token in job_name.split("_"):
        if token.upper() not in labels:
            errors.append(f"{prefix}: no run-interop-test call labelled {token.upper()}")


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
        f'BIRD3_VERSION="{BIRD3_VERSION}"',
        f'BIRD3_SHA256="{BIRD3_SHA256}"',
        "--version",
        "--sha256",
        "--coverage-label",
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

    consumer = ci_jobs.get("core_tests", "")
    for seam in (
        "needs: v064_validator",
        "uses: actions/download-artifact@v8",
        f"name: {V064_ARTIFACT}",
        "path: ${{ runner.temp }}/rustbgpd-v064-artifact",
        "--install-archive",
        f'"$RUNNER_TEMP/rustbgpd-v064-artifact/{V064_ARCHIVE}"',
        '"$RUNNER_TEMP/rustbgpd-v064"',
    ):
        if seam not in consumer:
            errors.append(f"ci.yml:core_tests missing validator seam {seam}")
    if consumer.count("uses: actions/download-artifact@v8") != 1:
        errors.append("ci.yml:core_tests must download one validator artifact")
    for forbidden in (
        "--prepare-archive",
        "actions/cache@",
        "actions/upload-artifact@",
        "releases/download/v0.64.0",
        "restore-keys:",
        "continue-on-error:",
    ):
        if forbidden in consumer:
            errors.append(f"ci.yml:core_tests validator consumer permits {forbidden}")

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
            + ([] if setup else ["bird2192_archive", "bird332_archive"])
            + (["bird3_archive"] if setup else [])
        )
        gobgp_consumers = (
            {"m65", "m71", "m72"} if setup else {"m74", "m75", "m81", "m82"}
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
            "name: Restore, prepare, and upload exact grpcurl archive",
            PREPARE_GRPCURL_ACTION,
        ):
            if seam not in grpcurl_producer:
                errors.append(f"{name}:grpcurl_archive missing {seam}")
        for forbidden in (
            "restore-keys:",
            "continue-on-error:",
            "actions/download-artifact@",
            "actions/cache@",
            "actions/upload-artifact@",
            "--prepare-archive",
            "--install-archive",
        ):
            if forbidden in grpcurl_producer:
                errors.append(f"{name}:grpcurl_archive permits {forbidden}")
        producer_uses = re.findall(
            r"(?m)^\s*(?:- )?uses:\s*(.+)$", grpcurl_producer
        )
        if producer_uses != [
            "actions/checkout@v7",
            "./.github/actions/prepare-grpcurl-artifact",
        ]:
            errors.append(f"{name}:grpcurl_archive action inventory drifted")
        if grpcurl_producer.count(PREPARE_GRPCURL_ACTION) != 1:
            errors.append(
                f"{name}:grpcurl_archive must call one exact producer action"
            )
        producer_call_tail = grpcurl_producer.split(PREPARE_GRPCURL_ACTION, 1)[-1]
        if "with:" in producer_call_tail:
            errors.append(f"{name}:grpcurl_archive producer call must have no inputs")
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
        if (
            _canonical_yaml_contract(gobgp_producer)
            != GOBGP_PRODUCER_JOB_CONTRACT
        ):
            errors.append(f"{name}:gobgp_archive exact job contract drifted")
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
        else:
            bird_producers = (
                (
                    "bird2192_archive",
                    "BIRD 2.19.2",
                    BIRD2192_VERSION,
                    BIRD2192_SHA256,
                    BIRD2192_ARCHIVE,
                    BIRD2192_ARTIFACT,
                    BIRD2192_CACHE_KEY,
                    "bird2192-cache",
                    "M83 BIRD 2.19.2 image blocked",
                ),
                (
                    "bird332_archive",
                    "BIRD 3.3.2",
                    BIRD332_VERSION,
                    BIRD332_SHA256,
                    BIRD332_ARCHIVE,
                    BIRD332_ARTIFACT,
                    BIRD332_CACHE_KEY,
                    BIRD332_CACHE_DIR,
                    "M101 BIRD 3.3.2 image blocked",
                ),
            )
            for (
                producer_name,
                display,
                version,
                checksum,
                archive,
                artifact,
                cache_key,
                cache_dir,
                coverage_label,
            ) in bird_producers:
                producer = jobs.get(producer_name, "")
                exact_path = (
                    f"path: ${{{{ runner.temp }}}}/{cache_dir}/{archive}"
                )
                for seam in (CLASSIFIER_NEEDS, CLASSIFIER_IF):
                    if not _has_line(producer, f"    {seam}"):
                        errors.append(
                            f"interop.yml:{producer_name} missing job-level {seam}"
                        )
                for seam in (
                    f"name: Prepare exact {display} archive",
                    "runs-on: ubuntu-latest",
                    "timeout-minutes: 10",
                    CHECKOUT,
                    "ref: ${{ github.sha }}",
                    "uses: actions/cache@v6",
                    exact_path,
                    f"key: {cache_key}",
                    f"--version {version}",
                    f"--sha256 {checksum}",
                    f'--coverage-label "{coverage_label}"',
                    "--prepare-archive",
                    f'"$RUNNER_TEMP/{cache_dir}/{archive}"',
                    "uses: actions/upload-artifact@v7",
                    f"name: {artifact}",
                    "if-no-files-found: error",
                    "retention-days: 1",
                    "compression-level: 0",
                ):
                    if seam not in producer:
                        errors.append(f"interop.yml:{producer_name} missing {seam}")
                for forbidden in (
                    "restore-keys:",
                    "continue-on-error:",
                    "actions/download-artifact@",
                    "--stage-archive",
                ):
                    if forbidden in producer:
                        errors.append(
                            f"interop.yml:{producer_name} permits {forbidden}"
                        )
                if producer.count("uses: actions/cache@v6") != 1:
                    errors.append(
                        f"interop.yml:{producer_name} must restore one exact cache"
                    )
                if producer.count("--prepare-archive") != 1:
                    errors.append(
                        f"interop.yml:{producer_name} must prepare one archive"
                    )
                if producer.count("uses: actions/upload-artifact@v7") != 1:
                    errors.append(
                        f"interop.yml:{producer_name} must upload one artifact"
                    )
                if producer.count(exact_path) != 2:
                    errors.append(
                        f"interop.yml:{producer_name} cache/artifact paths drifted"
                    )
        primer = jobs.get("prime_dev_image", "")
        if (
            _canonical_yaml_contract(primer)
            != PRIME_DEV_IMAGE_JOB_CONTRACT
        ):
            errors.append(f"{name}: primer exact job contract drifted")
        for job_name in roster:
            job = jobs.get(job_name, "")
            if not setup and job_name == "m100":
                expected_needs = "    needs: [grpcurl_archive, bird2192_archive]"
            elif not setup and job_name in ("m83", "m85", "m104"):
                expected_needs = (
                    "    needs: [grpcurl_archive, bird2192_archive, prime_dev_image]"
                )
            elif not setup and job_name == "m101":
                expected_needs = (
                    "    needs: [grpcurl_archive, bird332_archive, prime_dev_image]"
                )
            elif not setup and job_name in ("m54", "m56"):
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
            bird_contracts = (
                {
                    "m43": (
                        "file: tests/interop/Dockerfile.bird3",
                        BIRD3_CACHE_SEAMS,
                        ("name: Stage verified BIRD 3 archive",),
                    )
                }
                if setup
                else {
                    "m83": (
                        "file: tests/interop/Dockerfile.bird-v2192",
                        (
                            "cache-from: type=gha,scope=bird2192-m83",
                            "cache-to: type=gha,mode=max,scope=bird2192-m83,ignore-error=true",
                        ),
                        (
                            "name: Stage verified BIRD 2.19.2 archive",
                            'version: "2.19.2"',
                            f"sha256: {BIRD2192_SHA256}",
                            f"artifact-name: {BIRD2192_ARTIFACT}",
                        ),
                    ),
                    "m100": (
                        "file: tests/interop/Dockerfile.bird-v2192",
                        (
                            "cache-from: type=gha,scope=bird2192-m100",
                            "cache-to: type=gha,mode=max,scope=bird2192-m100,ignore-error=true",
                        ),
                        (
                            "name: Stage verified BIRD 2.19.2 archive",
                            'version: "2.19.2"',
                            f"sha256: {BIRD2192_SHA256}",
                            f"artifact-name: {BIRD2192_ARTIFACT}",
                        ),
                    ),
                    "m85": (
                        "file: tests/interop/Dockerfile.bird-v2192",
                        (
                            "cache-from: type=gha,scope=bird2192-m85",
                            "cache-to: type=gha,mode=max,scope=bird2192-m85,ignore-error=true",
                        ),
                        (
                            "name: Stage verified BIRD 2.19.2 archive",
                            'version: "2.19.2"',
                            f"sha256: {BIRD2192_SHA256}",
                            f"artifact-name: {BIRD2192_ARTIFACT}",
                        ),
                    ),
                    "m101": (
                        "file: tests/interop/Dockerfile.bird-v332",
                        (
                            "cache-from: type=gha,scope=bird332-m101",
                            "cache-to: type=gha,mode=max,scope=bird332-m101,ignore-error=true",
                        ),
                        (
                            "name: Stage verified BIRD 3.3.2 archive",
                            'version: "3.3.2"',
                            f"sha256: {BIRD332_SHA256}",
                            f"artifact-name: {BIRD332_ARTIFACT}",
                        ),
                    ),
                    "m104": (
                        "file: tests/interop/Dockerfile.bird-v2192",
                        (
                            "cache-from: type=gha,scope=bird2192-m104",
                            "cache-to: type=gha,mode=max,scope=bird2192-m104,ignore-error=true",
                        ),
                        (
                            "name: Stage verified BIRD 2.19.2 archive",
                            'version: "2.19.2"',
                            f"sha256: {BIRD2192_SHA256}",
                            f"artifact-name: {BIRD2192_ARTIFACT}",
                        ),
                    ),
                }
            )
            expected_bird3 = 1 if job_name in bird_contracts else 0
            if job.count(BIRD3_ACTION) != expected_bird3:
                errors.append(f"{name}:{job_name}: bird3 stage consumer drifted")
            if expected_bird3:
                bird_build, cache_seams, action_inputs = bird_contracts[job_name]
                if job.count(bird_build) != 1:
                    errors.append(
                        f"{name}:{job_name}: bird image build inventory drifted"
                    )
                if not (0 <= job.find(BIRD3_ACTION) < job.find(bird_build)):
                    errors.append(
                        f"{name}:{job_name}: bird build precedes the staged artifact"
                    )
                for seam in (*cache_seams, *action_inputs):
                    if seam not in job:
                        errors.append(
                            f"{name}:{job_name}: bird artifact/build seam missing {seam}"
                        )
                expected_build_push = 1 if setup or job_name == "m100" else 2
                if job.count(BUILD_PUSH) != expected_build_push:
                    errors.append(
                        f"{name}:{job_name}: build-push-action inventory drifted"
                    )
            if not setup and job_name == "m76":
                m76_required = {
                    "needs: [grpcurl_archive, prime_dev_image]": 1,
                    "name: M76 — ORR divergent-best (GoBGP 4.8.0)": 1,
                    "name: Build gobgp:v4.8.0-m76": 1,
                    "--build-arg TARGETARCH=amd64": 1,
                    "--build-arg GOBGP_VERSION=4.8.0": 1,
                    "--build-arg GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03": 1,
                    "-t gobgp:v4.8.0-m76 -f tests/interop/Dockerfile.gobgp-v47 tests/interop": 1,
                    "name: Run M76 (deploy + test + destroy with retry)": 1,
                    "topology: tests/interop/m76-orr-divergent-best-gobgp.clab.yml": 1,
                    "script: tests/interop/scripts/test-m76-orr-divergent-best-gobgp.sh": 1,
                }
                if any(job.count(seam) != count for seam, count in m76_required.items()):
                    errors.append("interop.yml:m76: exact GoBGP 4.8.0 job contract drifted")
                for forbidden in (
                    "GoBGP 4.6.0",
                    "gobgp:bgpls",
                    "Dockerfile.gobgp-bgpls",
                ):
                    if forbidden in job:
                        errors.append(f"interop.yml:m76: permits historical peer seam {forbidden}")
            if not setup and job_name == "m77":
                m77_required = {
                    "needs: [grpcurl_archive, prime_dev_image]": 1,
                    "name: M77 — VPNv4/VPNv6/RTC GR+LLGR + BGP-LS GR (GoBGP 4.8.0)": 1,
                    "name: Build gobgp:v4.8.0-m77": 1,
                    "--build-arg TARGETARCH=amd64": 1,
                    "--build-arg GOBGP_VERSION=4.8.0": 1,
                    "--build-arg GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03": 1,
                    "-t gobgp:v4.8.0-m77 -f tests/interop/Dockerfile.gobgp-v47 tests/interop": 1,
                    "name: Run M77 (deploy + test + destroy with retry)": 1,
                    "topology: tests/interop/m77-gr-llgr-rr-gobgp.clab.yml": 1,
                    "script: tests/interop/scripts/test-m77-gr-llgr-rr-gobgp.sh": 1,
                }
                if any(job.count(seam) != count for seam, count in m77_required.items()):
                    errors.append("interop.yml:m77: exact GoBGP 4.8.0 job contract drifted")
                for forbidden in (
                    "GoBGP 4.6.0",
                    "gobgp:bgpls",
                    "Dockerfile.gobgp-bgpls",
                ):
                    if forbidden in job:
                        errors.append(f"interop.yml:m77: permits historical peer seam {forbidden}")
            if not setup and job_name == "m83":
                m83_required = {
                    "needs: [grpcurl_archive, bird2192_archive, prime_dev_image]": 1,
                    "name: M83 — route-server profile, multi-stack (BIRD 2.19.2 + GoBGP 4.8.0 + FRR 10.7.0 + RTR)": 1,
                    "tags: bird:v2.19.2-m83": 1,
                    "--build-arg GOBGP_VERSION=4.8.0": 1,
                    "--build-arg GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03": 1,
                    "-t gobgp:v4.8.0-m83 -f tests/interop/Dockerfile.gobgp-v47 tests/interop": 1,
                    "name: Pull digest-pinned FRR 10.7.0 image": 1,
                    f"run: docker pull {FRR1070_IMAGE}": 1,
                }
                if any(job.count(seam) != count for seam, count in m83_required.items()):
                    errors.append("interop.yml:m83: exact incumbent image contract drifted")
            if not setup and job_name == "m85":
                m85_required = {
                    "needs: [grpcurl_archive, bird2192_archive, prime_dev_image]": 1,
                    "name: M85/M93/M95 — RR core, required families, and RFC 8212 presence transitions against BIRD 2.19.2": 1,
                    "name: Build bird:v2.19.2-m85": 1,
                    "tags: bird:v2.19.2-m85": 1,
                    "label: M85\n": 1,
                    "topology: tests/interop/m85-rr-bird.clab.yml": 1,
                    "script: tests/interop/scripts/test-m85-rr-bird.sh": 1,
                    "label: M93\n": 1,
                    "topology: tests/interop/m93-required-families-bird.clab.yml": 1,
                    "script: tests/interop/scripts/test-m93-required-families-bird.sh": 1,
                    "label: M95\n": 1,
                    "topology: tests/interop/m95-rfc8212-presence-frr-bird.clab.yml": 1,
                    "script: tests/interop/scripts/test-m95-rfc8212-presence.sh": 1,
                }
                if any(job.count(seam) != count for seam, count in m85_required.items()):
                    errors.append("interop.yml:m85: exact BIRD 2.19.2 job semantics drifted")
                for forbidden in (
                    "bird:2-bookworm",
                    "Dockerfile.bird tests/interop",
                    "BIRD 2.0.12",
                ):
                    if forbidden in job:
                        errors.append(f"interop.yml:m85: permits {forbidden}")
            if CHECKOUT not in job:
                errors.append(f"{name}:{job_name}: pinned checkout drifted")
            _check_lab_calls(name, job_name, job, errors)
            if setup:
                if job.count(SETUP_HOST_ACTION) != 1:
                    errors.append(f"{name}:{job_name}: setup call drifted")
                if GRPCURL_ACTION in job:
                    errors.append(f"{name}:{job_name}: bypasses shared host setup")
            else:
                if SETUP_HOST_ACTION in job:
                    errors.append(f"{name}:{job_name}: kernel host setup in interop lab")
                if job.count(GRPCURL_ACTION) != 1:
                    errors.append(
                        f"{name}:{job_name}: must consume one grpcurl artifact"
                    )
                if job_name == "m100":
                    for seam in (
                        "prime_dev_image",
                        "rustbgpd:dev",
                        "scope=rustbgpd-dev",
                        "target: dev",
                    ):
                        if seam in job:
                            errors.append(f"{name}:{job_name}: release lane permits {seam}")
                else:
                    for seam in (
                        IMPORT,
                        "load: true",
                        "tags: rustbgpd:dev",
                        "target: dev",
                    ):
                        if seam not in job:
                            errors.append(f"{name}:{job_name}: consumer missing {seam}")
                if "cache-to:" in job and job_name not in bird_contracts:
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
    m99 = _jobs(texts["interop.yml"]).get("m99", "")
    m99_required = {
        GRPCURL_ACTION: 1,
        "name: Ensure host raw-capture tools": 1,
        "if ! command -v tshark >/dev/null || ! command -v nsenter >/dev/null": 1,
        "|| ! command -v jq >/dev/null": 1,
        "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y tshark util-linux jq": 1,
        "tshark --version": 1,
        "nsenter --version": 1,
        "uses: ./.github/actions/run-interop-test": 1,
        "label: M99\n": 1,
        "topology: tests/interop/m99-rfc9072-extended-open-frr.clab.yml": 1,
        "script: tests/interop/scripts/test-m99-rfc9072-extended-open.sh": 1,
        'max_attempts: "1"': 1,
    }
    if any(m99.count(seam) != count for seam, count in m99_required.items()):
        errors.append("interop.yml:m99: RFC 9072 raw-capture job semantics drifted")
    for forbidden in ("continue-on-error:", "docker exec", "max_attempts: \"2\""):
        if forbidden in m99:
            errors.append(f"interop.yml:m99: permits {forbidden}")
    m100 = _jobs(texts["interop.yml"]).get("m100", "")
    m100_required = {
        GRPCURL_ACTION: 1,
        "needs: [grpcurl_archive, bird2192_archive]": 1,
        BIRD3_ACTION: 1,
        'version: "2.19.2"': 1,
        f"sha256: {BIRD2192_SHA256}": 1,
        f"artifact-name: {BIRD2192_ARTIFACT}": 1,
        "name: Build bird:v2.19.2-m100": 1,
        "file: tests/interop/Dockerfile.bird-v2192": 1,
        "tags: bird:v2.19.2-m100": 1,
        "cache-from: type=gha,scope=bird2192-m100": 1,
        "cache-to: type=gha,mode=max,scope=bird2192-m100,ignore-error=true": 1,
        "docker build -t bmpsink:m100 -f tests/interop/Dockerfile.bmpsink tests/interop": 1,
        "docker pull ghcr.io/lance0/rustbgpd@sha256:cc6207fe950ee15f6793ca0119d531067c7b358b6c6193b0fda929495714c9da": 1,
        "docker pull openbgpd/openbgpd@sha256:b2e94bd1538102a89cff96867993eabb6dbb27720de4ab7b588860880e3e3bf9": 1,
        "docker pull quay.io/frrouting/frr@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c": 1,
        "python3 tests/interop/scripts/m100_partial_raw_peer.py --self-test": 1,
        'CLEANUP: "1"': 1,
        "M100_ARTIFACT_DIR: ${{ runner.temp }}/m100": 1,
        "uses: ./.github/actions/run-interop-test": 1,
        "label: M100\n": 1,
        "topology: tests/interop/m100-partial-receiver.clab.yml": 1,
        "script: tests/interop/scripts/test-m100-partial-receiver.sh": 1,
        'max_attempts: "1"': 1,
        "uses: actions/upload-artifact@v7": 1,
        "name: m100-partial-receiver-${{ github.sha }}": 1,
        "path: ${{ runner.temp }}/m100": 1,
        "if-no-files-found: error": 1,
        "retention-days: 14": 1,
    }
    if any(m100.count(seam) != count for seam, count in m100_required.items()):
        errors.append("interop.yml:m100: exact released-daemon receiver matrix drifted")
    for forbidden in (
        "ghcr.io/lance0/rustbgpd:0.67.0",
        "openbgpd/openbgpd:9.2",
        "quay.io/frrouting/frr:10.3.1",
        "bird:2.19.2",
        "prime_dev_image",
        "rustbgpd:dev",
        "scope=rustbgpd-dev",
        "continue-on-error:",
        'max_attempts: "2"',
    ):
        if forbidden in m100:
            errors.append(f"interop.yml:m100: permits {forbidden}")
    m101 = _jobs(texts["interop.yml"]).get("m101", "")
    m101_required = {
        GRPCURL_ACTION: 1,
        BIRD3_ACTION: 1,
        f"artifact-name: {BIRD332_ARTIFACT}": 1,
        "name: Build checksum-pinned BIRD 3.3.2 image": 1,
        "file: tests/interop/Dockerfile.bird-v332": 1,
        "tags: bird:v3.3.2-m101": 1,
        "cache-from: type=gha,scope=bird332-m101": 1,
        "cache-to: type=gha,mode=max,scope=bird332-m101,ignore-error=true": 1,
        "name: Pull digest-pinned FRR 10.3.1 image": 1,
        "docker pull quay.io/frrouting/frr@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c": 1,
        "uses: ./.github/actions/run-interop-test": 1,
        "label: M101\n": 1,
        "topology: tests/interop/m101-routeserver-bird332.clab.yml": 1,
        "script: tests/interop/scripts/test-m101-routeserver-bird332.sh": 1,
        'max_attempts: "1"': 1,
    }
    if any(m101.count(seam) != count for seam, count in m101_required.items()):
        errors.append("interop.yml:m101: BIRD 3.3.2 real-wire job semantics drifted")
    for forbidden in (
        "bird:3.3.2",
        "quay.io/frrouting/frr:10.3.1",
        "continue-on-error:",
        'max_attempts: "2"',
    ):
        if forbidden in m101:
            errors.append(f"interop.yml:m101: permits {forbidden}")
    m102 = _jobs(texts["interop.yml"]).get("m102", "")
    m102_required = {
        GRPCURL_ACTION: 1,
        "name: Verify and pull digest-pinned OpenBGPD 9.2 image": 1,
        "OPENBGPD_AMD64_MANIFEST: sha256:3178027d7ca916eacec247c66472a1f95a17d83d4616fe4f118318a912ab8beb": 1,
        "OPENBGPD_CONFIG: sha256:06317b65d9fadc80f68c5c8e7c82815b0643577fd5441bd55038e43771b5807e": 1,
        'index_json=$(docker buildx imagetools inspect --raw "$OPENBGPD_IMAGE")': 1,
        'test "$amd64_manifest" = "$OPENBGPD_AMD64_MANIFEST"': 1,
        'test "$(jq -er \'.config.digest\' <<<"$manifest_json")" = "$OPENBGPD_CONFIG"': 1,
        'docker pull "$OPENBGPD_IMAGE"': 1,
        "name: Build bmpsink:m102 capture sidecar": 1,
        "docker build -t bmpsink:m102 -f tests/interop/Dockerfile.bmpsink tests/interop": 1,
        "name: Pull digest-pinned FRR 10.3.1 image": 1,
        "docker pull quay.io/frrouting/frr@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c": 1,
        "uses: ./.github/actions/run-interop-test": 1,
        'CLEANUP: "1"': 1,
        "label: M102\n": 1,
        "topology: tests/interop/m102-routeserver-openbgpd92.clab.yml": 1,
        "script: tests/interop/scripts/test-m102-routeserver-openbgpd92.sh": 1,
        'max_attempts: "1"': 1,
    }
    if any(m102.count(seam) != count for seam, count in m102_required.items()):
        errors.append("interop.yml:m102: OpenBGPD 9.2 route-server job semantics drifted")
    for forbidden in (
        "openbgpd/openbgpd:9.2",
        "quay.io/frrouting/frr:10.3.1",
        "name: Ensure host raw-capture tools",
        "apt-get install",
        "nsenter",
        "sudo ",
        "continue-on-error:",
        'max_attempts: "2"',
    ):
        if forbidden in m102:
            errors.append(f"interop.yml:m102: permits {forbidden}")
    m103 = _jobs(texts["interop.yml"]).get("m103", "")
    m103_required = {
        GRPCURL_ACTION: 1,
        "docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop": 1,
        "name: Build gobgp:v4.8.0-m103": 1,
        "--build-arg TARGETARCH=amd64": 1,
        "--build-arg GOBGP_VERSION=4.8.0": 1,
        "--build-arg GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03": 1,
        "-t gobgp:v4.8.0-m103 -f tests/interop/Dockerfile.gobgp-v47 tests/interop": 1,
        "uses: ./.github/actions/run-interop-test": 2,
        "name: Run M103 (single-attempt GoBGP 4.8 differential)": 1,
        "name: Run M103 negative completeness proof (single attempt)": 1,
        "uses: actions/upload-artifact@v7": 2,
        "name: Upload M103 normal successful-run evidence": 1,
        "name: Upload M103 negative successful-run evidence": 1,
        "M103_ARTIFACT_DIR: ${{ runner.temp }}/m103-normal": 1,
        "M103_ARTIFACT_DIR: ${{ runner.temp }}/m103-negative": 1,
        "name: m103-gobgp-v48-normal-${{ github.sha }}": 1,
        "name: m103-gobgp-v48-negative-${{ github.sha }}": 1,
        "path: ${{ runner.temp }}/m103-normal": 1,
        "path: ${{ runner.temp }}/m103-negative": 1,
        "if-no-files-found: error": 2,
        "retention-days: 14": 2,
        "topology: tests/interop/m103-gobgp-v48-rs-differential.clab.yml": 2,
        "script: tests/interop/scripts/test-m103-gobgp-v48-rs-differential.sh": 2,
        "label: M103\n": 1,
        "label: M103-negative\n": 1,
        'M103_COMPLETENESS_NEGATIVE: "1"': 1,
        'max_attempts: "1"': 2,
    }
    if any(m103.count(seam) != count for seam, count in m103_required.items()):
        errors.append("interop.yml:m103: GoBGP 4.8 differential job semantics drifted")
    negative = m103.split("- name: Run M103 negative completeness proof", 1)
    if len(negative) != 2 or 'M103_COMPLETENESS_NEGATIVE: "1"' in negative[0]:
        errors.append("interop.yml:m103: negative environment scope drifted")
    for forbidden in ("continue-on-error:", 'max_attempts: "2"'):
        if forbidden in m103:
            errors.append(f"interop.yml:m103: permits {forbidden}")
    m104 = _jobs(texts["interop.yml"]).get("m104", "")
    m104_required = {
        GRPCURL_ACTION: 1,
        BIRD3_ACTION: 1,
        'version: "2.19.2"': 1,
        f"sha256: {BIRD2192_SHA256}": 1,
        f"artifact-name: {BIRD2192_ARTIFACT}": 1,
        "name: Verify and pull exact ARouteServer 1.23.2 image": 1,
        "AROUTESERVER_IMAGE: pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66": 1,
        "AROUTESERVER_CONFIG: sha256:4a08ef740f00a119f5897b0f834da9ff172a282c93d47fdff636c3b50c9aec93": 1,
        'manifest_json=$(docker buildx imagetools inspect --raw "$AROUTESERVER_IMAGE")': 1,
        "application/vnd.docker.distribution.manifest.v2+json": 1,
        'test "$(jq -er \'.config.digest\' <<<"$manifest_json")" =': 1,
        'docker pull "$AROUTESERVER_IMAGE"': 1,
        'importlib.metadata.version("arouteserver")': 1,
        "name: Build bird:v2.19.2-m104": 1,
        "file: tests/interop/Dockerfile.bird-v2192": 1,
        "tags: bird:v2.19.2-m104": 1,
        "cache-from: type=gha,scope=bird2192-m104": 1,
        "cache-to: type=gha,mode=max,scope=bird2192-m104,ignore-error=true": 1,
        "name: Build gobgp:v4.8.0-m104": 1,
        "uses: ./.github/actions/install-protobuf": 1,
        "--build-arg TARGETARCH=amd64": 1,
        "--build-arg GOBGP_VERSION=4.8.0": 1,
        "--build-arg GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03": 1,
        "-t gobgp:v4.8.0-m104 -f tests/interop/Dockerfile.gobgp-v47 tests/interop": 1,
        "name: Run immutable M90 context proof (exact 23/23)": 1,
        "M90_ARS_IMAGE: pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66": 1,
        "bash tests/interop/m90-differential/prove-context-ingestion.sh": 1,
        "grep -Fq 'PROOF PASS: 23 checks'": 1,
        "name: Run M104 offline destructive contract": 1,
        "--self-test-offline-contract": 1,
        "name: Run M104 (single-attempt current-daemon differential)": 1,
        "M104_EXPECTED_GIT_SHA: ${{ github.sha }}": 1,
        "uses: ./.github/actions/run-interop-test": 1,
        "label: M104\n": 1,
        "topology: tests/interop/m104-arouteserver-current-rs-differential.clab.yml": 1,
        "script: tests/interop/scripts/test-m104-arouteserver-current-rs-differential.sh": 1,
        'max_attempts: "1"': 1,
    }
    if any(m104.count(seam) != count for seam, count in m104_required.items()):
        errors.append(
            "interop.yml:m104: current ARouteServer differential semantics drifted"
        )
    m104_context = m104.find("name: Run immutable M90 context proof (exact 23/23)")
    m104_protobuf = m104.find("uses: ./.github/actions/install-protobuf")
    m104_live = m104.find("name: Run M104 (single-attempt current-daemon differential)")
    if not (0 <= m104_protobuf < m104_context < m104_live):
        errors.append(
            "interop.yml:m104: protoc must precede the context proof and live differential"
        )
    for forbidden in (
        "pierky/arouteserver:latest",
        "BIRD_TARGET_VERSION=2.0.11",
        "continue-on-error:",
        'max_attempts: "2"',
    ):
        if forbidden in m104:
            errors.append(f"interop.yml:m104: permits {forbidden}")
    interop_classifier = _jobs(texts["interop.yml"]).get("classify_changes", "")
    kernel_jobs = _jobs(texts["kernel-dataplane.yml"])
    interop_classifier = interop_classifier.replace("interop heavy-lab", "heavy-lab")
    kernel_classifier = kernel_jobs.get("classify_changes", "").replace(
        "kernel heavy-lab", "heavy-lab"
    )
    if interop_classifier != kernel_classifier:
        errors.append("heavy workflows must share an identical classifier job")
    interop_grpcurl = _jobs(texts["interop.yml"]).get("grpcurl_archive", "")
    if interop_grpcurl != kernel_jobs.get("grpcurl_archive", ""):
        errors.append("heavy workflows must share an identical grpcurl producer job")
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
    prepare_grpcurl_action = (
        root / ".github" / "actions" / "prepare-grpcurl-artifact" / "action.yml"
    ).read_text()
    prepare_gobgp_action = (
        root / ".github" / "actions" / "prepare-gobgp-artifact" / "action.yml"
    ).read_text()
    prime_dev_image_action = (
        root / ".github" / "actions" / "prime-rustbgpd-dev-cache" / "action.yml"
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
        'using: "composite"',
        "uses: actions/cache@v6",
        f"path: ${{{{ runner.temp }}}}/grpcurl-cache/{GRPCURL_ARCHIVE}",
        f"key: {GRPCURL_CACHE_KEY}",
        "shell: bash",
        "--prepare-archive",
        f'"$RUNNER_TEMP/grpcurl-cache/{GRPCURL_ARCHIVE}"',
        "uses: actions/upload-artifact@v7",
        f"name: {GRPCURL_ARTIFACT}",
        "if-no-files-found: error",
        "retention-days: 1",
        "compression-level: 0",
    ):
        if seam not in prepare_grpcurl_action:
            errors.append(f"prepare-grpcurl-artifact missing {seam}")
    if prepare_grpcurl_action.count("uses: actions/cache@v6") != 1:
        errors.append("prepare-grpcurl-artifact must restore one exact cache")
    if prepare_grpcurl_action.count("--prepare-archive") != 1:
        errors.append("prepare-grpcurl-artifact must prepare one archive")
    if prepare_grpcurl_action.count("uses: actions/upload-artifact@v7") != 1:
        errors.append("prepare-grpcurl-artifact must upload one artifact")
    exact_grpcurl_path = (
        f"path: ${{{{ runner.temp }}}}/grpcurl-cache/{GRPCURL_ARCHIVE}"
    )
    if prepare_grpcurl_action.count(exact_grpcurl_path) != 2:
        errors.append("prepare-grpcurl-artifact cache/artifact paths drifted")
    if prepare_grpcurl_action.count(f"key: {GRPCURL_CACHE_KEY}") != 1:
        errors.append("prepare-grpcurl-artifact cache key drifted")
    if prepare_grpcurl_action.count(f"name: {GRPCURL_ARTIFACT}") != 1:
        errors.append("prepare-grpcurl-artifact artifact name drifted")
    for forbidden in (
        "inputs:",
        "outputs:",
        "restore-keys:",
        "continue-on-error:",
        "actions/download-artifact@",
        "--install-archive",
        "releases/download/",
    ):
        if forbidden in prepare_grpcurl_action:
            errors.append(f"prepare-grpcurl-artifact permits {forbidden}")
    if re.search(r"(?m)^\s*curl\s", prepare_grpcurl_action):
        errors.append("prepare-grpcurl-artifact permits curl")
    if (
        _canonical_yaml_contract(prepare_gobgp_action)
        != PREPARE_GOBGP_ACTION_CONTRACT
    ):
        errors.append("prepare-gobgp-artifact exact action contract drifted")
    if (
        _canonical_yaml_contract(prime_dev_image_action)
        != PRIME_DEV_IMAGE_ACTION_CONTRACT
    ):
        errors.append("prime-rustbgpd-dev-cache exact action contract drifted")
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
        "inputs:",
        'default: "3.3.2"',
        f'default: "{BIRD3_SHA256}"',
        f'default: "{BIRD3_ARTIFACT}"',
        'default: "tests/interop/bird3-archive"',
        "uses: actions/download-artifact@v8",
        "name: ${{ inputs.artifact-name }}",
        "path: ${{ runner.temp }}/bird3-artifact",
        '--version "${{ inputs.version }}"',
        '--sha256 "${{ inputs.sha256 }}"',
        "--stage-archive",
        '"$RUNNER_TEMP/bird3-artifact/bird-${{ inputs.version }}.tar.gz"',
        '"${{ inputs.stage-directory }}"',
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
    if bird3_action.count("default:") != 4:
        errors.append("stage-bird3-artifact exact default inventory drifted")
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
        (
            texts["interop.yml"],
            texts["kernel-dataplane.yml"],
            action,
            prepare_grpcurl_action,
            grpcurl_action,
        )
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
    if texts["interop.yml"].count(GOBGP_ACTION) != 4:
        errors.append("interop.yml: gobgp stage consumer inventory drifted")
    if texts["kernel-dataplane.yml"].count(GOBGP_ACTION) != 3:
        errors.append("kernel-dataplane.yml: gobgp stage consumer inventory drifted")
    gobgp_surfaces = "\n".join(
        (
            texts["interop.yml"],
            texts["kernel-dataplane.yml"],
            prepare_gobgp_action,
            gobgp_action,
        )
    )
    if "osrg/gobgp/releases" in gobgp_surfaces:
        errors.append("gobgp release URL escaped the installer/Dockerfile")
    if texts["interop.yml"].count(BIRD3_ACTION) != 5:
        errors.append("interop.yml: BIRD stage consumer inventory drifted")
    if texts["kernel-dataplane.yml"].count(BIRD3_ACTION) != 1:
        errors.append("kernel-dataplane.yml: bird3 stage consumer inventory drifted")
    bird3_surfaces = "\n".join(
        (texts["interop.yml"], texts["kernel-dataplane.yml"], bird3_action)
    )
    if "bird.nic.cz" in bird3_surfaces:
        errors.append("bird.nic.cz URL escaped the installer/Dockerfile")

    pin_surfaces = {
        **{f".github/workflows/{name}": text for name, text in texts.items()},
        ".github/actions/setup-dataplane-host/action.yml": action,
        ".github/actions/prepare-grpcurl-artifact/action.yml": prepare_grpcurl_action,
        ".github/actions/prepare-gobgp-artifact/action.yml": prepare_gobgp_action,
        ".github/actions/prime-rustbgpd-dev-cache/action.yml": prime_dev_image_action,
        ".github/actions/install-grpcurl-artifact/action.yml": grpcurl_action,
        ".github/actions/install-gnmic-artifact/action.yml": gnmic_action,
        ".github/actions/stage-gobgp-artifact/action.yml": gobgp_action,
        ".github/actions/stage-bird3-artifact/action.yml": bird3_action,
    }
    for source, text in pin_surfaces.items():
        for value in re.findall(r"^\s*(?:- )?uses:\s*(.+)$", text, re.MULTILINE):
            ref = value.split("#", 1)[0].strip()
            if ref.startswith("./"):
                continue
            if not VERSION_TAG.search(ref):
                errors.append(f"{source}: action ref is not a reviewed version tag: {ref}")
            elif ref not in PINS:
                errors.append(f"{source}: action ref is not in the reviewed pin set: {ref}")

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
    for dockerfile, version, checksum in (
        ("Dockerfile.bird-v2192", BIRD2192_VERSION, BIRD2192_SHA256),
        ("Dockerfile.bird-v332", BIRD332_VERSION, BIRD332_SHA256),
    ):
        source = (root / "tests" / "interop" / dockerfile).read_text()
        for seam in (
            f"ARG BIRD_VERSION={version}",
            f"ARG BIRD_SHA256={checksum}",
            "COPY bird3-archive/ /tmp/bird-archive/",
            'archive="bird-${BIRD_VERSION}.tar.gz"',
            'target="/tmp/bird-archive/${archive}"',
            'if [ ! -f "${target}" ]; then',
            "--connect-timeout 10 --max-time 120",
            "https://bird.nic.cz/download/${archive}",
            '--output "${target}.download"',
            'if [ "${attempt}" -ge 3 ]; then',
            'echo "${BIRD_SHA256}  ${target}" | sha256sum --check --strict',
            'tar -xzf "${target}" -C /tmp/bird --strip-components=1',
            'test "$(bird --version 2>&1)" = "BIRD version ${BIRD_VERSION}"',
        ):
            if seam not in source:
                errors.append(f"{dockerfile}: pinned source seam missing: {seam}")
        if source.count("bird.nic.cz/download/") != 1:
            errors.append(f"{dockerfile}: download URL inventory drifted")
        if not (
            0
            <= source.find("COPY bird3-archive/ /tmp/bird-archive/")
            < source.find(
                'echo "${BIRD_SHA256}  ${target}" | sha256sum --check --strict'
            )
            < source.find('tar -xzf "${target}" -C /tmp/bird --strip-components=1')
        ):
            errors.append(f"{dockerfile}: copy/check/extract ordering drifted")
        if re.search(r"BIRD_VERSION=latest|/download/latest", source):
            errors.append(f"{dockerfile}: floating BIRD release is forbidden")
    return errors


if __name__ == "__main__":
    failures = check(Path(__file__).resolve().parents[1])
    if failures:
        print("CI image-primer contract check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        raise SystemExit(1)
    print("CI image-primer contract OK")
