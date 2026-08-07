#!/usr/bin/env python3
"""Fail closed when the CI core/scale split contract drifts."""

from __future__ import annotations

import collections
import hashlib
import re
import sys
from pathlib import Path

ROSTER = [
    "core",
    "core_tests",
    "scale_receipts",
    "check",
    "msrv",
    "evpn_bum_filter_kernel",
]
TRIGGER_HASH = "65951f4c4d1d6c4d3aae2c33705d14cdc144b3efd8bcc01653049e6d7f2fb5f8"
PERMISSION_HASH = "9691400b3b1036bcdfe724926816dbe71b0aa22ed9b5eb89627e2eeb75079898"
JOB_HASHES = {
    "core": "a4c0f059a81cc7f6161b27ee557a444d8ece31554461a25cb7ed425e6e348da5",
    "core_tests": "249218c607b87f02e827acb81ca2c26d2a16eebc0aa5c4b0780d539aee17ba65",
    "scale_receipts": "de016d9c60dc02710cd3a2d87b3d1da4d12cc077055974220b07a50f0835b27b",
    "check": "cfc655ca80392ab0699390b461e5e8e9b41410cc724201aafe75ae6da7d83213",
    "msrv": "886fcc40c19b18d4c7bde52d8b735b153d0c091e0a8e1c865bcd6651daf0b7b5",
    "evpn_bum_filter_kernel": "d427ed2c650d619d926cad0a4cbb6b558dd013ace9b18ba48757be529420863a",
}
COMMAND_BODY_HASH = "9e3c949873c8c0872a1a5403b69300c3a5306025af3cf893782ff1d60a1a2b2f"
STEP_NAME = "Check standalone scale harnesses and receipt classifiers"
CHECKOUT = "uses: actions/checkout@v7"
TOOLCHAIN = "uses: dtolnay/rust-toolchain@master # stable"
RUST_CACHE = "uses: Swatinem/rust-cache@v2"
PINS = collections.Counter(
    {
        "actions/checkout@v7": 5,
        "Swatinem/rust-cache@v2": 4,
        "dtolnay/rust-toolchain@master # stable": 3,
        "dtolnay/rust-toolchain@master # 1.95": 1,
        "docker/setup-buildx-action@v4": 1,
        "docker/build-push-action@v7": 1,
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
        match.group(1): body[
            match.end() : (
                matches[index + 1].start() if index + 1 < len(matches) else len(body)
            )
        ]
        for index, match in enumerate(matches)
    }


def aggregate_shell(job: str) -> str:
    match = re.search(
        r"(?ms)^      - name: Aggregate required CI result\n        run: \|\n(.*?)(?=^      - |\Z)",
        job,
    )
    return "" if match is None else re.sub(r"(?m)^          ", "", match.group(1))


def check(root: Path) -> list[str]:
    errors: list[str] = []
    text = (root / ".github" / "workflows" / "ci.yml").read_text()
    jobs = _jobs(text)
    if list(jobs) != ROSTER:
        errors.append("exact CI job roster/order drifted")
    if _hash(_top_block(text, "on")) != TRIGGER_HASH:
        errors.append("CI triggers drifted")
    if _hash(_top_block(text, "permissions")) != PERMISSION_HASH:
        errors.append("CI permissions drifted")
    for name, expected in JOB_HASHES.items():
        if _hash(jobs.get(name, "")) != expected:
            errors.append(f"{name} job body drifted")

    core_tests = jobs.get("core_tests", "")
    for seam in (
        "name: core tests / rustdoc",
        "runs-on: ubuntu-latest",
        "timeout-minutes: 30",
        CHECKOUT,
        "fetch-depth: 0",
        TOOLCHAIN,
        "toolchain: stable",
        "uses: ./.github/actions/install-protobuf",
        RUST_CACHE,
        "- run: cargo test --workspace",
        "- run: cargo doc --workspace --lib --no-deps",
        'RUSTDOCFLAGS: "-D warnings"',
    ):
        if seam not in core_tests:
            errors.append(f"core_tests missing {seam}")
    for command in (
        "- run: cargo test --workspace",
        "- run: cargo doc --workspace --lib --no-deps",
    ):
        if text.count(command) != 1 or command in jobs.get("core", ""):
            errors.append(f"{command} must exist only in core_tests")

    if text.count(f"- name: {STEP_NAME}") != 1:
        errors.append("extracted scale/receipt step must appear exactly once")
    scale = jobs.get("scale_receipts", "")
    command_match = re.search(
        rf"(?ms)^      - name: {re.escape(STEP_NAME)}\n        run: \|\n(.*?)(?=^      - |\Z)",
        scale,
    )
    if command_match is None or _hash(command_match.group(1)) != COMMAND_BODY_HASH:
        errors.append("extracted command body/order drifted")
    for seam in (
        "name: scale / receipt checks",
        "runs-on: ubuntu-latest",
        "timeout-minutes: 30",
        CHECKOUT,
        "fetch-depth: 0",
        TOOLCHAIN,
        "toolchain: stable",
        "components: rustfmt, clippy",
        "uses: ./.github/actions/install-protobuf",
        RUST_CACHE,
        "sudo apt-get update",
        "sudo apt-get install -y ripgrep",
    ):
        if seam not in scale:
            errors.append(f"scale_receipts missing {seam}")

    aggregate = jobs.get("check", "")
    for seam in (
        "name: check",
        "runs-on: ubuntu-latest",
        "timeout-minutes: 5",
        "if: ${{ always() }}",
        "needs: [core, core_tests, scale_receipts]",
        "CORE_RESULT: ${{ needs.core.result }}",
        "CORE_TESTS_RESULT: ${{ needs.core_tests.result }}",
        "SCALE_RECEIPTS_RESULT: ${{ needs.scale_receipts.result }}",
        "printf 'core=%s\\n' \"$CORE_RESULT\"",
        "printf 'core_tests=%s\\n' \"$CORE_TESTS_RESULT\"",
        "printf 'scale_receipts=%s\\n' \"$SCALE_RECEIPTS_RESULT\"",
        '[[ "$CORE_RESULT" != "success" || "$CORE_TESTS_RESULT" != "success" || "$SCALE_RECEIPTS_RESULT" != "success" ]]',
    ):
        if seam not in aggregate:
            errors.append(f"aggregate check missing {seam}")
    if "actions/checkout@" in aggregate:
        errors.append("aggregate check must not checkout source")
    if not aggregate_shell(aggregate):
        errors.append("aggregate check shell missing")

    pins = collections.Counter(
        value.strip()
        for value in re.findall(r"^\s*(?:- )?uses:\s*(.+)$", text, re.MULTILINE)
        if not value.strip().startswith("./")
    )
    if pins != PINS:
        errors.append("CI external action pins/counts drifted")
    return errors


if __name__ == "__main__":
    failures = check(Path(__file__).resolve().parents[1])
    if failures:
        print("CI scale split contract check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        raise SystemExit(1)
    print("CI scale split contract OK")
