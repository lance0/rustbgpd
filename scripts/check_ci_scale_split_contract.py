#!/usr/bin/env python3
"""Fail closed when the CI scale/receipt split contract drifts."""

from __future__ import annotations

import collections
import hashlib
import re
import sys
from pathlib import Path

ROSTER = ["core", "scale_receipts", "check", "msrv", "evpn_bum_filter_kernel"]
TRIGGER_HASH = "65951f4c4d1d6c4d3aae2c33705d14cdc144b3efd8bcc01653049e6d7f2fb5f8"
PERMISSION_HASH = "9691400b3b1036bcdfe724926816dbe71b0aa22ed9b5eb89627e2eeb75079898"
JOB_HASHES = {
    "core": "81bea34b590cff22f28e437e20dd15ba200d1bfb2424b9158ecdc1c61ac4b2e9",
    "scale_receipts": "91d5396ba46147fd7a489b49cbc6207f8588f350df3308c92f236f3936dbcf4f",
    "check": "afc9629a32cc7c3194ccf0417aaf2623e7a01a8dc95fd0194c2cbfbb29068b57",
    "msrv": "db1ae833d9c8fbbc47dbf2969ac291b90cf413ba9eed2b95dd4cfe34e0a4ba5d",
    "evpn_bum_filter_kernel": "f965e7f95f30772d9d335104dda9e30c53816098bd5f1225a3cadabe7d9a23b3",
}
COMMAND_BODY_HASH = "9e3c949873c8c0872a1a5403b69300c3a5306025af3cf893782ff1d60a1a2b2f"
STEP_NAME = "Check standalone scale harnesses and receipt classifiers"
CHECKOUT = "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7"
TOOLCHAIN = (
    "uses: dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c # stable"
)
RUST_CACHE = "uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2"
PINS = collections.Counter(
    {
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7": 4,
        "Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2": 3,
        "dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c # stable": 2,
        "dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c # 1.95": 1,
        "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # v4": 1,
        "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a # v7": 1,
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
        "needs: [core, scale_receipts]",
        "CORE_RESULT: ${{ needs.core.result }}",
        "SCALE_RECEIPTS_RESULT: ${{ needs.scale_receipts.result }}",
        "printf 'core=%s\\n' \"$CORE_RESULT\"",
        "printf 'scale_receipts=%s\\n' \"$SCALE_RECEIPTS_RESULT\"",
        '[[ "$CORE_RESULT" != "success" || "$SCALE_RECEIPTS_RESULT" != "success" ]]',
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
