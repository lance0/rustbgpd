#!/usr/bin/env python3
"""Fail closed when the load-bearing CI split contract drifts."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROSTER = {
    "v064_validator",
    "core",
    "core_tests",
    "scale_receipts",
    "check",
    "msrv",
    "evpn_bum_filter_kernel",
}
RESULTS = ("V064_VALIDATOR", "CORE", "CORE_TESTS", "SCALE_RECEIPTS")


def _jobs(text: str) -> dict[str, str]:
    body = text.split("\njobs:\n", 1)[1] if "\njobs:\n" in text else ""
    matches = list(re.finditer(r"(?m)^  ([\w-]+):\n", body))
    return {
        match.group(1): body[
            match.end() : matches[index + 1].start()
            if index + 1 < len(matches)
            else len(body)
        ]
        for index, match in enumerate(matches)
    }


def aggregate_shell(job: str) -> str:
    match = re.search(
        r"(?ms)^      - name: Aggregate required CI result\n"
        r"        run: \|\n(.*?)(?=^      - |\Z)",
        job,
    )
    return "" if match is None else re.sub(r"(?m)^          ", "", match.group(1))


def named_step(job: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^      - name: {re.escape(name)}\n(.*?)(?=^      - |\Z)",
        job,
    )
    return "" if match is None else match.group(1)


def check(root: Path) -> list[str]:
    text = (root / ".github/workflows/ci.yml").read_text()
    jobs = _jobs(text)
    errors: list[str] = []
    if set(jobs) != ROSTER:
        errors.append("exact CI job roster drifted")

    core_tests = jobs.get("core_tests", "")
    for command in ("cargo test --workspace", "cargo doc --workspace --lib --no-deps"):
        if text.count(command) != 1 or command not in core_tests:
            errors.append(f"{command} must exist exactly once in core_tests")
    if 'RUSTDOCFLAGS: "-D warnings"' not in core_tests:
        errors.append("core_tests rustdoc warnings contract drifted")

    wire_step_name = "Wire crate README freshness gate"
    wire_step = named_step(jobs.get("core", ""), wire_step_name)
    if text.count(f"- name: {wire_step_name}") != 1 or not wire_step:
        errors.append("wire README freshness gate must exist exactly once in core")
    else:
        for seam in (
            'git diff "$base"...HEAD -- crates/wire/Cargo.toml \\',
            'git diff "$base"...HEAD -- crates/wire/README.md \\',
            r"'^\+version\s*='",
            "exit 1",
        ):
            if seam not in wire_step:
                errors.append(f"wire README freshness gate missing {seam}")

    aggregate = jobs.get("check", "")
    if "if: ${{ always() }}" not in aggregate:
        errors.append("aggregate check must run with always()")
    needs = "needs: [v064_validator, core, core_tests, scale_receipts]"
    if needs not in aggregate:
        errors.append("aggregate check needs drifted")
    for name in RESULTS:
        job = name.lower()
        seam = f"{name}_RESULT: ${{{{ needs.{job}.result }}}}"
        if seam not in aggregate:
            errors.append(f"aggregate check missing {job} result wiring")
    disjunction = " || ".join(f'\"${name}_RESULT\" != \"success\"' for name in RESULTS)
    if f"[[ {disjunction} ]]" not in aggregate:
        errors.append("aggregate non-success disjunction drifted")
    if not aggregate_shell(aggregate):
        errors.append("aggregate check shell missing")
    return errors


if __name__ == "__main__":
    failures = check(Path(__file__).resolve().parents[1])
    if failures:
        print("CI scale split contract check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        raise SystemExit(1)
    print("CI scale split contract OK")
