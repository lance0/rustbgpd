#!/usr/bin/env python3
"""Fail closed when the load-bearing CI split contract drifts."""

from __future__ import annotations

import re
import sys
from collections import Counter
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
RETIRED_PRIVILEGED_WORKFLOW = ".github/workflows/privileged-interop.yml"
WORKFLOWS = tuple(
    f".github/workflows/{name}.yml"
    for name in ("ci", "container", "kernel-dataplane",
                 "release-install-contract", "release", "update-group-fault")
)
EXPECTED_ROOT_COMMANDS = {
    WORKFLOWS[0]: Counter(build=1, check=6, clippy=2, doc=4, test=7),
    WORKFLOWS[1]: Counter(test=1),
    WORKFLOWS[2]: Counter(test=6),
    WORKFLOWS[3]: Counter(build=1, test=2),
    WORKFLOWS[4]: Counter(build=2, test=1),
    WORKFLOWS[5]: Counter(test=3),
}
EXPECTED_STANDALONE_COMMANDS = (
    (WORKFLOWS[0], "cargo test --manifest-path bench/scale/rrharness/Cargo.toml --locked"),
    (WORKFLOWS[0], "cargo test --manifest-path bench/scale/rrtransport/Cargo.toml --locked"),
    (WORKFLOWS[0], "cargo test --manifest-path bench/scale/reloadstall/Cargo.toml --locked"),
    (WORKFLOWS[0], "cargo test --manifest-path bench/scale/enhanced-route-refresh/Cargo.toml --locked"),
    (WORKFLOWS[0],
     "cargo clippy --manifest-path bench/scale/rrtransport/Cargo.toml --locked --all-targets -- -D warnings"),
    (WORKFLOWS[0], "cargo run --manifest-path bench/scale/rrtransport/Cargo.toml --locked -- smoke"),
    (
        WORKFLOWS[0],
        "cargo clippy --manifest-path bench/scale/enhanced-route-refresh/Cargo.toml --locked --all-targets -- -D warnings",
    ),
)
CARGO_COMMAND = re.compile(r"(?<![\w-])cargo(?:\s+\+\S+)?\s+(build|check|test|clippy|doc|bench|run)\b")
LOCKED_TOKEN = re.compile(r"(?<!\S)--locked(?=\s|$)")
ARG_SEPARATOR = re.compile(r"(?<!\S)--(?=\s|$)")
MANIFEST_PATH = re.compile(r"(?<!\S)--manifest-path(?:=|\s+)([^\s;|&)]+)")


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


def _logical_lines(text: str) -> list[str]:
    logical: list[str] = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        pending += stripped
        if re.search(r"\\\s*$", pending):
            pending = re.sub(r"[ \t]*\\\s*$", " ", pending)
            continue
        logical.append(pending)
        pending = ""
    if pending:
        logical.append(pending)
    return logical


def _cargo_commands(text: str) -> list[tuple[str, str]]:
    commands: list[tuple[str, str]] = []
    for line in _logical_lines(text):
        matches = list(CARGO_COMMAND.finditer(line))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(line)
            command = line[match.start() : end].strip()
            if boundary := re.search(r"&&|\|\||[;|&)]", command):
                command = command[: boundary.start()].rstrip()
            commands.append((match.group(1), command))
    return commands


def _check_dependency_commands(root: Path, errors: list[str]) -> None:
    root_commands: dict[str, Counter[str]] = {}
    standalone: list[tuple[str, str]] = []
    directory = root / ".github/workflows"
    for path in sorted((*directory.glob("*.yml"), *directory.glob("*.yaml"))):
        if not (commands := _cargo_commands(path.read_text())):
            continue
        workflow = path.relative_to(root).as_posix()
        counts: Counter[str] = Counter()
        for subcommand, command in commands:
            locked = list(LOCKED_TOKEN.finditer(command))
            separator = ARG_SEPARATOR.search(command)
            if not locked:
                errors.append(f"{workflow}: {subcommand} command is missing --locked: {command}")
            elif len(locked) > 1:
                errors.append(f"{workflow}: {subcommand} command has duplicate --locked: {command}")
            elif separator is not None and locked[0].start() > separator.start():
                errors.append(f"{workflow}: {subcommand} command has --locked after Cargo's -- separator: {command}")
            if MANIFEST_PATH.search(command):
                standalone.append((workflow, command))
            else:
                counts[subcommand] += 1
        root_commands[workflow] = counts

    if root_commands != EXPECTED_ROOT_COMMANDS:
        errors.append(
            f"root Cargo command inventory drifted: expected {EXPECTED_ROOT_COMMANDS}, got {root_commands}"
        )
    if tuple(standalone) != EXPECTED_STANDALONE_COMMANDS:
        errors.append("standalone Cargo command inventory or flags drifted")


def check(root: Path) -> list[str]:
    text = (root / ".github/workflows/ci.yml").read_text()
    jobs = _jobs(text)
    errors: list[str] = []
    if (root / RETIRED_PRIVILEGED_WORKFLOW).exists():
        errors.append(
            f"retired workflow must stay absent: {RETIRED_PRIVILEGED_WORKFLOW}"
        )
    _check_dependency_commands(root, errors)
    if set(jobs) != ROSTER:
        errors.append("exact CI job roster drifted")

    core_tests = jobs.get("core_tests", "")
    for command in (
        "cargo test --locked --workspace",
        "cargo doc --locked --workspace --lib --no-deps --document-private-items",
        "cargo doc --locked -p rustbgpd --bin rustbgpd --no-deps",
        "cargo doc --locked -p rustbgpctl --bin rbgp --no-deps",
    ):
        if text.count(command) != 1 or command not in core_tests:
            errors.append(f"{command} must exist exactly once in core_tests")
    if core_tests.count('RUSTDOCFLAGS: "-D warnings"') != 4:
        errors.append("core_tests rustdoc warnings contract drifted")

    feature_commands = (
        (
            jobs.get("core", ""),
            "cargo clippy --locked -p rustbgpd-wire --all-targets --features tokio-codec -- -D warnings",
            "core",
        ),
        (
            core_tests,
            "cargo test --locked -p rustbgpd-wire --features tokio-codec",
            "core_tests",
        ),
        (
            core_tests,
            "cargo doc --locked -p rustbgpd-wire --lib --no-deps --features tokio-codec",
            "core_tests",
        ),
    )
    for job, command, job_name in feature_commands:
        if text.count(command) != 1 or command not in job:
            errors.append(f"{command} must exist exactly once in {job_name}")

    readme_step_name = "Published crate README freshness gate"
    readme_step = named_step(jobs.get("core", ""), readme_step_name)
    if text.count(f"- name: {readme_step_name}") != 1 or not readme_step:
        errors.append("published-crate README freshness gate must exist exactly once in core")
    else:
        for seam in (
            "for crate in wire fsm rpki; do",
            'git diff "$base"...HEAD -- "crates/$crate/Cargo.toml" \\',
            'git diff "$base"...HEAD -- "crates/$crate/README.md" \\',
            r"'^\+version\s*='",
            "exit 1",
        ):
            if seam not in readme_step:
                errors.append(f"published-crate README freshness gate missing {seam}")

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
