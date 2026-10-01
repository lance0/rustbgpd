#!/usr/bin/env python3
"""Fail closed when the load-bearing CI split contract drifts."""

from __future__ import annotations

import re
import sys
import tomllib
from collections import Counter
from pathlib import Path

ROSTER = {
    "core",
    "core_tests",
    "scale_receipts",
    "check",
    "msrv",
    "evpn_bum_filter_kernel",
}
RESULTS = ("CORE", "CORE_TESTS", "SCALE_RECEIPTS")
RETIRED_PRIVILEGED_WORKFLOW = ".github/workflows/privileged-interop.yml"
WORKFLOWS = tuple(
    f".github/workflows/{name}.yml"
    for name in ("ci", "container", "kernel-dataplane",
                 "release-install-contract", "release", "update-group-fault",
                 "public-docs-contract")
)
# Floors, not a census: a new root Cargo command needs only `--locked`, while a
# removed one (or an extractor that stops seeing a workflow) still fails.
MIN_ROOT_COMMANDS = {
    WORKFLOWS[0]: Counter(build=1, check=7, clippy=2, doc=2, test=7),
    WORKFLOWS[1]: Counter(test=1),
    WORKFLOWS[2]: Counter(test=6),
    WORKFLOWS[3]: Counter(build=1, test=2),
    WORKFLOWS[4]: Counter(build=2, test=1),
    WORKFLOWS[5]: Counter(test=3),
    WORKFLOWS[6]: Counter(test=1),
}
SCALE_COMMANDS = (
    "cargo test --locked -p enhanced-route-refresh-receipt -p reloadstall -p rrharness -p rrtransport",
    "cargo clippy --locked -p rrtransport --all-targets -- -D warnings",
    "cargo run --locked -p rrtransport -- smoke",
    "cargo clippy --locked -p enhanced-route-refresh-receipt --all-targets -- -D warnings",
    "cargo build --locked -p rs-config-render",
    "cargo build --locked -p reloadstall",
)
SCALE_PROFILE = {
    "inherits": "release",
    "lto": False,
    "codegen-units": 16,
    "strip": False,
    "debug": 1,
}
CARGO_COMMAND = re.compile(r"(?<![\w-])cargo(?:\s+\+\S+)?\s+(build|check|test|clippy|doc|bench|run)\b")
LOCKED_TOKEN = re.compile(r"(?<!\S)--locked(?=\s|$)")
ARG_SEPARATOR = re.compile(r"(?<!\S)--(?=\s|$)")
MSRV_PINS = (
    ("Dockerfile", None, None, r"(?m)^FROM rust:([^\s-]+)-\S+ AS chef$"),
    ("crates/evpn-linux/tests/docker/Dockerfile", None, None, r"(?m)^FROM rust:([^\s-]+)-\S+$"),
    (".github/workflows/release.yml", "build", None, r"(?m)^ {4}container: rust:([^\s-]+)-"),
    (".github/workflows/kernel-dataplane.yml", "m43", "dtolnay/rust-toolchain", r'(?m)^ {10}toolchain: "([0-9.]+)"[ \t]*$'),
    (".github/workflows/ci.yml", "msrv", "dtolnay/rust-toolchain", r'(?m)^ {10}toolchain: "([0-9.]+)"[ \t]*$'),
    (".github/workflows/ci.yml", "msrv", "Swatinem/rust-cache", r"(?m)^ {10}key: msrv-([^\s]+)[ \t]*$"),
)


def _action_inputs(job: str, action: str) -> str:
    # Like _jobs, intentionally accept the repository's workflow layout.
    # A nearby env key or a different action's input is not the active pin.
    steps = [" " * 8 + step for step in re.split(r"(?m)^ {6}- ", job)[1:]]
    matches = [step for step in steps if re.search(rf"(?m)^ {{8}}uses: {re.escape(action)}@\S+", step)]
    if len(matches) != 1:
        return ""
    inputs = re.search(r"(?ms)^ {8}with:[ \t]*\n(.*?)(?=^ {0,8}\S|\Z)", matches[0])
    return inputs.group(1) if inputs else ""


def _check_msrv_pins(root: Path, errors: list[str]) -> None:
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    msrv = manifest.get("workspace", {}).get("package", {}).get("rust-version")
    if not isinstance(msrv, str) or not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", msrv):
        errors.append("Cargo.toml: expected one numeric workspace.package.rust-version")
        return
    for filename, job, action, pattern in MSRV_PINS:
        text = (root / filename).read_text()
        if job:
            text = _jobs(text).get(job, "")
        if action:
            text = _action_inputs(text, action)
        pins = re.findall(pattern, text)
        if pins != [msrv]:
            errors.append(f"{filename}: MSRV pin {pins!r} must match Cargo.toml rust-version {msrv!r}")


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
            counts[subcommand] += 1
        root_commands[workflow] = counts

    for workflow, floor in MIN_ROOT_COMMANDS.items():
        if missing := floor - root_commands.get(workflow, Counter()):
            errors.append(f"{workflow}: root Cargo commands removed: {dict(missing)}")


def check(root: Path) -> list[str]:
    text = (root / ".github/workflows/ci.yml").read_text()
    jobs = _jobs(text)
    errors: list[str] = []
    if (root / RETIRED_PRIVILEGED_WORKFLOW).exists():
        errors.append(
            f"retired workflow must stay absent: {RETIRED_PRIVILEGED_WORKFLOW}"
        )
    _check_dependency_commands(root, errors)
    _check_msrv_pins(root, errors)
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    if manifest.get("profile", {}).get("scale") != SCALE_PROFILE:
        errors.append("Cargo.toml: scale profile must match former scale release settings")
    scale_members = {
        f"bench/scale/{name}"
        for name in ("enhanced-route-refresh", "reloadstall", "rrharness", "rrtransport")
    }
    workspace = manifest.get("workspace", {})
    if not scale_members <= set(workspace.get("members", [])):
        errors.append("Cargo.toml: scale harnesses must be root workspace members")
    if scale_members & set(workspace.get("default-members", [])):
        errors.append("Cargo.toml: scale harnesses must stay outside default-members")
    if set(jobs) != ROSTER:
        errors.append("exact CI job roster drifted")

    scale_commands = Counter(command for _, command in _cargo_commands(jobs.get("scale_receipts", "")))
    for command in SCALE_COMMANDS:
        if scale_commands[command] != 1:
            errors.append(f"scale receipt Cargo command missing or duplicated: {command}")

    core_tests = jobs.get("core_tests", "")
    for command in (
        "cargo test --locked --workspace",
        "cargo doc --locked --workspace --lib --bin rustbgpd --bin rbgp --no-deps --document-private-items",
    ):
        if text.count(command) != 1 or command not in core_tests:
            errors.append(f"{command} must exist exactly once in core_tests")
    if core_tests.count('RUSTDOCFLAGS: "-D warnings"') != 2:
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

    aggregate = jobs.get("check", "")
    if "if: ${{ always() }}" not in aggregate:
        errors.append("aggregate check must run with always()")
    needs = "needs: [core, core_tests, scale_receipts]"
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
