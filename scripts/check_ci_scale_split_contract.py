#!/usr/bin/env python3
"""Fail closed when the load-bearing CI split contract drifts."""

from __future__ import annotations

import re
import json
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
    "recovery_memory_receipt",
    "recovery_mass_dirty_receipt",
}
RECOVERY_MEMORY_SELECTOR = (
    "${{ github.event_name == 'workflow_dispatch' && "
    "inputs.recovery_memory_receipt == true && inputs.recovery_receipt_mode != 'mass-dirty' }}"
)
RECOVERY_MASS_DIRTY_SELECTOR = (
    "${{ github.event_name == 'workflow_dispatch' && "
    "inputs.recovery_memory_receipt == true && inputs.recovery_receipt_mode == 'mass-dirty' }}"
)
RECOVERY_MEMORY_CONCURRENCY = (
    "${{ github.workflow }}-${{ github.event_name == 'workflow_dispatch' && "
    "inputs.recovery_memory_receipt == true && "
    "format('recovery-memory-{0}', github.run_id) || github.ref }}"
)
RESULTS = ("CORE", "CORE_TESTS", "SCALE_RECEIPTS")
RETIRED_PRIVILEGED_WORKFLOW = ".github/workflows/privileged-interop.yml"
WORKFLOWS = tuple(
    f".github/workflows/{name}.yml"
    for name in ("ci", "container", "kernel-dataplane",
                 "release-install-contract", "release", "update-group-fault",
                 "public-docs-contract")
)
# Floors, not a census: new root Cargo commands need `--locked`. CI floors
# are job-scoped so scale commands cannot mask removed core checks.
MIN_ROOT_COMMANDS = {
    (WORKFLOWS[0], "core"): Counter(check=6, clippy=2, test=4),
    (WORKFLOWS[0], "core_tests"): Counter(doc=2, test=2),
    (WORKFLOWS[0], "msrv"): Counter(check=1),
    (WORKFLOWS[1], None): Counter(test=1),
    (WORKFLOWS[2], None): Counter(test=6),
    (WORKFLOWS[3], None): Counter(build=1, test=2),
    (WORKFLOWS[4], None): Counter(build=2, test=1),
    (WORKFLOWS[5], None): Counter(test=3),
    (WORKFLOWS[6], None): Counter(test=1),
}
SCALE_COMMANDS = (
    "cargo test --locked -p enhanced-route-refresh-receipt -p reloadstall -p rrharness -p rrtransport",
    "cargo clippy --locked -p rrtransport --all-targets -- -D warnings",
    "cargo run --locked -p rrtransport -- smoke",
    "cargo clippy --locked -p enhanced-route-refresh-receipt --all-targets -- -D warnings",
    "cargo build --locked -p rs-config-render",
    "cargo test --locked --test reloadstall_scenario_emitted_check",
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
MANIFEST_PATH_TOKEN = re.compile(r"(?<!\S)--manifest-path(?=\s|=|$)")
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


def _named_step(job: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^      - name: {re.escape(name)}\n(.*?)(?=^      - |\Z)", job,
    )
    return match.group(1) if match else ""


def step_shell(job: str, name: str) -> str:
    match = re.search(r"(?ms)^        run: \|\n(.*)\Z", _named_step(job, name))
    return "" if match is None else re.sub(r"(?m)^          ", "", match.group(1))


def _check_mass_dirty(job: str, errors: list[str]) -> None:
    if re.findall(r"(?m)^ {4}if:[ \t]*(.*?)[ \t]*$", job) != [RECOVERY_MASS_DIRTY_SELECTOR]:
        errors.append("mass-dirty receipt must keep its separate operator-dispatch selector")
    if re.findall(r"(?m)^ {4}runs-on:[ \t]*(.*?)[ \t]*$", job) != ["ubuntu-24.04"]:
        errors.append("mass-dirty receipt must use a fresh ubuntu-24.04 hosted runner")
    if "    timeout-minutes: 120\n" not in job or "      fail-fast: false\n" not in job:
        errors.append("mass-dirty receipt must bound each independent matrix job without canceling siblings")
    matrix = re.findall(r"(?m)^        include: \$\{\{ fromJSON\('([^']*)'\) \}\}[ \t]*$", job)
    try:
        selected = json.loads(matrix[0]) if len(matrix) == 1 else None
    except ValueError:
        selected = None
    if selected != [
        {"profile": profile, "cohort": cohort}
        for profile in ("full-uc", "full-vpn") for cohort in ("no-refusal", "cap-pressure")
    ]:
        errors.append("mass-dirty receipt must isolate all four fixed profile/cohort cells")
    checkout = _action_inputs(job, "actions/checkout")
    if any(re.findall(rf"(?m)^ {{10}}{name}:[ \t]*(.*?)[ \t]*$", checkout) != [value]
           for name, value in (("ref", "${{ github.sha }}"), ("fetch-depth", "0"))):
        errors.append("mass-dirty receipt must check out its exact dispatched source with history")
    toolchain = _action_inputs(job, "dtolnay/rust-toolchain")
    if re.findall(r"(?m)^ {10}toolchain:[ \t]*(.*?)[ \t]*$", toolchain) != ["stable"]:
        errors.append("mass-dirty receipt must provide the stable toolchain input")
    if "      - uses: ./.github/actions/install-protobuf\n" not in job:
        errors.append("mass-dirty receipt must install protobuf for its exact source build")
    if any(required not in job for required in (
        '      CARGO_BUILD_JOBS: "4"',
        '      RECOVERY_MASS_DIRTY_PROFILE: ${{ matrix.profile }}',
        '      RECOVERY_MASS_DIRTY_COHORT: ${{ matrix.cohort }}',
    )):
        errors.append("mass-dirty receipt must bind its build limit and selected profile/cohort")
    fixtures = step_shell(job, "Check mass-dirty receipt negative fixtures")
    if fixtures.splitlines() != [
        "bash -n bench/scale/reloadstall/run-recovery-mass-dirty.sh",
        "python3 -m unittest discover -s bench/scale/reloadstall -p test_recovery_mass_dirty.py -v",
    ]:
        errors.append("mass-dirty receipt must run its controller negative fixtures before qualification")
    reserve = step_shell(job, "Reserve time for mass-dirty evidence finalization")
    driver = step_shell(job, "Run frozen-source daemon mass-dirty comparison")
    if any(required not in reserve for required in (
        'mkdir -p "$RUNNER_TEMP/update-group-recovery-mass-dirty"',
        'RECOVERY_MASS_DIRTY_DRIVER_DEADLINE={time.monotonic() + 110 * 60}',
    )) or any(required not in driver for required in (
        'Path("/proc/meminfo").read_text()', 'values["MemAvailable"]',
        'required = 12 * 1024**3', 'if available < required:',
        'raise SystemExit("fresh runner has less than 12 GiB available; refusing qualification")',
        "<<'PY' > \"$evidence/preflight.log\" 2>&1 || status=$?",
        'if [[ $status == 0 ]]; then', 'if [[ $remaining -gt 0 ]]; then',
        'os.environ["RECOVERY_MASS_DIRTY_DRIVER_DEADLINE"]',
        'timeout --foreground --signal=TERM --kill-after=150s "${remaining}s"',
        'bash bench/scale/reloadstall/run-recovery-mass-dirty.sh',
        '--head "$GITHUB_SHA"', '--output-dir "$evidence/campaign"',
        '--profile "$RECOVERY_MASS_DIRTY_PROFILE"', '--cohort "$RECOVERY_MASS_DIRTY_COHORT"',
        '> "$evidence/driver.log" 2>&1 || status=$?', 'status=124',
        'printf \'%s\\n\' "$status" > "$evidence/driver-invocation.exit"', 'exit "$status"',
    )):
        errors.append("mass-dirty driver must preflight 12 GiB, bound execution, and retain its real failure")
    finalizer_step = _named_step(job, "Finalize mass-dirty evidence even after failure")
    finalizer = step_shell(job, "Finalize mass-dirty evidence even after failure")
    if "        if: always()\n" not in finalizer_step or any(required not in finalizer for required in (
        'timeout --foreground --signal=TERM --kill-after=5s 60s',
        'python3 bench/scale/reloadstall/recovery_mass_dirty.py finalize "$evidence/campaign"',
        '> "$evidence/finalizer.log" 2>&1 || status=$?',
        'printf \'%s\\n\' "$status" > "$evidence/finalizer.exit"', 'exit "$status"',
    )):
        errors.append("mass-dirty finalizer must always run, retain failure evidence, and fail closed")
    upload = _named_step(job, "Upload mass-dirty evidence even after refusal or failure")
    if any(required not in upload for required in (
        '        if: always()', '        uses: actions/upload-artifact@v7',
        'name: update-group-recovery-mass-dirty-${{ matrix.profile }}-${{ matrix.cohort }}-${{ github.sha }}',
        'path: ${{ runner.temp }}/update-group-recovery-mass-dirty',
        'if-no-files-found: error', 'retention-days: 30',
    )):
        errors.append("mass-dirty receipt must always upload distinct retained evidence and reject missing files")
    if re.search(r"(?m)^\s*continue-on-error:", job) or "--correctness-only" in driver:
        errors.append("mass-dirty qualification must not suppress errors or substitute a correctness-only run")


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
    workflow_text: dict[str, str] = {}
    directory = root / ".github/workflows"
    for path in sorted((*directory.glob("*.yml"), *directory.glob("*.yaml"))):
        text = path.read_text()
        if not (commands := _cargo_commands(text)):
            continue
        workflow = path.relative_to(root).as_posix()
        workflow_text[workflow] = text
        for subcommand, command in commands:
            locked = list(LOCKED_TOKEN.finditer(command))
            separator = ARG_SEPARATOR.search(command)
            cargo_args = command[: separator.start()] if separator else command
            if MANIFEST_PATH_TOKEN.search(cargo_args):
                errors.append(f"{workflow}: {subcommand} command has --manifest-path; use the root workspace invocation: {command}")
            if not locked:
                errors.append(f"{workflow}: {subcommand} command is missing --locked: {command}")
            elif len(locked) > 1:
                errors.append(f"{workflow}: {subcommand} command has duplicate --locked: {command}")
            elif separator is not None and locked[0].start() > separator.start():
                errors.append(f"{workflow}: {subcommand} command has --locked after Cargo's -- separator: {command}")
    for (workflow, job), floor in MIN_ROOT_COMMANDS.items():
        text = workflow_text.get(workflow, "")
        if job:
            text = _jobs(text).get(job, "")
        counts = Counter(subcommand for subcommand, _ in _cargo_commands(text))
        if missing := floor - counts:
            scope = f"{workflow}:{job}" if job else workflow
            errors.append(f"{scope}: root Cargo commands removed: {dict(missing)}")


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

    concurrency = re.findall(
        r"(?m)^concurrency:\n  group:[ \t]*(.*?)[ \t]*\n  cancel-in-progress:[ \t]*(.*?)[ \t]*$",
        text,
    )
    if concurrency != [(RECOVERY_MEMORY_CONCURRENCY, "true")]:
        errors.append("receipt dispatch concurrency must isolate its run while retaining ordinary ref cancellation")

    # Ordinary manual re-tests must not implicitly start a hosted campaign.
    dispatch = text.split("\njobs:", 1)[0]
    input_block = re.search(
        r"(?m)^  workflow_dispatch:\n    inputs:\n      recovery_memory_receipt:\n(?:        [^\n]*\n)+",
        dispatch,
    )
    if input_block is None or any(
        re.findall(rf"(?m)^        {name}:[ \t]*(.*?)[ \t]*$", input_block.group()) != [value]
        for name, value in (("type", "boolean"), ("default", "false"), ("required", "false"))
    ):
        errors.append("recovery_memory_receipt input must be an optional default-false boolean")
    scan_input = re.search(r"(?m)^      recovery_receipt_mode:\n(?:        [^\n]*\n)+", dispatch)
    if scan_input is None or any(
        re.findall(rf"(?m)^        {name}:[ \t]*(.*?)[ \t]*$", scan_input.group()) != [value]
        for name, value in (("type", "choice"), ("options", "[memory, scan, retirement, mass-dirty]"),
                            ("default", "memory"), ("required", "false"))
    ):
        errors.append("recovery receipt mode must be an optional choice defaulting to memory")
    recovery = jobs.get("recovery_memory_receipt", "")
    if re.findall(r"(?m)^ {4}if:[ \t]*(.*?)[ \t]*$", recovery) != [RECOVERY_MEMORY_SELECTOR]:
        errors.append("recovery_memory_receipt must keep its operator-dispatch selector")
    if re.findall(r"(?m)^ {4}runs-on:[ \t]*(.*?)[ \t]*$", recovery) != ["ubuntu-24.04"]:
        errors.append("recovery_memory_receipt must use the fresh ubuntu-24.04 hosted runner")
    if len(re.findall(
        r"(?m)^ {6}- uses: dtolnay/rust-toolchain@v1[^\n]*\n {8}with:\n {10}toolchain: stable[ \t]*$",
        recovery,
    )) != 1:
        errors.append("recovery_memory_receipt must provide the stable toolchain input")

    matrix = re.findall(
        r"(?m)^        include: \$\{\{ fromJSON\(inputs\.recovery_receipt_mode == 'retirement' && '([^']*)' \|\| inputs\.recovery_receipt_mode == 'scan' && '([^']*)' \|\| '([^']*)'\) \}\}[ \t]*$",
        recovery,
    )
    try:
        selected_retirement, selected_scan, selected_memory = map(json.loads, matrix[0]) if len(matrix) == 1 else (None, None, None)
    except ValueError:
        selected_retirement = selected_scan = selected_memory = None
    expected_memory = [
        {"profile": profile, "cell": cell}
        for profile, cells in (
            ("ipv4-100k", ("dataset-reevaluate", "peer-down")),
            ("full-uc", ("dataset-reevaluate", "peer-down")),
            ("full-vpn", ("dataset-reevaluate", "peer-down", "widen")),
            ("mixed-widen", ("widen",)),
            ("full-uc", ("unsynchronized-dirty",)),
            ("full-vpn", ("unsynchronized-dirty",)),
        ) for cell in cells
    ]
    if selected_retirement != [{"profile": profile, "cell": "retirement"} for profile in ("full-uc", "full-vpn")]:
        errors.append("retirement mode must isolate the two full-table profiles")
    if selected_memory != expected_memory or selected_scan != [
        {"profile": profile, "cell": "capture-scan", "old_order": old_order}
        for profile in ("full-uc", "full-vpn", "evpn-soak") for old_order in ("sorted", "shuffled")
    ]:
        errors.append("recovery receipt matrix must preserve memory cells and isolate scan profiles/OLD orders")
    if (
        'RECOVERY_RECEIPT_MODE: ${{ inputs.recovery_receipt_mode || \'memory\' }}' not in recovery
        or '--mode "$RECOVERY_RECEIPT_MODE"' not in recovery
    ):
        errors.append("recovery receipt driver must receive the selected mode")
    if any(required not in recovery for required in (
        "RECOVERY_SCAN_OLD_ORDER: ${{ matrix.old_order || 'sorted' }}",
        'if [[ $RECOVERY_RECEIPT_MODE == scan && $RECOVERY_SCAN_OLD_ORDER == shuffled ]]; then',
        'scan_options=(--shuffled-old)',
        '--cell "$RECOVERY_MEMORY_CELL" "${scan_options[@]}"',
        "${{ matrix.old_order && format('-{0}', matrix.old_order) || '' }}",
    )):
        errors.append("component scans must preserve OLD order through invocation and artifact identity")

    _check_mass_dirty(jobs.get("recovery_mass_dirty_receipt", ""), errors)

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
