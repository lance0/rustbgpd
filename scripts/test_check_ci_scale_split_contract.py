#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from scripts import check_ci_scale_split_contract as contract
from scripts.check_ci_scale_split_contract import (
    RETIRED_PRIVILEGED_WORKFLOW,
    WORKFLOWS,
    _jobs,
    aggregate_shell,
    check,
    step_shell,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/ci.yml"


class ScaleSplitContractTests(unittest.TestCase):
    def copy_workflows(self, root: Path) -> None:
        for workflow in {*WORKFLOWS, "Cargo.toml", *(pin[0] for pin in contract.MSRV_PINS)}:
            target = root / workflow
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / workflow, target)

    def mutate(
        self,
        old: str,
        new: str = "",
        occurrence: int = 0,
        workflow: str = WORKFLOW,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_workflows(root)
            target = root / workflow
            text = target.read_text()
            start = 0
            for _ in range(occurrence + 1):
                index = text.find(old, start)
                self.assertNotEqual(-1, index, f"missing occurrence: {old}")
                start = index + len(old)
            target.write_text(text[:index] + new + text[index + len(old) :])
            self.assertTrue(check(root), f"mutation stayed green: {old}")

    def test_live_contract(self) -> None:
        self.assertEqual([], check(ROOT))

    def test_recovery_memory_receipt_stays_optional_and_hosted(self) -> None:
        selector = f"    if: {contract.RECOVERY_MEMORY_SELECTOR}\n"
        cases = (
            ("  recovery_memory_receipt:\n", "  renamed_recovery_memory_receipt:\n"),
            (selector, ""),
            (selector, "    if: ${{ github.event_name == 'workflow_dispatch' }}\n"),
            (selector, selector.replace("'workflow_dispatch'", "'pull_request'")),
            (selector, "    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}\n"),
            (selector, "    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/fix/update-group-recovery-memory' }}\n"),
            (selector, f"    env:\n      RECEIPT_SELECTOR: {contract.RECOVERY_MEMORY_SELECTOR}\n"),
            ("    runs-on: ubuntu-24.04\n", ""),
            ("    runs-on: ubuntu-24.04\n", "    runs-on: self-hosted\n"),
            ("    runs-on: ubuntu-24.04\n", "    runs-on: [self-hosted, Linux]\n"),
            ("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-latest\n"),
        )
        for old, new in cases:
            with self.subTest(seam=old, replacement=new):
                self.mutate(old, new)

    def test_recovery_memory_receipt_dispatch_is_explicit_default_false(self) -> None:
        for old, new in (
            ("        default: false\n", ""),
            ("        default: false\n", "        default: true\n"),
            ("        type: boolean\n", "        type: string\n"),
            ("        required: false\n", "        required: true\n"),
            ("      recovery_memory_receipt:\n", "      wrong_input:\n"),
        ):
            with self.subTest(old=old, replacement=new):
                self.mutate(old, new)

    def test_receipt_concurrency_is_run_specific_only_when_opted_in(self) -> None:
        self.assertEqual([], check(ROOT))
        original = f"  group: {contract.RECOVERY_MEMORY_CONCURRENCY}\n"
        for replacement in (
            "  group: ${{ github.workflow }}-${{ github.ref }}\n",
            "  group: ${{ github.workflow }}-${{ github.run_id }}\n",
            original.replace(" && inputs.recovery_memory_receipt == true", ""),
            original.replace("github.run_id", "github.sha"),
            original.replace(" || github.ref", ""),
        ):
            with self.subTest(replacement=replacement):
                self.mutate(original, replacement)
        self.mutate("  cancel-in-progress: true\n", "  cancel-in-progress: false\n")

    def test_component_scan_mode_is_explicit_and_preserves_memory_matrix(self) -> None:
        for old, new in (
            ("        default: memory\n", "        default: scan\n"),
            ("        options: [memory, scan, retirement, mass-dirty]\n", "        options: [scan]\n"),
            ("        type: choice\n", "        type: boolean\n"),
            ("      recovery_receipt_mode:\n", "      ignored_mode:\n"),
            ("inputs.recovery_receipt_mode == 'scan'", "github.event_name == 'workflow_dispatch'"),
            ('{"profile":"evpn-soak","cell":"capture-scan","old_order":"sorted"}', '{"profile":"full-uc","cell":"capture-scan","old_order":"sorted"}'),
            ('{"profile":"full-vpn","cell":"capture-scan","old_order":"shuffled"}', '{"profile":"full-vpn","cell":"capture-scan","old_order":"sorted"}'),
            ('{"profile":"full-vpn","cell":"unsynchronized-dirty"}', '{"profile":"full-vpn","cell":"peer-down"}'),
            ('--mode "$RECOVERY_RECEIPT_MODE"', '--mode memory'),
        ):
            with self.subTest(old=old, replacement=new):
                self.mutate(old, new)

    def test_retirement_mode_is_explicit_and_keeps_both_full_table_profiles(self) -> None:
        for old, new in (
            ("inputs.recovery_receipt_mode == 'retirement'", "inputs.recovery_receipt_mode == 'memory'"),
            ('{"profile":"full-vpn","cell":"retirement"}', '{"profile":"full-uc","cell":"retirement"}'),
            ("[memory, scan, retirement, mass-dirty]", "[memory, scan, mass-dirty]"),
        ):
            with self.subTest(old=old):
                self.mutate(old, new)

    def test_recovery_memory_receipt_requires_an_actual_toolchain_input(self) -> None:
        tail = "      - name: Check recovery receipt negative fixtures\n"
        original = "        with:\n          toolchain: stable\n      - uses: ./.github/actions/install-protobuf\n" + tail
        for replacement in (
            "",
            "        with:\n          toolchain: '1.95'\n",
            "        env:\n          toolchain: stable\n",
        ):
            with self.subTest(replacement=replacement):
                self.mutate(original, replacement + "      - uses: ./.github/actions/install-protobuf\n" + tail)

    def test_component_scan_old_order_reaches_driver_and_artifact_identity(self) -> None:
        for old, new in (
            ("RECOVERY_SCAN_OLD_ORDER: ${{ matrix.old_order || 'sorted' }}", "RECOVERY_SCAN_OLD_ORDER: sorted"),
            ('if [[ $RECOVERY_RECEIPT_MODE == scan && $RECOVERY_SCAN_OLD_ORDER == shuffled ]]; then',
             'if [[ $RECOVERY_RECEIPT_MODE == scan ]]; then'),
            ('scan_options=(--shuffled-old)', 'scan_options=()'),
            ('--cell "$RECOVERY_MEMORY_CELL" "${scan_options[@]}"', '--cell "$RECOVERY_MEMORY_CELL"'),
            ("${{ matrix.old_order && format('-{0}', matrix.old_order) || '' }}", ""),
        ):
            with self.subTest(seam=old):
                self.mutate(old, new)

    def test_mass_dirty_mode_uses_only_its_dedicated_job(self) -> None:
        component = f"    if: {contract.RECOVERY_MEMORY_SELECTOR}\n"
        dedicated = f"    if: {contract.RECOVERY_MASS_DIRTY_SELECTOR}\n"
        for old, new in (
            (component, component.replace(" && inputs.recovery_receipt_mode != 'mass-dirty'", "")),
            (dedicated, ""),
            (dedicated, dedicated.replace(" && inputs.recovery_memory_receipt == true", "")),
            (dedicated, dedicated.replace("'workflow_dispatch'", "'pull_request'")),
            (dedicated, dedicated.replace("== 'mass-dirty'", "!= 'scan'")),
            ("  recovery_mass_dirty_receipt:\n", "  renamed_mass_dirty:\n"),
            ('{"profile":"full-vpn","cohort":"cap-pressure"}', '{"profile":"full-uc","cohort":"cap-pressure"}'),
            ('{"profile":"full-uc","cohort":"no-refusal"}', '{"profile":"full-uc","cohort":"cap-pressure"}'),
            ('RECOVERY_MASS_DIRTY_COHORT: ${{ matrix.cohort }}', 'RECOVERY_MASS_DIRTY_COHORT: no-refusal'),
        ):
            with self.subTest(seam=old):
                self.mutate(old, new)
        for old, new in (
            ("runs-on: ubuntu-24.04", "runs-on: self-hosted"),
            ("timeout-minutes: 120", "timeout-minutes: 360"),
            ("fail-fast: false", "fail-fast: true"),
            ("ref: ${{ github.sha }}", "ref: main"),
            ("fetch-depth: 0", "fetch-depth: 1"),
            ("toolchain: stable", "toolchain: nightly"),
            ('CARGO_BUILD_JOBS: "4"', 'CARGO_BUILD_JOBS: "8"'),
            ("uses: ./.github/actions/install-protobuf", "run: true"),
        ):
            with self.subTest(mass_dirty_seam=old), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.copy_workflows(root)
                path = root / WORKFLOW
                text = path.read_text()
                job = _jobs(text)["recovery_mass_dirty_receipt"]
                self.assertIn(old, job)
                path.write_text(text.replace(job, job.replace(old, new, 1), 1))
                self.assertTrue(check(root))

    def test_mass_dirty_failures_and_evidence_cannot_be_suppressed(self) -> None:
        for old, new in (
            ('timeout --foreground --signal=TERM --kill-after=150s "${remaining}s"',
             'timeout --signal=TERM --kill-after=150s "${remaining}s"'),
            ('timeout --foreground --signal=TERM --kill-after=150s "${remaining}s"',
             'timeout --foreground --signal=TERM --kill-after=30s "${remaining}s"'),
            ('timeout --foreground --signal=TERM --kill-after=5s 60s',
             'timeout --signal=TERM --kill-after=5s 60s'),
            ('timeout --foreground --signal=TERM --kill-after=5s 60s',
             'timeout --foreground --signal=TERM --kill-after=30s 60s'),
            ('required = 12 * 1024**3', 'required = 6 * 1024**3'),
            ('if available < required:', 'if False:'),
            ('if [[ $status == 0 ]]; then', 'if true; then'),
            ('RECOVERY_MASS_DIRTY_DRIVER_DEADLINE={time.monotonic() + 110 * 60}',
             'RECOVERY_MASS_DIRTY_DRIVER_DEADLINE={time.monotonic() + 119 * 60}'),
            ('--cohort "$RECOVERY_MASS_DIRTY_COHORT"', '--cohort no-refusal'),
            ('--head "$GITHUB_SHA"', '--head main'),
            ('> "$evidence/driver.log" 2>&1 || status=$?', '> "$evidence/driver.log" 2>&1 || true'),
            ('> "$evidence/finalizer.log" 2>&1 || status=$?', '> "$evidence/finalizer.log" 2>&1 || true'),
            ('Finalize mass-dirty evidence even after failure\n        if: always()',
             'Finalize mass-dirty evidence even after failure\n        if: success()'),
            ('Upload mass-dirty evidence even after refusal or failure\n        if: always()',
             'Upload mass-dirty evidence even after refusal or failure\n        if: success()'),
            ('python3 bench/scale/reloadstall/recovery_mass_dirty.py finalize "$evidence/campaign"',
             'python3 bench/scale/reloadstall/recovery_mass_dirty.py finalize "$evidence/other"'),
            ('if-no-files-found: error', 'if-no-files-found: warn'),
            ('name: update-group-recovery-mass-dirty-${{ matrix.profile }}-${{ matrix.cohort }}-${{ github.sha }}',
             'name: update-group-recovery-mass-dirty-${{ matrix.profile }}-${{ github.sha }}'),
            ('bash bench/scale/reloadstall/run-recovery-mass-dirty.sh',
             'bash bench/scale/reloadstall/run-recovery-mass-dirty.sh --correctness-only'),
            ('      - name: Run frozen-source daemon mass-dirty comparison\n',
             '      - name: Run frozen-source daemon mass-dirty comparison\n        continue-on-error: true\n'),
            ('python3 -m unittest discover -s bench/scale/reloadstall -p test_recovery_mass_dirty.py -v',
             'true'),
        ):
            with self.subTest(seam=old):
                # --head also exists in the component job; change only the
                # dedicated job so one receipt cannot mask another's loss.
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.copy_workflows(root)
                    path = root / WORKFLOW
                    text = path.read_text()
                    job = _jobs(text)["recovery_mass_dirty_receipt"]
                    self.assertIn(old, job)
                    path.write_text(text.replace(job, job.replace(old, new, 1), 1))
                    self.assertTrue(check(root), f"mutation stayed green: {old}")

    def test_mass_dirty_driver_and_finalizer_shell_keep_real_exit_codes(self) -> None:
        job = _jobs((ROOT / WORKFLOW).read_text())["recovery_mass_dirty_receipt"]
        driver = step_shell(job, "Run frozen-source daemon mass-dirty comparison")
        finalizer = step_shell(job, "Finalize mass-dirty evidence even after failure")
        self.assertTrue(driver)
        self.assertTrue(finalizer)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "bin"
            binary.mkdir()
            python = binary / "python3"
            python.write_text(textwrap.dedent("""\
                #!/bin/bash
                if [[ $1 == - ]]; then
                  source=$(cat)
                  if [[ $source == *MemAvailable* ]]; then
                    exit "$TEST_PREFLIGHT"
                  fi
                  printf '%s\\n' "$TEST_REMAINING"
                  exit 0
                fi
                printf '%s\\n' "$@" > "$TEST_FINALIZER_ARGS"
                exit "$TEST_FINALIZER"
                """))
            python.chmod(0o755)
            wrapper = root / "bench/scale/reloadstall/run-recovery-mass-dirty.sh"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text('printf \'%s\\n\' "$@" > "$TEST_DRIVER_ARGS"\nexit "$TEST_DRIVER"\n')
            env = os.environ | {
                "PATH": f"{binary}:{os.environ['PATH']}",
                "GITHUB_SHA": "a" * 40,
                "RECOVERY_MASS_DIRTY_PROFILE": "full-vpn",
                "RECOVERY_MASS_DIRTY_COHORT": "cap-pressure",
                "RECOVERY_MASS_DIRTY_DRIVER_DEADLINE": "999999999999",
                "TEST_DRIVER_ARGS": str(root / "driver.args"),
                "TEST_FINALIZER_ARGS": str(root / "finalizer.args"),
                "TEST_PREFLIGHT": "0", "TEST_DRIVER": "0",
                "TEST_FINALIZER": "0", "TEST_REMAINING": "3600",
            }
            for index, (preflight, remaining, driver_status, expected) in enumerate((
                (0, 3600, 0, 0), (0, 3600, 1, 1), (0, 3600, 124, 124),
                (1, 3600, 0, 1), (0, 0, 0, 124),
            )):
                with self.subTest(preflight=preflight, remaining=remaining, driver=driver_status):
                    runner = root / f"driver-{index}"
                    call_env = env | {
                        "RUNNER_TEMP": str(runner), "TEST_PREFLIGHT": str(preflight),
                        "TEST_REMAINING": str(remaining), "TEST_DRIVER": str(driver_status),
                    }
                    capture = root / "driver.args"
                    capture.unlink(missing_ok=True)
                    result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", driver],
                                            cwd=root, env=call_env, capture_output=True, text=True)
                    self.assertEqual(expected, result.returncode, result.stderr)
                    evidence = runner / "update-group-recovery-mass-dirty"
                    self.assertEqual(f"{expected}\n", (evidence / "driver-invocation.exit").read_text())
                    self.assertTrue((evidence / "preflight.log").exists())
                    if not preflight and remaining:
                        self.assertEqual([
                            "--head", "a" * 40, "--output-dir", str(evidence / "campaign"),
                            "--profile", "full-vpn", "--cohort", "cap-pressure",
                        ], capture.read_text().splitlines())
                    else:
                        self.assertFalse(capture.exists())
            for status in (0, 1, 124):
                with self.subTest(finalizer=status):
                    runner = root / f"finalizer-{status}"
                    result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", finalizer],
                                            cwd=root, env=env | {"RUNNER_TEMP": str(runner),
                                                              "TEST_FINALIZER": str(status)},
                                            capture_output=True, text=True)
                    self.assertEqual(status, result.returncode, result.stderr)
                    evidence = runner / "update-group-recovery-mass-dirty"
                    self.assertEqual(f"{status}\n", (evidence / "finalizer.exit").read_text())
                    self.assertEqual([
                        "bench/scale/reloadstall/recovery_mass_dirty.py", "finalize", str(evidence / "campaign"),
                    ], (root / "finalizer.args").read_text().splitlines())
                    self.assertTrue((evidence / "finalizer.log").exists())

    def test_mass_dirty_preflight_has_a_real_12_gib_boundary(self) -> None:
        job = _jobs((ROOT / WORKFLOW).read_text())["recovery_mass_dirty_receipt"]
        driver = step_shell(job, "Run frozen-source daemon mass-dirty comparison")
        body = re.search(r"<<'PY'[^\n]*\n(.*?)\nPY", driver, re.S)
        self.assertIsNotNone(body)
        for available, accepted in ((12 * 1024**2 - 1, False), (12 * 1024**2, True)):
            with self.subTest(available_kib=available), mock.patch.object(
                Path, "read_text", return_value=f"MemAvailable: {available} kB\n"
            ), mock.patch("builtins.print"):
                if accepted:
                    exec(compile(body.group(1), "<workflow-memory-preflight>", "exec"), {})
                else:
                    with self.assertRaises(SystemExit):
                        exec(compile(body.group(1), "<workflow-memory-preflight>", "exec"), {})

    def test_scale_profile_and_membership_are_required(self) -> None:
        for old, new in (
            ("lto = false\ncodegen-units = 16\nstrip = false\ndebug = 1", "lto = true\ncodegen-units = 1\nstrip = false\ndebug = 1"),
            ('    "bench/scale/reloadstall",\n', ""),
        ):
            with self.subTest(old=old):
                self.mutate(old, new, workflow="Cargo.toml")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_workflows(root)
            manifest = root / "Cargo.toml"
            manifest.write_text(manifest.read_text().replace(
                'default-members = [\n    ".",',
                'default-members = [\n    "bench/scale/reloadstall",\n    ".",', 1,
            ))
            self.assertIn(
                "Cargo.toml: scale harnesses must stay outside default-members",
                check(root),
            )

    def test_msrv_bump_names_every_stale_pin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_workflows(root)
            manifest = root / "Cargo.toml"
            msrv = tomllib.loads(manifest.read_text())["workspace"]["package"]["rust-version"]
            manifest.write_text(manifest.read_text().replace(f'rust-version = "{msrv}"', 'rust-version = "9.99"'))
            failures = check(root)
            self.assertEqual(len(contract.MSRV_PINS), len(failures), failures)
            for name, *_ in contract.MSRV_PINS:
                self.assertTrue(any(failure.startswith(f"{name}: MSRV pin") for failure in failures))
            for name in {pin[0] for pin in contract.MSRV_PINS}:
                path = root / name
                path.write_text(path.read_text().replace(msrv, "9.99"))
            self.assertEqual([], check(root))

    def test_each_msrv_pin_is_required_and_checked_independently(self) -> None:
        for name, _, _, pattern in contract.MSRV_PINS:
            for replacement in ["9.99", ""]:
                with self.subTest(file=name, pattern=pattern, replacement=replacement):
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        self.copy_workflows(root)
                        path = root / name
                        text = path.read_text()
                        match = re.search(pattern, text)
                        self.assertIsNotNone(match)
                        path.write_text(text[:match.start(1)] + replacement + text[match.end(1):])
                        self.assertTrue(any(failure.startswith(f"{name}: MSRV pin") for failure in check(root)))

    def test_nearby_keys_cannot_replace_action_inputs(self) -> None:
        for name, job, action, pattern in contract.MSRV_PINS:
            if not action:
                continue
            for destination in ["env", "other-action", "other-job"]:
                with self.subTest(file=name, action=action, destination=destination):
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        self.copy_workflows(root)
                        path = root / name
                        text = path.read_text()
                        body = _jobs(text)[job]
                        match = re.search(pattern, body)
                        self.assertIsNotNone(match)
                        pin = match.group(0).rstrip()
                        if action == "dtolnay/rust-toolchain":
                            changed = body.replace(f"        with:\n{pin}\n", "", 1)
                        else:
                            changed = body.replace(pin + "\n", "", 1)
                        self.assertNotEqual(body, changed)
                        moved = {
                            "env": f"      - run: true\n        env:\n{pin}\n",
                            "other-action": f"      - uses: example/irrelevant@v1\n        with:\n{pin}\n",
                            "other-job": f"  unrelated:\n    steps:\n      - uses: {action}@v1\n        with:\n{pin}\n",
                        }[destination]
                        if destination == "other-job":
                            text = text.replace(body, changed, 1) + "\n" + moved
                        else:
                            text = text.replace(body, changed + moved + "\n", 1)
                        path.write_text(text)
                        self.assertTrue(any(failure.startswith(f"{name}: MSRV pin") for failure in check(root)))

    def test_gate_msrv_uses_the_installed_toolchain_name(self) -> None:
        recipe = (ROOT / "justfile").read_text().split("gate-msrv:\n", 1)[1].split("\n#", 1)[0]
        recipe = textwrap.dedent(recipe)
        cases = (
            ("1.95", "1.95-x86_64-unknown-linux-gnu (default)\n", "1.95-x86_64-unknown-linux-gnu"),
            ("1.95", "1.95.0-x86_64-unknown-linux-gnu\n", "1.95.0-x86_64-unknown-linux-gnu"),
            ("1.95", "1.95.1-x86_64-unknown-linux-gnu\n", "1.95.1-x86_64-unknown-linux-gnu"),
            ("1.95.1", "1.95.0-x86_64-unknown-linux-gnu\n1.95.1-x86_64-unknown-linux-gnu\n", "1.95.1-x86_64-unknown-linux-gnu"),
            ("1.95", "1.950.0-x86_64-unknown-linux-gnu\nnightly-x86_64-unknown-linux-gnu\n", None),
            ("1.95.1", "1.95.0-x86_64-unknown-linux-gnu\n", None),
        )
        for msrv, installed, expected in cases:
            with self.subTest(msrv=msrv, installed=installed):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    (root / "Cargo.toml").write_text(f'[workspace.package]\nrust-version = "{msrv}"\n')
                    (root / "scripts").mkdir()
                    (root / "scripts/build-lock.sh").write_text('exec "$@"\n')
                    for name, body in {
                        "rustup": 'printf "%s" "$MSRV_INSTALLED"',
                        "cargo": 'printf "%s\\n" "$@" > "$MSRV_CAPTURE"',
                    }.items():
                        executable = root / name
                        executable.write_text(f"#!/bin/sh\n{body}\n")
                        executable.chmod(0o755)
                    capture = root / "invocation"
                    result = subprocess.run(
                        ["bash", "-c", recipe], cwd=root, capture_output=True, text=True,
                        env=os.environ | {"PATH": f"{root}:{os.environ['PATH']}", "MSRV_INSTALLED": installed, "MSRV_CAPTURE": str(capture)},
                    )
                    if expected is None:
                        self.assertEqual(127, result.returncode, result.stderr)
                        self.assertFalse(capture.exists())
                        self.assertIn(f"rustup toolchain install {msrv}", result.stderr)
                    else:
                        self.assertEqual(0, result.returncode, result.stderr)
                        self.assertEqual([f"+{expected}", "check", "--locked", "--workspace", "--all-targets"], capture.read_text().splitlines())

    def test_retired_privileged_workflow_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_workflows(root)
            retired = root / RETIRED_PRIVILEGED_WORKFLOW
            retired.write_text(
                "on:\n  workflow_dispatch:\n"
                "jobs:\n  netns:\n    steps:\n"
                "      - run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh all\n"
            )
            self.assertIn(
                f"retired workflow must stay absent: {RETIRED_PRIVILEGED_WORKFLOW}",
                "\n".join(check(root)),
            )

    def test_comments_toolchain_selector_and_new_workflow_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_workflows(root)
            target = root / WORKFLOW
            target.write_text(
                "# cargo check --workspace\n"
                + target.read_text().replace(
                    "cargo check --locked -p rustbgpd-rib",
                    "cargo +1.95 check --locked -p rustbgpd-rib",
                    1,
                )
            )
            self.assertEqual([], check(root))
            added = root / ".github/workflows/new.yml"
            added.write_text("jobs:\n  new:\n    steps:\n      - run: cargo +1.95 check --workspace\n")
            self.assertIn("command is missing --locked", "\n".join(check(root)))
            added.write_text(added.read_text().replace("check --workspace", "check --locked --locked --workspace"))
            self.assertIn("command has duplicate --locked", "\n".join(check(root)))
            added.unlink()
            target.write_text(target.read_text() + "\n      - run: cargo check --workspace -- --locked \\\n")
            self.assertIn("command has --locked after Cargo's -- separator", "\n".join(check(root)))

    def test_lockfile_fidelity_mutations_fail_closed(self) -> None:
        cases = (
            (
                WORKFLOW,
                "cargo clippy --locked --workspace --all-targets",
                "cargo clippy --workspace --all-targets",
            ),
            (
                ".github/workflows/update-group-fault.yml",
                'listing="$(cargo test --locked -p rustbgpd-rib --lib "$test_name" -- --ignored --exact --list)"',
                'listing="$(cargo test -p rustbgpd-rib --lib "$test_name" -- --ignored --exact --list)" --locked',
            ),
            (
                WORKFLOW,
                "cargo check --locked -p rustbgpd-rib --features bench-internals --benches",
                "cargo check -p rustbgpd-rib --features bench-internals --benches; echo --locked",
            ),
            (
                WORKFLOW,
                "cargo test --locked -p rustbgpd --no-default-features --features bench-internals --test policy_set_store_allocation shared_set_batch_allocations_do_not_scale_per_peer -- --exact",
                "cargo test -p rustbgpd --no-default-features --features bench-internals --test policy_set_store_allocation shared_set_batch_allocations_do_not_scale_per_peer -- --locked --exact",
            ),
            (
                WORKFLOW,
                "cargo test --locked -p enhanced-route-refresh-receipt -p reloadstall -p rrharness -p rrtransport",
                "cargo test --locked -p reloadstall -p rrharness -p rrtransport",
            ),
            (
                WORKFLOW,
                "cargo run --locked -p rrtransport -- smoke",
                "cargo run --locked -p rrtransport -- other",
            ),
            (
                WORKFLOW,
                "- run: cargo test --locked --workspace",
                "- run: cargo test --locked --workspace\n      - run: cargo check --workspace",
            ),
            (
                WORKFLOW,
                "cargo build --locked -p rs-config-render",
                "true",
            ),
            (
                WORKFLOW,
                "cargo build --locked -p reloadstall",
                "true",
            ),
        )
        for workflow, old, new in cases:
            with self.subTest(workflow=workflow, seam=old):
                self.mutate(old, new, workflow=workflow)

    def test_scale_commands_cannot_mask_removed_core_commands(self) -> None:
        for subcommand, command in (
            ("clippy", "cargo clippy --locked --workspace --all-targets -- -D warnings"),
            ("clippy", "cargo clippy --locked -p rustbgpd-wire --all-targets --features tokio-codec -- -D warnings"),
            ("test", "cargo test --locked -p rustbgpd-mrt --bench snapshot_allocation -- timing --candidate --smoke"),
        ):
            with self.subTest(command=command):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.copy_workflows(root)
                    target = root / WORKFLOW
                    text = target.read_text()
                    self.assertEqual(1, text.count(command))
                    target.write_text(text.replace(command, "true", 1))
                    self.assertIn(
                        f"{WORKFLOW}:core: root Cargo commands removed: {{{subcommand!r}: 1}}",
                        check(root),
                    )

    def test_extra_manifest_commands_are_rejected(self) -> None:
        for workflow in (WORKFLOW, ".github/workflows/release.yml", ".github/workflows/new.yml"):
            for option in ("--manifest-path bench/scale/Cargo.toml", "--manifest-path=bench/scale/Cargo.toml"):
                with self.subTest(workflow=workflow, option=option):
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        self.copy_workflows(root)
                        target = root / workflow
                        text = target.read_text() if target.exists() else "name: extra\njobs:\n  extra:\n    steps:\n"
                        target.write_text(text + f"\n      - run: cargo check --locked {option}\n")
                        self.assertIn("command has --manifest-path", "\n".join(check(root)))

    def test_binary_manifest_option_is_not_a_cargo_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_workflows(root)
            (root / ".github/workflows/new.yml").write_text(
                "name: extra\njobs:\n  extra:\n    steps:\n"
                "      - run: cargo run --locked -p rrtransport -- --manifest-path receipt.json\n"
            )
            self.assertEqual([], check(root))

    def test_added_locked_command_passes_and_blind_extractor_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_workflows(root)
            target = root / WORKFLOW
            target.write_text(
                target.read_text().replace(
                    "- run: cargo test --locked --workspace",
                    "- run: cargo test --locked --workspace\n"
                    "      - run: cargo check --locked -p rustbgpd-api",
                    1,
                )
            )
            self.assertEqual([], check(root))
        # A command regex that matches nothing sees no workflow at all.
        with mock.patch.object(contract, "CARGO_COMMAND", re.compile(r"(?!)")):
            failures = "\n".join(check(ROOT))
        self.assertIn("root Cargo commands removed", failures)
        self.assertIn("scale receipt Cargo command missing", failures)

    def test_semantic_mutations_fail_closed(self) -> None:
        cases = (
            ("  core:\n", "  renamed_core:\n"),
            ("  core_tests:\n", "  renamed_core_tests:\n"),
            ("  scale_receipts:\n", "  renamed_scale:\n"),
            ("  check:\n", "  renamed_check:\n"),
            ("  msrv:\n", "  renamed_msrv:\n"),
            ("  evpn_bum_filter_kernel:\n", "  renamed_evpn:\n"),
            ("- run: cargo test --locked --workspace", "- run: true"),
            ("- run: cargo doc --locked --workspace --lib --bin rustbgpd --bin rbgp --no-deps --document-private-items", "- run: true"),
            ("--lib --bin rustbgpd --bin rbgp", "--bin rustbgpd --bin rbgp"),
            ("--bin rustbgpd --bin rbgp", "--bin rbgp"),
            ("--bin rustbgpd --bin rbgp", "--bin rustbgpd"),
            ("--document-private-items", ""),
            (
                "- run: cargo clippy --locked -p rustbgpd-wire --all-targets --features tokio-codec -- -D warnings",
                "- run: true",
            ),
            (
                "- run: cargo test --locked -p rustbgpd-wire --features tokio-codec",
                "- run: true",
            ),
            (
                "- run: cargo doc --locked -p rustbgpd-wire --lib --no-deps --features tokio-codec",
                "- run: true",
            ),
            ('RUSTDOCFLAGS: "-D warnings"', 'RUSTDOCFLAGS: ""'),
            ("if: ${{ always() }}", "if: ${{ success() }}"),
            (
                "needs: [core, core_tests, scale_receipts]",
                "needs: [core]",
            ),
            ("CORE_RESULT: ${{ needs.core.result }}", "CORE_RESULT: success"),
            (
                "CORE_TESTS_RESULT: ${{ needs.core_tests.result }}",
                "CORE_TESTS_RESULT: success",
            ),
            (
                "SCALE_RECEIPTS_RESULT: ${{ needs.scale_receipts.result }}",
                "SCALE_RECEIPTS_RESULT: success",
            ),
            (
                '[[ "$CORE_RESULT" != "success" || "$CORE_TESTS_RESULT" != '
                '"success" || "$SCALE_RECEIPTS_RESULT" != "success" ]]',
                "[[ false ]]",
            ),
        )
        for old, new in cases:
            with self.subTest(seam=old):
                self.mutate(old, new)

    def test_aggregate_shell_truth_table(self) -> None:
        shell = aggregate_shell(_jobs((ROOT / WORKFLOW).read_text())["check"])
        self.assertTrue(shell)

        def run(values):
            env = os.environ.copy()
            for name in ("CORE", "CORE_TESTS", "SCALE_RECEIPTS"):
                env.pop(f"{name}_RESULT", None)
            for name, value in values.items():
                if value is not None:
                    env[f"{name}_RESULT"] = value
            return subprocess.run(["bash", "-c", shell], env=env, capture_output=True)

        names = ("CORE", "CORE_TESTS", "SCALE_RECEIPTS")
        good = {name: "success" for name in names}
        self.assertEqual(0, run(good).returncode)
        for name in good:
            for bad in ("failure", "cancelled", "skipped", "", None):
                values = good | {name: bad}
                with self.subTest(child=name, result=bad):
                    self.assertNotEqual(0, run(values).returncode)


if __name__ == "__main__":
    unittest.main()
