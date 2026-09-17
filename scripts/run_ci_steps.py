#!/usr/bin/env python3
"""Run hosted CI's named script steps locally, read from the workflow itself.

Every named `run:` step of the jobs in LOCAL_SKIPS runs in workflow order
unless LOCAL_SKIPS names it, so a script step added to CI runs here without a
second copy to keep in sync. Unnamed steps are single commands that
`just gate`, `just test-feature-gated`, and `just gate-msrv` mirror; `uses:`
steps are hosted actions and never run here.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/ci.yml"
INSTALLS_TOOLS = "installs CI tooling; install ripgrep and shellcheck locally"
LOCAL_SKIPS = {
    "core": {
        "Install exact developer linters": "`just check-devtools` checks the local pins",
        "Install receipt-tool dependencies": INSTALLS_TOOLS,
        "Smoke benchmark targets without dedicated checks": "`just test-feature-gated`",
        "Smoke selection-deferral release receipt": "`just test-feature-gated`",
        "Smoke MRT snapshot allocation benchmark modes": "`just test-feature-gated`",
        "Gate eager policy-set sharing allocation shape": "`just test-feature-gated`",
        "Published crate README freshness gate": "needs the pull request base",
    },
    "scale_receipts": {
        "Install receipt-tool dependencies": INSTALLS_TOOLS,
    },
}
KEY = re.compile(r"^ {8}([\w-]+):[ \t]*(.*)$")


class PlanError(Exception):
    """The workflow holds a step this runner cannot reproduce."""


def job_steps(text: str, job: str) -> list[dict[str, str]]:
    """Return the top-level keys of each step in `job`."""
    match = re.search(rf"(?ms)^  {re.escape(job)}:\n(.*?)(?=^ {{0,2}}\S|\Z)", text)
    if match is None or "\n    steps:\n" not in f"\n{match.group(1)}":
        raise PlanError(f"{WORKFLOW} has no job {job} with steps")
    body = match.group(1).split("    steps:\n", 1)[1]
    steps = []
    for chunk in re.split(r"(?m)^ {6}- ", body)[1:]:
        lines = (" " * 8 + chunk).splitlines()
        fields: dict[str, str] = {}
        index = 0
        while index < len(lines):
            key = KEY.match(lines[index])
            index += 1
            if key is None:
                continue
            name, value = key.groups()
            if value in ("|", "|-"):
                block = []
                while index < len(lines) and (
                    not lines[index].strip() or lines[index].startswith(" " * 10)
                ):
                    block.append(lines[index][10:])
                    index += 1
                value = "\n".join(block).strip("\n")
            fields[name] = value
        steps.append(fields)
    return steps


def plan(text: str, skips: dict[str, dict[str, str]]) -> list[tuple[str, dict[str, str]]]:
    """Return the (job, step) pairs to run, failing closed on anything unsupported."""
    selected = []
    for job, job_skips in skips.items():
        named = [step for step in job_steps(text, job) if "name" in step and "run" in step]
        stale = set(job_skips) - {step["name"] for step in named}
        if stale:
            raise PlanError(f"{job}: skipped steps not in {WORKFLOW}: {sorted(stale)}")
        for step in named:
            if step["name"] in job_skips:
                continue
            unsupported = set(step) - {"name", "run", "shell"}
            if unsupported or step.get("shell", "bash") != "bash" or "${{" in step["run"]:
                raise PlanError(
                    f"{job}: cannot run {step['name']!r} locally (keys {sorted(step)}); "
                    "skip it in scripts/run_ci_steps.py with a reason"
                )
            selected.append((job, step))
    return selected


def bash_argv(step: dict[str, str]) -> list[str]:
    """Match GitHub's Linux shells: `bash -e {0}`, or pipefail for `shell: bash`."""
    if "shell" in step:
        return ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]]
    return ["bash", "-e", "-c", step["run"]]


def run(root: Path, selected: list[tuple[str, dict[str, str]]]) -> int:
    runner_temp = Path(tempfile.mkdtemp(prefix="rustbgpd-ci-steps-"))
    for job, step in selected:
        print(f"==> {job}: {step['name']}", file=sys.stderr, flush=True)
        job_temp = runner_temp / job
        job_temp.mkdir(exist_ok=True)
        env = {**os.environ, "RUNNER_TEMP": str(job_temp)}
        result = subprocess.run(bash_argv(step), cwd=root, env=env, check=False)
        if result.returncode != 0:
            print(
                f"{job}: {step['name']!r} failed with exit {result.returncode}; "
                f"RUNNER_TEMP kept at {job_temp}",
                file=sys.stderr,
            )
            return 1
    shutil.rmtree(runner_temp)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jobs", nargs="*", help=f"any of {', '.join(LOCAL_SKIPS)} (default: all)")
    parser.add_argument("--dry-run", action="store_true", help="print the plan only")
    args = parser.parse_args()
    if unknown := set(args.jobs) - set(LOCAL_SKIPS):
        parser.error(f"unknown jobs: {sorted(unknown)}")
    skips = {job: LOCAL_SKIPS[job] for job in args.jobs or LOCAL_SKIPS}
    try:
        selected = plan((ROOT / WORKFLOW).read_text(), skips)
    except PlanError as error:
        print(f"CI step plan failed: {error}", file=sys.stderr)
        return 1
    if args.dry_run:
        for job, step in selected:
            print(f"{job}: {step['name']}")
        return 0
    return run(ROOT, selected)


if __name__ == "__main__":
    raise SystemExit(main())
