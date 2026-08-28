#!/usr/bin/env python3
"""Run the repository's exact developer-tooling lint contract."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSIONS = {
    "actionlint": "1.7.12",
    "ruff": "ruff 0.16.0",
}
ACTIONLINT_FLAGS = ("-no-color", "-shellcheck=", "-pyflakes=")


class CheckFailed(Exception):
    """The developer-tooling contract did not hold."""


def binary(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise CheckFailed(f"{name} is not installed or is absent from PATH")
    return path


def exact_version(command: list[str], expected: str) -> None:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    lines = result.stdout.splitlines()
    actual = lines[0].strip() if lines else ""
    if result.returncode != 0 or actual != expected:
        detail = actual or result.stderr.strip() or f"exit {result.returncode}"
        raise CheckFailed(f"expected {expected!r} from {' '.join(command)}, got {detail!r}")


def tools() -> tuple[str, str]:
    actionlint = binary("actionlint")
    ruff = binary("ruff")
    exact_version([actionlint, "-version"], EXPECTED_VERSIONS["actionlint"])
    exact_version([ruff, "--version"], EXPECTED_VERSIONS["ruff"])
    return actionlint, ruff


def expected_failure(command: list[str], needle: str) -> str:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    output = result.stdout + result.stderr
    if result.returncode == 0:
        raise CheckFailed(f"negative fixture unexpectedly passed: {' '.join(command)}")
    if needle not in output:
        raise CheckFailed(
            f"negative fixture did not report {needle!r}: {' '.join(command)}\n{output}"
        )
    return output


def self_test(actionlint: str, ruff: str) -> None:
    with tempfile.TemporaryDirectory(prefix="rustbgpd-developer-lint-") as temporary:
        fixture = Path(temporary)
        undefined_name = fixture / "undefined_name.py"
        undefined_name.write_text("print(missing_name)\n", encoding="utf-8")
        expected_failure(
            [
                ruff,
                "check",
                "--config",
                str(ROOT / "pyproject.toml"),
                str(undefined_name),
            ],
            "F821",
        )

        runner_temp = fixture / "runner-temp.yml"
        runner_temp.write_text(
            """name: invalid runner context
on: push
jobs:
  invalid:
    runs-on: ubuntu-latest
    env:
      TOOL_DIR: ${{ runner.temp }}
    steps:
      - run: 'true'
""",
            encoding="utf-8",
        )
        output = expected_failure(
            [actionlint, *ACTIONLINT_FLAGS, str(runner_temp)],
            "runner",
        )
        if "context" not in output:
            raise CheckFailed("actionlint runner.temp fixture did not report a context error")


def live_check(actionlint: str, ruff: str) -> None:
    subprocess.run([ruff, "check", "."], cwd=ROOT, check=True)
    subprocess.run([actionlint, *ACTIONLINT_FLAGS], cwd=ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove the lint gate rejects representative Python and workflow errors",
    )
    args = parser.parse_args()

    try:
        actionlint, ruff = tools()
        if args.self_test:
            self_test(actionlint, ruff)
        else:
            live_check(actionlint, ruff)
    except (CheckFailed, subprocess.CalledProcessError) as error:
        print(f"developer-tooling check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
