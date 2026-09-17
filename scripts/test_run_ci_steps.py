#!/usr/bin/env python3

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.run_ci_steps import LOCAL_SKIPS, ROOT, WORKFLOW, PlanError, plan, run

FIXTURE = """jobs:
  core:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - run: cargo check --locked
      - name: Write runner temp
        run: |
          set -eu
          touch "$RUNNER_TEMP/marker"

          test -f "$RUNNER_TEMP/marker"
      # A comment between steps ends the block above.
      - name: Needs a hosted base
        run: echo ${{ github.sha }}
      - name: Pipe without pipefail
        run: false | true
  after:
    steps:
      - name: Pipe with pipefail
        shell: bash
        run: false | true
"""
SKIPS = {"core": {"Needs a hosted base": "hosted only"}}


class RunCiStepsTests(unittest.TestCase):
    def test_live_plan_is_runnable(self) -> None:
        selected = plan((ROOT / WORKFLOW).read_text(), LOCAL_SKIPS)
        self.assertEqual(set(LOCAL_SKIPS), {job for job, _ in selected})

    def test_selects_named_run_steps_and_honours_skips(self) -> None:
        selected = plan(FIXTURE, SKIPS)
        self.assertEqual(
            ["Write runner temp", "Pipe without pipefail"],
            [step["name"] for _, step in selected],
        )
        self.assertEqual(
            'set -eu\ntouch "$RUNNER_TEMP/marker"\n\ntest -f "$RUNNER_TEMP/marker"',
            selected[0][1]["run"],
        )

    def test_rejects_stale_skips_and_hosted_only_steps(self) -> None:
        with self.assertRaisesRegex(PlanError, "not in"):
            plan(FIXTURE, {"core": {**SKIPS["core"], "Renamed step": "gone"}})
        with self.assertRaisesRegex(PlanError, "Needs a hosted base"):
            plan(FIXTURE, {"core": {}})
        with self.assertRaisesRegex(PlanError, "no job missing"):
            plan(FIXTURE, {"missing": {}})

    def test_runs_steps_with_github_shell_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch("tempfile.tempdir", temporary):
            root = Path(temporary)
            self.assertEqual(0, run(root, plan(FIXTURE, SKIPS)))
            self.assertEqual(1, run(root, plan(FIXTURE, {"after": {}})))


if __name__ == "__main__":
    unittest.main()
