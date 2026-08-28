#!/usr/bin/env python3
"""Prove the kernel-dataplane bird3-outage tolerance is exactly one skip wide.

The `check` aggregate in `.github/workflows/kernel-dataplane.yml` tolerates
`m43=skipped` when — and only when — the bird3 producer succeeded and published
`bird3_status=unavailable`. A gate that can no longer fail is worse than the
problem it fixed, so the aggregate's real shell body is extracted from the
workflow and executed here against stubbed `needs` contexts: every genuine
failure must still exit non-zero.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "kernel-dataplane.yml"
INSTALLER = ROOT / ".github" / "scripts" / "install-bird3.sh"

EXPECTED_JOBS = """
classify_changes grpcurl_archive gobgp_archive bird3_archive prime_dev_image
m36 m37 m37-ip m38 m39
m39b m48 m60 m61 m62 m40 m42 m50 m52 m58 m53 m51 m43 m47
m69 m70 m65 m71 m72 m66 m67 m68 netns
""".split()

EXCUSE = "m43=skipped (bird3 archive unavailable upstream)"


def aggregate_source() -> str:
    """Return the aggregate's real Python body, as the workflow runs it."""
    text = WORKFLOW.read_text()
    body = text.split("\njobs:\n", 1)[1]
    match = re.search(r"(?ms)^  check:\n(.*?)(?=^  [\w-]+:\n|\Z)", body)
    assert match is not None, "check job not found"
    inline = re.search(
        r"(?ms)^          python3 - <<'PY'\n(.*?)^          PY$", match.group(1)
    )
    assert inline is not None, "inline aggregate script not found"
    return textwrap.dedent(inline.group(1))


def needs_context(
    *,
    run_labs: str = "true",
    bird3_status: str | None = "ok",
    bird3_result: str | None = None,
    m43_result: str | None = None,
    tcp_ao_supported: str | None = "true",
) -> dict[str, dict]:
    default = "success" if run_labs == "true" else "skipped"
    needs = {job: {"result": default} for job in EXPECTED_JOBS}
    needs["classify_changes"] = {
        "result": "success",
        "outputs": {"run_labs": run_labs},
    }
    needs["bird3_archive"] = {"result": bird3_result or default}
    if bird3_status is not None:
        needs["bird3_archive"]["outputs"] = {"bird3_status": bird3_status}
    needs["m43"] = {"result": m43_result or default}
    if tcp_ao_supported is not None:
        needs["m43"]["outputs"] = {"tcp_ao_supported": tcp_ao_supported}
    return needs


def run_aggregate(needs: dict[str, dict]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", aggregate_source()],
        env={
            "NEEDS_CONTEXT": json.dumps(needs),
            "EXPECTED_JOBS": " ".join(EXPECTED_JOBS),
            "PATH": "/usr/bin:/bin",
        },
        capture_output=True,
        text=True,
        check=False,
    )


class Bird3ToleranceTests(unittest.TestCase):
    def test_all_green_passes_with_a_bare_roster(self) -> None:
        result = run_aggregate(needs_context())
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("m43=success\n", result.stdout)
        self.assertNotIn("unavailable", result.stdout)

    def test_upstream_unavailable_passes_loudly(self) -> None:
        result = run_aggregate(
            needs_context(bird3_status="unavailable", m43_result="skipped")
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(f"{EXCUSE}\n", result.stdout)
        self.assertIn(f"::warning::{EXCUSE}", result.stdout)
        # Every other scenario keeps its ordinary roster entry.
        self.assertIn("m47=success\n", result.stdout)

    def test_m43_running_and_failing_still_fails(self) -> None:
        result = run_aggregate(
            needs_context(bird3_status="unavailable", m43_result="failure")
        )
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("m43=failure\n", result.stdout)
        self.assertNotIn(EXCUSE, result.stdout)

    def test_m43_success_with_tcp_ao_disabled_fails(self) -> None:
        # A green m43 on a kernel without CONFIG_TCP_AO=y ran zero lab
        # steps; the aggregate must treat that success as a coverage hole.
        for tcp_ao in ("false", None):
            with self.subTest(tcp_ao_supported=tcp_ao):
                result = run_aggregate(needs_context(tcp_ao_supported=tcp_ao))
                self.assertEqual(1, result.returncode, result.stdout)
                self.assertIn("every TCP-AO step was disabled", result.stdout)

    def test_excused_skip_needs_no_tcp_ao_output(self) -> None:
        # A skipped job publishes no outputs; the excused bird3 skip must
        # not additionally be charged with the missing TCP-AO verdict.
        result = run_aggregate(
            needs_context(
                bird3_status="unavailable",
                m43_result="skipped",
                tcp_ao_supported=None,
            )
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_corrupt_archive_stays_red(self) -> None:
        # A checksum/version failure on bytes that DID download is a
        # supply-chain signal: the producer exits non-zero, so m43 skips
        # without an excuse and the aggregate must fail.
        result = run_aggregate(
            needs_context(
                bird3_status="corrupt",
                bird3_result="failure",
                m43_result="skipped",
            )
        )
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("bird3_archive=failure\n", result.stdout)
        self.assertNotIn(EXCUSE, result.stdout)

    def test_bare_m43_skip_is_not_excused(self) -> None:
        for status in ("ok", "corrupt", None):
            with self.subTest(bird3_status=status):
                result = run_aggregate(
                    needs_context(bird3_status=status, m43_result="skipped")
                )
                self.assertEqual(1, result.returncode, result.stdout)
                self.assertNotIn(EXCUSE, result.stdout)

    def test_unavailable_excuses_only_m43(self) -> None:
        needs = needs_context(bird3_status="unavailable", m43_result="skipped")
        needs["m51"] = {"result": "skipped"}
        result = run_aggregate(needs)
        self.assertEqual(1, result.returncode, result.stdout)

    def test_lab_free_run_still_requires_every_job_skipped(self) -> None:
        self.assertEqual(
            0, run_aggregate(needs_context(run_labs="false")).returncode
        )
        noisy = needs_context(run_labs="false")
        noisy["m43"] = {"result": "failure"}
        self.assertEqual(1, run_aggregate(noisy).returncode)

    def test_workflow_wiring(self) -> None:
        text = WORKFLOW.read_text()
        for seam in (
            "bird3_status: ${{ steps.prepare.outputs.bird3_status }}",
            "if: needs.bird3_archive.outputs.bird3_status != 'unavailable'",
            "if: steps.prepare.outputs.bird3_status == 'ok'",
            "tcp_ao_supported: ${{ steps.tcp_ao.outputs.supported }}",
            "3) status=unavailable ;;",
            "4) status=corrupt ;;",
        ):
            self.assertIn(seam, text, f"kernel-dataplane.yml missing {seam}")
        # The tolerance must never be spelled with continue-on-error, which
        # would swallow genuine m43 failures too.
        self.assertNotIn("continue-on-error", text)

    def test_installer_classifies_outage_apart_from_corruption(self) -> None:
        result = subprocess.run(
            ["bash", str(INSTALLER), "--self-test"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
