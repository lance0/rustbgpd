#!/usr/bin/env python3
"""Offline checks for the OpenBGPD image-primer retry boundary."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / ".github/scripts/retry-docker-image.sh"
INTEROP = (ROOT / ".github/workflows/interop.yml").read_text()


def primer(label):
    match = re.search(
        rf"(?ms)^      - name: Verify and pull digest-pinned OpenBGPD {label}[^\n]*\n"
        r"(.*?)(?=^      - name: |^  \w+:|\Z)", INTEROP
    )
    assert match, label
    step = match.group(1)
    env = dict(re.findall(r"^          (OPENBGPD_\w+): (\S+)$", step, re.M))
    body = step.split("        run: |\n", 1)[1]
    return env, textwrap.dedent(body)


class RetryDockerImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        bin_dir = self.path / "bin"
        bin_dir.mkdir()
        docker = bin_dir / "docker"
        docker.write_text(textwrap.dedent("""\
            #!/usr/bin/env python3
            import json, os, pathlib, sys
            base = pathlib.Path(os.environ['FAKE_LOG'])
            args = sys.argv[1:]
            op = 'pull' if args[0] == 'pull' else ('leaf' if args[-1] != os.environ['OPENBGPD_IMAGE'] else 'index')
            count_file = base / op
            count = int(count_file.read_text()) + 1 if count_file.exists() else 1
            count_file.write_text(str(count))
            with (base / 'calls').open('a') as log:
                log.write(json.dumps([args, os.environ.get('DOCKER_CONFIG')]) + '\\n')
            if count <= int(os.environ.get('FAIL_' + op.upper(), '0')):
                print('partial-' + op)
                print('error-' + op, file=sys.stderr)
                sys.exit(int(os.environ.get('FAIL_CODE', '37')))
            if op == 'pull':
                print('pulled')
            elif op == 'leaf':
                print(json.dumps({'config': {'digest': os.environ.get('FAKE_CONFIG', os.environ['OPENBGPD_CONFIG'])}}))
            else:
                case = os.environ.get('FAKE_INDEX', 'valid')
                if case == 'malformed':
                    print('{bad json')
                else:
                    leaf = os.environ.get('FAKE_LEAF', os.environ['OPENBGPD_AMD64_MANIFEST'])
                    manifests = [{'platform': {'os': 'linux', 'architecture': 'amd64'}, 'digest': leaf}]
                    if case == 'zero':
                        manifests = []
                    if case == 'multiple':
                        manifests *= 2
                    print(json.dumps({'manifests': manifests}))
            """))
        docker.chmod(0o755)
        sleeper = bin_dir / "sleep"
        sleeper.write_text("#!/bin/sh\nprintf '%s\\n' \"$1\" >>\"$FAKE_LOG/sleeps\"\n")
        sleeper.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "FAKE_LOG": str(self.path),
            "DOCKER_CONFIG": str(self.path / "synthetic-docker-config"),
            "OPENBGPD_IMAGE": "openbgpd/openbgpd@sha256:" + "a" * 64,
            "OPENBGPD_AMD64_MANIFEST": "sha256:" + "b" * 64,
            "OPENBGPD_CONFIG": "sha256:" + "c" * 64,
        }

    def run_helper(self, **extra):
        return subprocess.run(
            [str(HELPER), "docker", "buildx", "imagetools", "inspect", "--raw", self.env['OPENBGPD_IMAGE']],
            cwd=ROOT, env={**self.env, **extra}, capture_output=True, text=True, check=False,
        )

    def calls(self):
        path = self.path / "calls"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def sleeps(self):
        path = self.path / "sleeps"
        return path.read_text().splitlines() if path.exists() else []

    def test_first_attempt_succeeds_without_sleep(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['manifests'][0]['digest'], self.env['OPENBGPD_AMD64_MANIFEST'])
        self.assertEqual(result.stderr, "")
        self.assertEqual(self.sleeps(), [])
        self.assertEqual(self.calls(), [[["buildx", "imagetools", "inspect", "--raw", self.env['OPENBGPD_IMAGE']], self.env['DOCKER_CONFIG']]])

    def test_third_attempt_recovers_with_clean_stdout(self):
        result = self.run_helper(FAIL_INDEX="2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("partial", result.stdout)
        self.assertEqual(result.stderr, "error-index\npartial-index\n" * 2)
        self.assertEqual(self.sleeps(), ["5", "10"])
        self.assertEqual(len(self.calls()), 3)

    def test_last_failure_preserves_exit_code_without_final_sleep(self):
        result = self.run_helper(FAIL_INDEX="3", FAIL_CODE="47")
        self.assertEqual(result.returncode, 47)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "error-index\npartial-index\n" * 3)
        self.assertEqual(self.sleeps(), ["5", "10"])

    def test_both_workflow_bodies_retry_each_network_operation(self):
        for label in ("9.1", "9.3"):
            with self.subTest(label=label):
                for op in ("index", "leaf", "pull"):
                    (self.path / op).unlink(missing_ok=True)
                env, body = primer(label)
                # Keep real per-step pins; fail twice independently at each Docker call.
                result = subprocess.run(
                    ["bash", "-eo", "pipefail", "-c", body], cwd=ROOT,
                    env={**self.env, **env, "FAIL_INDEX": "2", "FAIL_LEAF": "2", "FAIL_PULL": "2"},
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "pulled\n")
                self.assertEqual(self.sleeps()[-6:], ["5", "10"] * 3)
                self.assertEqual([call[0][0] for call in self.calls()[-9:]], ["buildx"] * 6 + ["pull"] * 3)
                self.assertTrue(all(call[1] == self.env['DOCKER_CONFIG'] for call in self.calls()[-9:]))

    def test_every_docker_hub_network_call_retries(self):
        # GHCR and Quay pulls are outside this boundary; every other pull or
        # registry inspect in the interop workflow targets Docker Hub.
        sites = [line for line in INTEROP.splitlines()
                 if re.search(r"docker (pull|buildx imagetools inspect)\b", line)
                 and not re.search(r"\b(ghcr|quay)\.io/", line)]
        self.assertGreaterEqual(len(sites), 9)
        for line in sites:
            with self.subTest(line=line.strip()):
                self.assertIn(".github/scripts/retry-docker-image.sh docker ", line)

    def test_bad_metadata_fails_before_pull(self):
        for label in ("9.1", "9.3"):
            env, body = primer(label)
            for case in ("malformed", "zero", "multiple", "wrong_leaf", "wrong_config"):
                with self.subTest(label=label, case=case):
                    before = len(self.calls())
                    overrides = {"FAKE_INDEX": case} if case in ("malformed", "zero", "multiple") else {}
                    if case == "wrong_leaf":
                        overrides["FAKE_LEAF"] = "sha256:" + "d" * 64
                    if case == "wrong_config":
                        overrides["FAKE_CONFIG"] = "sha256:" + "e" * 64
                    result = subprocess.run(
                        ["bash", "-eo", "pipefail", "-c", body], cwd=ROOT,
                        env={**self.env, **env, **overrides}, capture_output=True, text=True, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    calls = self.calls()[before:]
                    self.assertFalse(any(call[0][0] == "pull" for call in calls))
                    self.assertEqual(len(calls), 2 if case == "wrong_config" else 1)


if __name__ == "__main__":
    unittest.main()
