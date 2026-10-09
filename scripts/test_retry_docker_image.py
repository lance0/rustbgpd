#!/usr/bin/env python3
"""Offline checks for the Docker Hub retry boundary in the lab workflows."""

import copy
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
        # registry inspect in the interop workflow and the local actions
        # targets Docker Hub.
        texts = [INTEROP, *(p.read_text() for p in ACTIONS.glob("*/action.yml"))]
        sites = [line for text in texts for line in text.splitlines()
                 if re.search(r"docker (pull|buildx imagetools inspect)\b", line)
                 and not re.search(r"\b(ghcr|quay)\.io/", line)]
        self.assertGreaterEqual(len(sites), 11)
        for line in sites:
            with self.subTest(line=line.strip()):
                self.assertRegex(line, r"\.github/scripts/retry-docker-image\.sh (timeout \d+ )?docker ")

    def test_retry_delay_scales_backoff(self):
        result = self.run_helper(FAIL_INDEX="2", RETRY_DELAY_SECONDS="10")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.sleeps(), ["10", "20"])

    def test_buildkit_pre_pull_retries_and_never_fails_the_step(self):
        for action in ("build-rustbgpd-dev", "prime-rustbgpd-dev-cache"):
            body = action_step(action, "Pre-pull BuildKit image")["run"]
            for fail, pulls in (("2", 3), ("3", 3)):
                with self.subTest(action=action, fail=fail):
                    (self.path / "pull").unlink(missing_ok=True)
                    (self.path / "calls").unlink(missing_ok=True)
                    (self.path / "sleeps").unlink(missing_ok=True)
                    result = subprocess.run(
                        ["bash", "-eo", "pipefail", "-c", body], cwd=ROOT,
                        env={**self.env, "FAIL_PULL": fail}, capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.sleeps(), ["10", "20"])
                    self.assertEqual([c[0] for c in self.calls()],
                                     [["pull", "moby/buildkit:buildx-stable-1"]] * pulls)
                    self.assertEqual("::warning::" in result.stdout, fail == "3")

    def test_lab_deploy_pre_pulls_missing_topology_images(self):
        body = action_step("run-interop-test", "Run interop test with retry")["run"]
        for tool in ("sudo", "containerlab"):
            fake = self.path / "bin" / tool
            fake.write_text('#!/bin/sh\n[ "$(basename "$0")" = sudo ] && exec "$@"\nexit 0\n')
            fake.chmod(0o755)
        topology = self.path / "lab.clab.yml"
        topology.write_text(
            "topology:\n  nodes:\n"
            "    a:\n      image: quay.io/frrouting/frr:10.7.1\n"
            "    b:\n      image: \"quay.io/frrouting/frr:10.7.1\"\n"
            "    c:\n      image: rustbgpd:dev\n"
        )
        script = self.path / "test.sh"
        script.write_text("exit 0\n")
        env = {**self.env, "INTEROP_TOPOLOGY": str(topology), "INTEROP_SCRIPT": str(script),
               "INTEROP_MAX_ATTEMPTS": "1", "INTEROP_LABEL": "MX", "GITHUB_STEP_SUMMARY": ""}
        for present, fail, pulls in (("0", "2", []), ("99", "2", ["frr", "rustbgpd"]), ("99", "3", ["frr", "rustbgpd"])):
            with self.subTest(present=present == "0", fail=fail):
                for name in ("pull", "leaf", "calls", "sleeps"):
                    (self.path / name).unlink(missing_ok=True)
                # FAIL_LEAF makes `docker image inspect` report the image as absent.
                result = subprocess.run(
                    ["bash", "-c", body], cwd=ROOT,
                    env={**env, "FAIL_LEAF": present, "FAIL_PULL": fail},
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                pulled = [c[0][1] for c in self.calls() if c[0][0] == "pull"]
                expected = {"frr": "quay.io/frrouting/frr:10.7.1", "rustbgpd": "rustbgpd:dev"}
                # The first image uses all three attempts (two or three failures);
                # the duplicate is pulled once and the next image pulls at once.
                self.assertEqual(pulled, [expected[pulls[0]]] * 3 + [expected[p] for p in pulls[1:]]
                                 if pulls else [])
                self.assertEqual("pre-pull of quay.io" in result.stdout, fail == "3")

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


ACTIONS = ROOT / ".github/actions"


def action_steps(action):
    """The steps of a local composite action as flat dicts; `with` stays raw text."""
    text = (ACTIONS / action / "action.yml").read_text().split("\n  steps:\n", 1)[1]
    steps = []
    for chunk in re.split(r"(?m)^    - ", text)[1:]:
        step = dict(re.findall(r"(?m)^(?:      )?(name|uses|id|if|continue-on-error): (.+)$", chunk))
        run = re.search(r"(?ms)^      run: \|\n(.*?)(?=^\S|^    \S|\Z)", chunk)
        if run:
            step["run"] = textwrap.dedent(run.group(1))
        inputs = re.search(r"(?ms)^      with:\n(.*?)(?=^      \S|^    \S|\Z)", chunk)
        if inputs:
            step["with"] = inputs.group(1).strip()
        steps.append(step)
    return steps


def action_step(action, name):
    return next(step for step in action_steps(action) if step.get("name") == name)


def build_retry_errors(steps):
    """Every Buildx bootstrap is pre-pulled and every build-push has a guarded retry."""
    errors = []
    for index, step in enumerate(steps):
        uses = step.get("uses", "")
        if uses.startswith("docker/setup-buildx-action@"):
            if not any("retry-docker-image.sh" in s.get("run", "") and "moby/buildkit" in s.get("run", "")
                       for s in steps[:index]):
                errors.append(f"{step.get('name')}: BuildKit image not pre-pulled first")
        if uses.startswith("docker/build-push-action@") and "if" not in step:
            retry = f"steps.{step.get('id')}.outcome == 'failure'"
            if not step.get("continue-on-error") or not any(
                s.get("if") == retry and s.get("uses") == uses and s.get("with") == step.get("with")
                for s in steps[index + 1:]
            ):
                errors.append(f"{step.get('name')}: build has no identical guarded retry")
    return errors


class BuildRetryShapeTests(unittest.TestCase):
    def test_lab_builds_go_through_the_retried_composites(self):
        for workflow in ("interop.yml", "kernel-dataplane.yml"):
            with self.subTest(workflow=workflow):
                text = (ROOT / ".github/workflows" / workflow).read_text()
                self.assertNotIn("docker/setup-buildx-action@", text)
        for action in ("build-rustbgpd-dev", "prime-rustbgpd-dev-cache"):
            with self.subTest(action=action):
                steps = action_steps(action)
                self.assertEqual(build_retry_errors(steps), [])

    def test_broken_retry_shapes_fail(self):
        steps = action_steps("build-rustbgpd-dev")
        cases = {
            "no pre-pull": lambda s: s.pop(0),
            "no continue-on-error": lambda s: s[2].pop("continue-on-error"),
            "no retry": lambda s: s.pop(),
            "retry inputs drift": lambda s: s[-1].update({"with": s[-1]["with"] + "\ncache-to: type=gha"}),
            "retry unguarded": lambda s: s[-1].update({"if": "always()"}),
        }
        for case, mutate in cases.items():
            with self.subTest(case=case):
                broken = copy.deepcopy(steps)
                mutate(broken)
                self.assertNotEqual(build_retry_errors(broken), [])


if __name__ == "__main__":
    unittest.main()
