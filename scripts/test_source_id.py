#!/usr/bin/env python3
"""Contract tests for scripts/source-id.sh.

The script's digest must match the one computed inside the image, so it has
to prune every .dockerignore rule that reaches into the hashed directories,
and it must never print a digest of an incomplete input set.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "source-id.sh"


def hashed_roots(script: str) -> list[str]:
    match = re.search(r"\bfind ((?:[\w.-]+ )+)\\", script)
    if not match:
        raise ValueError("source-id.sh: no find root list")
    return match.group(1).split()


def unmirrored(dockerignore: str, script: str) -> list[str]:
    """.dockerignore rules inside the hashed roots that the script does not prune.

    Docker anchors every pattern at the context root, so `*.log` only matches
    root-level files; `**/` matches at any depth.
    """
    roots = hashed_roots(script)
    missing = []
    for line in dockerignore.splitlines():
        rule = line.strip()
        if not rule or rule.startswith("#"):
            continue
        pattern = rule.lstrip("!").lstrip("/").rstrip("/")
        segments = pattern.split("/")
        if segments[0] != "**" and not any(
            fnmatch.fnmatchcase(root, segments[0]) for root in roots
        ):
            continue
        if rule.startswith("!"):
            missing.append(f"{rule} (negation is not supported)")
        elif segments[0] == "**":
            if len(segments) != 2 or f"-name {segments[1]}" not in script:
                missing.append(rule)
        elif len(segments) == 1 or f"-path '{pattern}'" not in script:
            missing.append(rule)
    return missing


class DockerignoreMirror(unittest.TestCase):
    def test_current_rules_are_mirrored(self) -> None:
        self.assertEqual(unmirrored((ROOT / ".dockerignore").read_text(), SCRIPT.read_text()), [])

    def test_unmirrored_rules_are_reported(self) -> None:
        script = SCRIPT.read_text()
        for rule in ("crates/wire/fuzz/corpus/", "**/node_modules/", "src/*.tmp", "!crates/x"):
            with self.subTest(rule=rule):
                self.assertEqual(len(unmirrored(f"{rule}\n", script)), 1)
        for prune in ("-name target", "-path 'bench/scale/matrix/artifacts-*'"):
            with self.subTest(dropped=prune):
                mutated = script.replace(prune, "-name never-matches")
                self.assertNotEqual(unmirrored((ROOT / ".dockerignore").read_text(), mutated), [])

    def test_root_level_rules_do_not_reach_hashed_roots(self) -> None:
        script = SCRIPT.read_text()
        self.assertEqual(unmirrored("*.log\ntarget/\nclab-*/\ndocs/artifacts/\n", script), [])


class TempTree(unittest.TestCase):
    """A minimal tree holding the script and one file per hashed root."""

    def setUp(self) -> None:
        self.tree = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tree, ignore_errors=True)
        (self.tree / "scripts").mkdir()
        shutil.copy2(SCRIPT, self.tree / "scripts" / SCRIPT.name)
        for root in hashed_roots(SCRIPT.read_text()):
            if "." in root.lstrip("."):
                (self.tree / root).write_text(root)
            else:
                (self.tree / root).mkdir()
                (self.tree / root / "lib.rs").write_text(root)

    def run_script(self, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.tree / "scripts" / SCRIPT.name)],
            capture_output=True,
            text=True,
            env=env,
        )


class FailClosed(TempTree):
    def test_complete_tree_prints_one_digest(self) -> None:
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"\A[0-9a-f]{64}\n\Z")

    @unittest.skipIf(os.geteuid() == 0, "root reads mode-000 files")
    def test_unreadable_file_prints_no_digest(self) -> None:
        unreadable = self.tree / "crates" / "secret.rs"
        unreadable.write_text("x")
        unreadable.chmod(0)
        self.addCleanup(unreadable.chmod, 0o644)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_failing_step_prints_no_digest(self) -> None:
        stubs = self.tree / "stubs"
        stubs.mkdir()
        stub = stubs / "sort"
        stub.write_text("#!/bin/sh\nexit 1\n")
        stub.chmod(0o755)
        env = dict(os.environ, PATH=f"{stubs}{os.pathsep}{os.environ['PATH']}")
        result = self.run_script(env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


class CheckImage(TempTree):
    """`--check IMAGE` against a stubbed docker that reports a fixed image id."""

    def check(self, image_id: str, **extra: str) -> subprocess.CompletedProcess:
        stubs = self.tree / "stubs"
        stubs.mkdir(exist_ok=True)
        stub = stubs / "docker"
        stub.write_text('#!/bin/sh\n[ -n "$FAKE_SOURCE_ID" ] || exit 1\necho "$FAKE_SOURCE_ID"\n')
        stub.chmod(0o755)
        env = {k: v for k, v in os.environ.items() if k not in ("CI", "GITHUB_ACTIONS")}
        env.update(
            PATH=f"{stubs}{os.pathsep}{os.environ['PATH']}", FAKE_SOURCE_ID=image_id, **extra
        )
        return subprocess.run(
            [str(self.tree / "scripts" / SCRIPT.name), "--check", "rustbgpd:test"],
            capture_output=True,
            text=True,
            env=env,
        )

    def tree_id(self) -> str:
        return self.run_script().stdout.strip()

    def test_image_from_this_tree_passes(self) -> None:
        result = self.check(self.tree_id())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_image_from_another_tree_fails_naming_both_ids(self) -> None:
        tree_a = self.tree_id()
        (self.tree / "crates" / "lib.rs").write_text("crateS")
        tree_b = self.tree_id()
        self.assertNotEqual(tree_a, tree_b)
        result = self.check(tree_a)
        self.assertEqual(result.returncode, 1)
        for needle in (tree_a, tree_b, "rustbgpd:test"):
            self.assertIn(needle, result.stderr)

    def test_unreadable_image_id_fails(self) -> None:
        result = self.check("")
        self.assertEqual(result.returncode, 1)
        self.assertIn("rustbgpd:test", result.stderr)

    def test_ci_skips_without_running_docker(self) -> None:
        for var in ("CI", "GITHUB_ACTIONS"):
            with self.subTest(var=var):
                result = self.check("", **{var: "true"})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("skipping", result.stderr)

    def test_bad_usage_is_rejected(self) -> None:
        for args in (["--check"], ["--check", ""], ["--chek", "x"], ["x"]):
            with self.subTest(args=args):
                result = subprocess.run(
                    [str(self.tree / "scripts" / SCRIPT.name), *args],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
