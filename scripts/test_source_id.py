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


class FailClosed(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
