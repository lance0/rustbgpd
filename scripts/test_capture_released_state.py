#!/usr/bin/env python3
"""The release recapture comparison permits timestamps, not payload drift."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

CAPTURE = runpy.run_path(str(Path(__file__).with_name("capture-released-state.py")))
CHECK_HISTORY = CAPTURE["check_history"]
FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/state/v0.74.0/config-history"


class ReleasedStateCaptureTests(unittest.TestCase):
    def test_only_capture_timestamp_may_differ(self):
        rows = sorted(FIXTURE.glob("*.json"))
        self.assertEqual(len(rows), 2)
        for path in rows:
            expected = json.loads(path.read_bytes())
            changed = dict(expected, timestamp_unix_seconds=1)
            CHECK_HISTORY(changed, expected)
            for field in ("version", "sequence", "sha256", "source_sha256"):
                with self.subTest(format=expected["version"], field=field):
                    with self.assertRaisesRegex(ValueError, "differs from archive"):
                        CHECK_HISTORY(dict(changed, **{field: None}), expected)
            payload_field = "normalized_toml" if expected["version"] == 2 else "normalized_toml_bytes"
            with self.assertRaisesRegex(ValueError, "differs from archive"):
                CHECK_HISTORY(dict(changed, **{payload_field: None}), expected)
            del changed["timestamp_unix_seconds"]
            with self.assertRaises(KeyError):
                CHECK_HISTORY(changed, expected)

    def test_optimized_python_still_rejects_payload_drift(self):
        result = subprocess.run([
            sys.executable, "-O", "-c",
            "import runpy, sys; "
            "check = runpy.run_path(sys.argv[1])['check_history']; "
            "check({'timestamp_unix_seconds': 1, 'normalized_toml': 'changed'}, "
            "{'timestamp_unix_seconds': 2, 'normalized_toml': 'released'})",
            str(Path(__file__).with_name("capture-released-state.py")),
        ], capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ValueError: released history content differs from archive", result.stderr)

    def test_recovery_requires_all_ownership_fields_and_ignores_absence(self):
        container = {"Name": "/capture", "Image": "image", "Id": "a" * 64,
                     "Config": {"Labels": {"org.rustbgpd.capture-owner": "nonce"}}}
        result = subprocess.CompletedProcess([], 0, json.dumps([container]), "")
        with mock.patch.object(subprocess, "run", return_value=result):
            for identity in (("other", "nonce", "image"), ("capture", "other", "image"),
                             ("capture", "nonce", "other")):
                with self.subTest(identity=identity), self.assertRaisesRegex(ValueError, "ownership"):
                    CAPTURE["recover_container"](*identity)
        for message in ("Error response from daemon: No such container: capture",
                        "Error: No such container: capture", "error: no such container: capture"):
            absent = subprocess.CompletedProcess([], 1, "", message)
            with self.subTest(message=message), \
                 mock.patch.object(subprocess, "run", return_value=absent) as inspect:
                self.assertIsNone(CAPTURE["recover_container"]("capture", "nonce", "image"))
                self.assertEqual(inspect.call_args.args[0],
                                 ["docker", "inspect", "--type", "container", "capture"])
        for message in ("Error: No such image: capture", "permission denied",
                        "error: no such container: other"):
            failed = subprocess.CompletedProcess([], 1, "", message)
            with self.subTest(message=message), \
                 mock.patch.object(subprocess, "run", return_value=failed), \
                 self.assertRaisesRegex(RuntimeError, "cannot inspect"):
                CAPTURE["recover_container"]("capture", "nonce", "image")

    def test_create_timeout_recovers_owned_container_and_preserves_failure(self):
        for cleanup_failure in (None, "logs", "remove"):
            with self.subTest(cleanup_failure=cleanup_failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                archive_path = root / "release.tar.gz"
                binary = b"test binary; never executed"
                with tarfile.open(archive_path, "w:gz") as archive:
                    member = tarfile.TarInfo("rustbgpd")
                    member.size = len(binary)
                    archive.addfile(member, io.BytesIO(binary))
                created = {}
                removed = []
                timeout = subprocess.TimeoutExpired("docker create", 60)

                def fake_run(*args, created=created, removed=removed, timeout=timeout, cleanup_failure=cleanup_failure):
                    if args[1:3] == ("image", "inspect"):
                        return "sha256:expected"
                    if args[1] == "create":
                        name = args[args.index("--name") + 1]
                        nonce = args[args.index("--label") + 1].split("=", 1)[1]
                        created.update(Name=f"/{name}", Image="sha256:expected", Id="a" * 64,
                                       Config={"Labels": {"org.rustbgpd.capture-owner": nonce}})
                        raise timeout  # Docker created it before its CLI timed out.
                    self.assertEqual(args[:3], ("docker", "rm", "--force"))
                    removed.append(args[3])
                    if cleanup_failure == "remove":
                        raise RuntimeError("injected removal failure")
                    return ""

                def fake_process(args, created=created, cleanup_failure=cleanup_failure, **_kwargs):
                    if args[1] == "inspect":
                        self.assertEqual(args[2:], ["--type", "container", created["Name"][1:]])
                        return subprocess.CompletedProcess(args, 0, json.dumps([created]), "")
                    self.assertEqual(args, ["docker", "logs", created["Id"]])
                    code = int(cleanup_failure == "logs")
                    return subprocess.CompletedProcess(args, code, b"retained stdout", b"retained stderr")

                overrides = {
                    "ARCHIVE_SHA256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    "DAEMON_SHA256": hashlib.sha256(binary).hexdigest(), "run": fake_run,
                }
                stderr = io.StringIO()
                with mock.patch.dict(CAPTURE["main"].__globals__, overrides), \
                     mock.patch.object(sys, "argv", ["capture", str(archive_path), str(root / "output")]), \
                     mock.patch.object(subprocess, "run", side_effect=fake_process), \
                     contextlib.redirect_stderr(stderr):
                    with self.assertRaises(subprocess.TimeoutExpired) as failure:
                        CAPTURE["main"]()
                self.assertIs(failure.exception, timeout)
                self.assertEqual(removed, ["a" * 64])
                self.assertEqual((root / "output/daemon.log").read_bytes(), b"retained stdoutretained stderr\n")
                if cleanup_failure:
                    self.assertIn("capture cleanup failed:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
