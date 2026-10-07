#!/usr/bin/env python3
"""The release recapture comparison permits timestamps, not payload drift."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import runpy
import shutil
import sqlite3
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


V075 = runpy.run_path(str(Path(__file__).with_name("capture-released-state-v075.py")))
V075_FIXTURE = V075["FIXTURE"]


def execute(path, statement):
    """Commit and close, so the change is checkpointed out of the WAL."""
    db = sqlite3.connect(path)
    db.execute(statement)
    db.commit()
    db.close()
    assert not path.with_name(path.name + "-wal").exists()


class ReleasedV075CaptureTests(unittest.TestCase):
    """The v0.75.0 recapture comparison permits only capture-specific values."""

    def compare(self, mutate, archive_side=False):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "copy"
            shutil.copytree(V075_FIXTURE, copy)
            mutate(copy)
            if archive_side:
                V075["check_artifacts"](V075_FIXTURE, copy)
            else:
                V075["check_artifacts"](copy, V075_FIXTURE)

    def snapshot(self, root):
        manifest = root / "warm-bundle-v1/manifest.json"
        return manifest, manifest.parent / json.loads(manifest.read_bytes())["snapshot"]["path"]

    def rewrite_snapshot(self, root, transform):
        """Replace the snapshot with a consistently named and hashed new payload."""
        manifest, snapshot = self.snapshot(root)
        data = transform(snapshot.read_bytes())
        snapshot.unlink()
        digest = hashlib.sha256(data).hexdigest()
        (manifest.parent / f"snapshot-{digest}.mrt").write_bytes(data)
        self.rewrite_json(manifest, "snapshot", "path", value=f"snapshot-{digest}.mrt")
        self.rewrite_json(manifest, "snapshot", "sha256", value=digest)
        self.rewrite_json(manifest, "snapshot", "size_bytes", value=len(data))

    def rewrite_toml(self, path, key, value):
        text = path.read_text()
        lines = [f"{key} = {json.dumps(value)}" if line.startswith(f"{key} = ") else line
                 for line in text.splitlines()]
        self.assertNotEqual(lines, text.splitlines())
        path.write_text("\n".join(lines) + "\n")

    def rewrite_json(self, path, *keys, value):
        document = json.loads(path.read_bytes())
        parent = document
        for key in keys[:-1]:
            parent = parent[key]
        parent[keys[-1]] = value
        path.write_text(json.dumps(document))

    def test_capture_specific_values_may_differ(self):
        def mutate(captured):
            for name, varying in V075["VARYING"].items():
                for keys in varying:
                    if name.endswith(".toml"):
                        self.rewrite_toml(captured / name, *keys, value=1)
                    elif keys[0] != "snapshot":
                        self.rewrite_json(captured / name, *keys, value=1)
            # A new generation renames the view, so the snapshot is renamed and
            # rehashed; its record timestamp is also capture-specific.
            manifest = self.snapshot(captured)[0]
            view = json.loads(V075_FIXTURE.joinpath("warm-bundle-v1/manifest.json").read_bytes())[
                "identity"]["peer_index_table_view"]
            self.rewrite_json(manifest, "identity", "peer_index_table_view", value="f" * 32)
            self.rewrite_snapshot(captured, lambda data: b"\x01\x02\x03\x04"
                                  + data[4:].replace(view.encode(), b"f" * 32))
            execute(captured / "events.db", "DELETE FROM events")
        self.compare(mutate)

    def test_payload_drift_is_rejected(self):
        drifts = [lambda c, name=name: (c / name).write_bytes((c / name).read_bytes() + b" ")
                  for name in V075["EXACT"]]
        drifts += [
            lambda c: self.rewrite_json(c / "commit-confirm/commit-confirm-v3-metadata.json", "confirm_id", value="x"),
            lambda c: self.rewrite_json(c / "warm-bundle-v1/manifest.json", "format_version", value=3),
            lambda c: self.rewrite_json(c / "warm-bundle-v1/manifest.json", "identity", "views", value=[]),
            lambda c: self.rewrite_toml(c / "gr-restart.toml", "version", value=4),
            lambda c: self.rewrite_toml(c / "gr-restart.toml", "boottime_offset_secs", value=7),
            # Same-size MRT payload drift (peer AS) with a consistent manifest.
            lambda c: self.rewrite_snapshot(c, lambda data: data[:-1] + bytes([data[-1] ^ 0x01])),
            lambda c: self.rewrite_snapshot(c, lambda data: data + data),  # an extra record
        ]
        for index, drift in enumerate(drifts):
            with self.subTest(drift=index), self.assertRaisesRegex(ValueError, "differs from archive"):
                self.compare(drift)
        with self.assertRaisesRegex(ValueError, "view name differs from the manifest"):
            self.compare(lambda c: self.rewrite_json(
                c / "warm-bundle-v1/manifest.json", "identity", "peer_index_table_view", value="f" * 32))

    def test_snapshot_must_match_its_manifest(self):
        def flip(root):
            snapshot = self.snapshot(root)[1]
            data = bytearray(snapshot.read_bytes())
            data[len(data) // 2] ^= 0x01
            snapshot.write_bytes(data)

        def truncate(root):
            manifest, snapshot = self.snapshot(root)
            snapshot.write_bytes(snapshot.read_bytes()[:-1])
            self.rewrite_json(manifest, "snapshot", "sha256", value=hashlib.sha256(snapshot.read_bytes()).hexdigest())

        def escape(root):
            manifest, snapshot = self.snapshot(root)
            shutil.copy(snapshot, root / snapshot.name)
            self.rewrite_json(manifest, "snapshot", "path", value=f"../{snapshot.name}")

        def remove(root):
            self.snapshot(root)[1].unlink()

        for mutate in (flip, truncate, escape, remove):
            for archive_side in (False, True):
                with self.subTest(mutate=mutate.__name__, archive_side=archive_side), \
                     self.assertRaisesRegex(ValueError, "snapshot file|does not match its manifest"):
                    self.compare(mutate, archive_side)

    def test_failed_log_retrieval_does_not_skip_remaining_cleanup(self):
        timeout = subprocess.TimeoutExpired("docker logs", 10)
        for kind, reported in (("exit", "docker logs failed; see retained daemon.log"),
                               ("raise", "TimeoutExpired")):
            with self.subTest(kind=kind):
                removed, stderr = self.cleanup_after_failure(kind, timeout)
                self.assertEqual(removed[:2], ["subject", "peer"])
                self.assertEqual(removed[2][:2], ("network", "rm"))
                self.assertIn(reported, stderr)

    def cleanup_after_failure(self, kind, timeout):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "release.tar.gz"
            binary = b"test binary; never executed"
            with tarfile.open(archive_path, "w:gz") as archive:
                for name in ("rustbgpd", "rbgp"):
                    member = tarfile.TarInfo(name)
                    member.size = len(binary)
                    archive.addfile(member, io.BytesIO(binary))
            removed = []
            containers = {}
            failure = RuntimeError("injected network failure")

            def fake_run(*args):
                if args[1:3] == ("image", "inspect"):
                    return "sha256:expected"
                if args[1:3] == ("network", "create"):
                    nonce = args[args.index("--label") + 1].split("=", 1)[1]
                    for role in ("subject", "peer"):
                        containers[f"released-state-{role}-{nonce}"] = role
                    raise failure
                if args[1:3] == ("network", "rm"):
                    removed.append(args[1:])
                    return ""
                self.assertEqual(args[:3], ("docker", "rm", "--force"))
                removed.append(args[3])
                return ""

            def fake_process(args, **_kwargs):
                if args[1] == "inspect":
                    nonce = args[-1].rsplit("-", 1)[1]
                    return subprocess.CompletedProcess(args, 0, json.dumps([{
                        "Name": f"/{args[-1]}", "Image": "sha256:expected", "Id": containers[args[-1]],
                        "Config": {"Labels": {"org.rustbgpd.capture-owner": nonce}}}]), "")
                if args[1] == "logs":
                    if args[2] == "subject" and kind == "raise":
                        raise timeout
                    return subprocess.CompletedProcess(args, int(args[2] == "subject"), b"out", b"err")
                self.assertEqual(args[1:3], ["network", "inspect"])
                return subprocess.CompletedProcess(args, 0, args[-1].rsplit("-", 1)[1] + "\n", "")

            digest = hashlib.sha256(binary).hexdigest()
            overrides = {"ARCHIVE_SHA256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                         "DAEMON_SHA256": digest, "CLI_SHA256": digest, "run": fake_run}
            stderr = io.StringIO()
            with mock.patch.dict(V075["main"].__globals__, overrides), \
                 mock.patch.object(sys, "argv", ["capture", str(archive_path), str(root / "output")]), \
                 mock.patch.object(subprocess, "run", side_effect=fake_process), \
                 contextlib.redirect_stderr(stderr), \
                 self.assertRaises(RuntimeError) as raised:
                V075["main"]()
            self.assertIs(raised.exception, failure)
            self.assertEqual((root / "output/peer.log").read_bytes(), b"outerr\n")
            if kind == "exit":
                self.assertEqual((root / "output/daemon.log").read_bytes(), b"outerr\n")
            return removed, stderr.getvalue()

    def test_event_schema_drift_is_rejected(self):
        for statement in ("UPDATE metadata SET value = '2' WHERE key = 'schema_version'",
                          "CREATE TABLE extra (id INTEGER)"):
            def mutate(captured, statement=statement):
                execute(captured / "events.db", statement)
            with self.subTest(statement=statement), self.assertRaisesRegex(ValueError, "schema differs"):
                self.compare(mutate)

    def test_archived_events_are_read_without_side_files(self):
        V075["events_schema"](V075_FIXTURE / "events.db")
        self.assertEqual(sorted(p.name for p in V075_FIXTURE.glob("events.db*")), ["events.db"])


if __name__ == "__main__":
    unittest.main()
