#!/usr/bin/env python3
"""Reproduce the v0.75.0 runtime-state fixture slice using its official Linux archive.

Requires Docker; creates one internal network and two containers: the subject
daemon (FIB, BLACKHOLE, event history and warm checkpoint enabled) and a peer
running the same release binary. Output must not exist. Capture-specific values
(timestamps, generations, inode identity, event rows) are excluded from the
comparison against the archived samples; everything else must match.
"""

import argparse
import hashlib
import io
import json
from pathlib import Path
import runpy
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import uuid

SHARED = runpy.run_path(str(Path(__file__).with_name("capture-released-state.py")))
require, run, wait_for, recover_container = (
    SHARED["require"], SHARED["run"], SHARED["wait_for"], SHARED["recover_container"])

ARCHIVE_SHA256 = "9aa9fe9f84162085ee5eef13f5090981550f1f45a5f9c3b37347178cff990489"
DAEMON_SHA256 = "6141b78195ffa7a83336576cedc2d62e844c4b346865f95d9fa555185688a225"
CLI_SHA256 = "d3d1af6ca875f1e5629d0cee28ead780e5f4e1419c76e4f9c81d0fb3fabfaa5d"
FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/state/v0.75.0"
STATE = "/var/lib/rustbgpd"
LOCATOR = "/etc/rustbgpd/config.toml.commit-confirm-locator.json"
EXACT = ("fib-owned.json", "blackhole-owned.json", "commit-confirm/locator.json",
         "commit-confirm/commit-confirm-v3-prior.toml")
# Capture-specific values: wall clock, the pending file's inode identity, the
# boot and time-namespace identity, and the per-shutdown checkpoint generation
# (which also names the snapshot; its contents are compared by mrt_records).
VARYING = {
    "commit-confirm/commit-confirm-v3-metadata.json": (("deadline_unix_seconds",), ("raw_device",), ("raw_inode",)),
    "warm-bundle-v1/manifest.json": (
        ("identity", "checkpoint_generation"), ("identity", "created_at_utc_seconds"),
        ("identity", "peer_index_table_view"), ("snapshot", "path"), ("snapshot", "sha256")),
    "gr-restart.toml": (("expires_at_unix",), ("checkpoint_generation",), ("boot_id",),
                        ("time_namespace_dev",), ("time_namespace_ino",), ("expires_at_boottime_ms",)),
}


def stable(name, document, varying):
    document = (tomllib.loads if name.endswith(".toml") else json.loads)(document)
    for path in varying:
        parent = document
        for key in path[:-1]:
            parent = parent[key]
        parent.pop(path[-1])
    return document


def events_schema(path):
    with sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True) as db:
        return (db.execute("SELECT value FROM metadata WHERE key = 'schema_version'").fetchone(),
                db.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY name").fetchall())


def mrt_records(data, view):
    """Split MRT records, zeroing each header timestamp and the generation-named view."""
    records, offset = [], 0
    while offset < len(data):
        require(len(data) - offset >= 12, "truncated MRT record header")
        end = offset + 12 + int.from_bytes(data[offset + 8:offset + 12], "big")
        require(end <= len(data), "truncated MRT record")
        record = bytearray(data[offset:end])
        record[0:4] = bytes(4)
        if record[4:8] == b"\x00\x0d\x00\x01":  # TABLE_DUMP_V2 PEER_INDEX_TABLE
            name_end = 18 + int.from_bytes(record[16:18], "big")
            require(record[18:name_end] == view.encode(), "MRT view name differs from the manifest")
            record[18:name_end] = bytes(name_end - 18)
        # RIB entries' originated times are not zeroed: the capture withdraws every route first.
        records.append(bytes(record))
        offset = end
    return records


def check_snapshot(root):
    """Verify the file the manifest names and return its capture-independent records."""
    manifest = json.loads((root / "warm-bundle-v1/manifest.json").read_bytes())
    snapshot = manifest["snapshot"]
    path = root / "warm-bundle-v1" / snapshot["path"]
    require(Path(snapshot["path"]).name == snapshot["path"] and path.is_file(),
            f"{path} is not the manifest's snapshot file")
    data = path.read_bytes()
    require(len(data) == snapshot["size_bytes"] and hashlib.sha256(data).hexdigest() == snapshot["sha256"],
            f"{path} does not match its manifest size and SHA-256")
    return mrt_records(data, manifest["identity"]["peer_index_table_view"])


def check_artifacts(captured, archived):
    """Compare a recapture with the archive, excluding only capture-specific values."""
    require(check_snapshot(captured) == check_snapshot(archived),
            "released warm snapshot differs from archive")
    for name in EXACT:
        require((captured / name).read_bytes() == (archived / name).read_bytes(),
                f"released {name} differs from archive")
    for name, varying in VARYING.items():
        require(stable(name, (captured / name).read_text(), varying)
                == stable(name, (archived / name).read_text(), varying),
                f"released {name} differs from archive")
    require(events_schema(captured / "events.db") == events_schema(archived / "events.db"),
            "released events.db schema differs from archive")


def extract(archive, member):
    data = archive.extractfile(member)
    if data is None:
        raise ValueError(f"{member} is not a regular file")
    return data.read()


def read_file(container, path):
    """Copy one file out of a container without depending on its tools."""
    data = subprocess.run(["docker", "cp", f"{container}:{path}", "-"],
                          capture_output=True, check=True, timeout=60).stdout
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        members = archive.getmembers()
        require(len(members) == 1 and members[0].isfile(), f"{path} is not one regular file")
        return extract(archive, members[0])


def exists(container, path):
    return subprocess.run(["docker", "exec", container, "test", "-e", path], timeout=10).returncode == 0


def owned_routes(container):
    if not exists(container, f"{STATE}/fib-owned.json"):
        return None
    state = json.loads(read_file(container, f"{STATE}/fib-owned.json"))
    return None if state.get("in_flight") else len(state["routes"])


def established(container):
    neighbors = json.loads(run("docker", "exec", container, "rbgp", "-j", "neighbor"))
    return [neighbor["state"] for neighbor in neighbors] == ["Established"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--image", default="debian:trixie-slim")
    args = parser.parse_args()
    require(hashlib.sha256(args.archive.read_bytes()).hexdigest() == ARCHIVE_SHA256, "unexpected release archive SHA-256")
    args.output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="released-state-") as temporary:
        root = Path(temporary)
        with tarfile.open(args.archive) as archive:
            for name, digest in (("rustbgpd", DAEMON_SHA256), ("rbgp", CLI_SHA256)):
                data = extract(archive, name)
                require(hashlib.sha256(data).hexdigest() == digest, f"unexpected release {name} SHA-256")
                (root / name).write_bytes(data)
                (root / name).chmod(0o755)
        image = run("docker", "image", "inspect", "--format", "{{.Id}}", args.image)
        nonce = uuid.uuid4().hex
        network = f"released-state-{nonce}"
        names = {"subject": f"released-state-subject-{nonce}", "peer": f"released-state-peer-{nonce}"}
        containers = {}
        try:
            run("docker", "network", "create", "--internal", "--subnet", "192.0.2.0/29",
                "--label", f"org.rustbgpd.capture-owner={nonce}", network)
            # Root inside an unpublished network: kernel route installs need
            # CAP_NET_ADMIN and BGP needs port 179. No other capability is kept.
            for role, address, config, caps in (
                ("subject", "192.0.2.2", "config.toml", ["NET_ADMIN", "NET_BIND_SERVICE"]),
                ("peer", "192.0.2.3", "peer.toml", ["NET_BIND_SERVICE"]),
            ):
                containers[role] = run(
                    "docker", "create", "--name", names[role],
                    "--label", f"org.rustbgpd.capture-owner={nonce}",
                    "--network", network, "--ip", address, "--cap-drop", "ALL",
                    *[flag for cap in caps for flag in ("--cap-add", cap)],
                    "-v", f"{root / 'rustbgpd'}:/usr/local/bin/rustbgpd:ro",
                    "-v", f"{root / 'rbgp'}:/usr/local/bin/rbgp:ro",
                    "--entrypoint", "/usr/local/bin/rustbgpd", image, "/etc/rustbgpd/config.toml",
                )
                # Commit-confirm requires an owner-private config directory.
                bundle = io.BytesIO()
                with tarfile.open(fileobj=bundle, mode="w") as tar:
                    directory = tarfile.TarInfo("rustbgpd")
                    directory.type, directory.mode = tarfile.DIRTYPE, 0o700
                    tar.addfile(directory)
                    source = (FIXTURE / config).read_bytes()
                    member = tarfile.TarInfo("rustbgpd/config.toml")
                    member.size, member.mode = len(source), 0o600
                    tar.addfile(member, io.BytesIO(source))
                subprocess.run(["docker", "cp", "-", f"{containers[role]}:/etc/"],
                               input=bundle.getvalue(), check=True, timeout=60)
            subject, peer = containers["subject"], containers["peer"]
            run("docker", "start", subject, peer)
            wait_for(lambda: exists(subject, f"{STATE}/grpc.sock") and exists(peer, f"{STATE}/grpc.sock"))
            wait_for(lambda: established(subject))
            version = run("docker", "exec", subject, "rustbgpd", "--version")
            require(version == "rustbgpd 0.75.0", version)

            run("docker", "exec", peer, "rbgp", "rib", "add", "198.51.100.0/24", "--next-hop", "192.0.2.3")
            run("docker", "exec", peer, "rbgp", "rib", "add", "203.0.113.1/32", "--next-hop", "192.0.2.3",
                "--communities", "BLACKHOLE")
            wait_for(lambda: owned_routes(subject) == 2 and exists(subject, f"{STATE}/blackhole-owned.json"))
            for name in ("fib-owned.json", "blackhole-owned.json"):
                (args.output / name).write_bytes(read_file(subject, f"{STATE}/{name}"))

            candidate = (FIXTURE / "config.toml").read_text().replace(
                'description = "released-state-fixture"', 'description = "released-state-confirm"')
            subprocess.run(["docker", "exec", "-i", subject, "sh", "-c", "cat > /tmp/candidate.toml"],
                           input=candidate.encode(), check=True, timeout=60)
            plan = subprocess.run(["docker", "exec", subject, "rbgp", "-j", "config", "plan", "/tmp/candidate.toml"],
                                  capture_output=True, text=True, timeout=60)
            require(plan.returncode == 2, f"plan is not committable: {plan.stderr}")  # 2 = committable
            plan = json.loads(plan.stdout)
            run("docker", "exec", subject, "rbgp", "config", "apply",
                "--expected-runtime-snapshot-token", plan["runtime_snapshot_token"],
                "--confirm-id", "released-state-fixture", "--confirm-timeout", "3600", "/tmp/candidate.toml")
            confirm = args.output / "commit-confirm"
            confirm.mkdir()
            (confirm / "locator.json").write_bytes(read_file(subject, LOCATOR))
            for name in ("commit-confirm-v3-metadata.json", "commit-confirm-v3-prior.toml"):
                (confirm / name).write_bytes(read_file(subject, f"{STATE}/{name}"))
            run("docker", "exec", subject, "rbgp", "config", "confirm", "released-state-fixture")

            # v0.75.0 cannot publish a warm checkpoint holding an IPv4 route
            # learned over BGP (its MRT recovery check rejects a duplicated
            # NEXT_HOP), so withdraw before the coordinated shutdown.
            for prefix in ("198.51.100.0/24", "203.0.113.1/32"):
                run("docker", "exec", peer, "rbgp", "rib", "delete", prefix)
            wait_for(lambda: owned_routes(subject) == 0 and not exists(subject, f"{STATE}/blackhole-owned.json"))
            run("docker", "kill", "--signal", "TERM", subject)
            exit_code = run("docker", "wait", subject)
            require(exit_code == "0", exit_code)
            for name in ("gr-restart.toml", "events.db", "warm-bundle-v1/manifest.json"):
                (args.output / name).parent.mkdir(exist_ok=True)
                (args.output / name).write_bytes(read_file(subject, f"{STATE}/{name}"))
            manifest = json.loads((args.output / "warm-bundle-v1/manifest.json").read_bytes())
            snapshot = f"warm-bundle-v1/{manifest['snapshot']['path']}"
            (args.output / snapshot).write_bytes(read_file(subject, f"{STATE}/{snapshot}"))
            marker = tomllib.loads((args.output / "gr-restart.toml").read_text())
            require(manifest["format_version"] == 2 and marker["version"] == 3
                    and marker["checkpoint_generation"] == manifest["identity"]["checkpoint_generation"],
                    "release capture validation failed")
            run("docker", "kill", "--signal", "TERM", peer)
            peer_exit = run("docker", "wait", peer)
            require(peer_exit == "0", peer_exit)
            (args.output / "capture.json").write_text(json.dumps({
                "release": "v0.75.0",
                "tag_commit": "54ed19b5af927f1c8e5064ecb1a497885c15d068",
                "archive_sha256": ARCHIVE_SHA256,
                "daemon_sha256": DAEMON_SHA256,
                "cli_sha256": CLI_SHA256,
                "version_stdout": version,
                "container_image": run("docker", "inspect", "--format", "{{.Image}}", subject),
                "network": "internal 192.0.2.0/29; subject 192.0.2.2, peer 192.0.2.3",
                "daemon_argv": ["/usr/local/bin/rustbgpd", "/etc/rustbgpd/config.toml"],
                "steps": [
                    "peer injects 198.51.100.0/24 and BLACKHOLE 203.0.113.1/32; copy FIB and BLACKHOLE receipts",
                    "confirmed apply changing the neighbor description; copy pending authority; confirm",
                    "peer withdraws both routes; subject receipts empty",
                    "TERM subject; copy GR marker, events.db and warm bundle",
                ],
                "exit_code": int(exit_code),
            }, indent=2) + "\n")
            check_artifacts(args.output, FIXTURE)
        finally:
            original_failure = sys.exception()
            failures = []

            def attempt(step):
                """Run one cleanup step; a failure must not skip the remaining steps."""
                try:
                    return step()
                except Exception as error:
                    failures.append(error)
                    return None

            def retain_log(container, log):
                logs = subprocess.run(["docker", "logs", container], capture_output=True, timeout=10)
                (args.output / log).write_bytes((logs.stdout + logs.stderr).rstrip() + b"\n")
                require(logs.returncode == 0, f"docker logs failed; see retained {log}")

            def remove_network():
                label = subprocess.run(["docker", "network", "inspect", "--format",
                                        '{{index .Labels "org.rustbgpd.capture-owner"}}', network],
                                       capture_output=True, text=True, timeout=10)
                if label.returncode == 0 and label.stdout.strip() == nonce:
                    run("docker", "network", "rm", network)

            for role, name in names.items():
                container = containers.get(role) or attempt(
                    lambda name=name: recover_container(name, nonce, image))
                if container:
                    log = "daemon.log" if role == "subject" else "peer.log"
                    attempt(lambda container=container, log=log: retain_log(container, log))
                    attempt(lambda container=container: run("docker", "rm", "--force", container))
            attempt(remove_network)
            if failures:
                message = "; ".join(f"{type(error).__name__}: {error}" for error in failures)
                if original_failure is None:
                    raise RuntimeError(f"capture cleanup failed: {message}") from failures[0]
                print(f"capture cleanup failed: {message}", file=sys.stderr)

if __name__ == "__main__":
    main()
