#!/usr/bin/env python3
"""Reproduce the v0.74.0 history/GR fixture slice using its official Linux archive.

Requires Docker; creates one network-isolated container. Output must not exist.
The archived fixture bytes stay unchanged; timestamps and clock-domain identity
are capture-specific, so a recapture compares history content, not file hashes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import uuid

ARCHIVE_SHA256 = "03c064492da4ceb3119b09bf986c4bcc3b629e6d18950d476ad9a372a7a534ce"
DAEMON_SHA256 = "672abd3c336536734df733c259be2587a89d8c762754467faf17626b44b0acaf"
FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/state/v0.74.0"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(*args):
    return subprocess.check_output(args, text=True, timeout=60).strip()


def wait_for(predicate):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise TimeoutError("release writer did not acknowledge the requested state")


def check_history(row, expected):
    """Compare emitted history, permitting only the capture-time field to vary."""
    actual = dict(row)
    archived = dict(expected)
    actual.pop("timestamp_unix_seconds")
    archived.pop("timestamp_unix_seconds")
    require(actual == archived, "released history content differs from archive")


def recover_container(name, nonce, image):
    result = subprocess.run(["docker", "inspect", "--type", "container", name],
                            capture_output=True, text=True, timeout=10)
    if result.returncode:
        # Docker's absence wording and capitalization vary across releases.
        if f"no such container: {name}" in result.stderr.lower():
            return None
        raise RuntimeError(f"cannot inspect capture container: {result.stderr}")
    inspected = json.loads(result.stdout)
    require(len(inspected) == 1, "ambiguous capture container identity")
    container = inspected[0]
    require(container["Name"] == f"/{name}"
            and (container["Config"].get("Labels") or {}).get("org.rustbgpd.capture-owner") == nonce
            and container["Image"] == image,
            "capture container ownership does not match; refusing cleanup")
    return container["Id"]


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
        binary = root / "rustbgpd"
        with tarfile.open(args.archive) as archive:
            binary.write_bytes(archive.extractfile("rustbgpd").read())
        require(hashlib.sha256(binary.read_bytes()).hexdigest() == DAEMON_SHA256, "unexpected release daemon SHA-256")
        binary.chmod(0o755)
        config = root / "config"
        state = root / "state"
        config.mkdir()
        state.mkdir(mode=0o700)
        source = (FIXTURE / "config.toml").read_text()
        (config / "config.toml").write_text(source)
        image = run("docker", "image", "inspect", "--format", "{{.Id}}", args.image)
        nonce = uuid.uuid4().hex
        name = f"released-state-{nonce}"
        container = None
        try:
            container = run(
                "docker", "create", "--name", name,
                "--label", f"org.rustbgpd.capture-owner={nonce}",
                "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                "-v", f"{binary}:/usr/local/bin/rustbgpd:ro",
                "-v", f"{config}:/etc/rustbgpd", "-v", f"{state}:/var/lib/rustbgpd",
                "--entrypoint", "/usr/local/bin/rustbgpd", image,
                "/etc/rustbgpd/config.toml",
            )
            run("docker", "start", container)
            history = state / "config-history"
            wait_for(lambda: len(list(history.glob("v2-*.json"))) == 1
                     and (state / "grpc.sock").exists())
            version = run("docker", "exec", container, "/usr/local/bin/rustbgpd", "--version")
            require(version == "rustbgpd 0.74.0", version)
            # Generate the oversized input only in this temporary capture workspace.
            (config / "config.toml").write_text(source.replace(
                'description = "released-state-fixture"',
                'description = "' + "x" * (10 * 1024 * 1024 + 1) + '"',
            ))
            run("docker", "kill", "--signal", "HUP", container)
            wait_for(lambda: len(list(history.glob("v3-*.json"))) == 1)
            run("docker", "kill", "--signal", "TERM", container)
            exit_code = run("docker", "wait", container)
            require(exit_code == "0", exit_code)
            marker_bytes = (state / "gr-restart.toml").read_bytes()
            shutil.copytree(history, args.output / "config-history")
            (args.output / "gr-restart.toml").write_bytes(marker_bytes)
            marker = tomllib.loads(marker_bytes.decode())
            require(marker["version"] == 3 and "checkpoint_generation" not in marker, "release capture validation failed")
            require(marker["expires_at_boottime_ms"] > 0 and marker["boot_id"], "release capture validation failed")
            rows = sorted(history.glob("*.json"))
            require(len(rows) == 2, "release capture validation failed")
            for path, expected_version in zip(rows, (2, 3), strict=True):
                row = json.loads(path.read_bytes())
                require(row["version"] == expected_version, "release capture validation failed")
                require(row["sequence"] == expected_version - 1, "release capture validation failed")
                if expected_version == 2:
                    require(hashlib.sha256(row["normalized_toml"].encode()).hexdigest() == row["sha256"], "release capture validation failed")
                else:
                    require("normalized_toml" not in row and "manifest" not in row, "release capture validation failed")
                    require(row["normalized_toml_bytes"] > 10 * 1024 * 1024, "release capture validation failed")
                archived = list((FIXTURE / "config-history").glob(f"v{expected_version}-*.json"))
                require(len(archived) == 1, "expected exactly one archived row per format")
                check_history(row, json.loads(archived[0].read_bytes()))
            (args.output / "capture.json").write_text(json.dumps({
                "release": "v0.74.0",
                "tag_commit": "4d14851f77b064dd254f2319708dd91f281f9b0d",
                "archive_sha256": ARCHIVE_SHA256,
                "daemon_sha256": DAEMON_SHA256,
                "version_stdout": version,
                "container_image": run("docker", "inspect", "--format", "{{.Image}}", container),
                "network_mode": "none",
                "daemon_argv": ["/usr/local/bin/rustbgpd", "/etc/rustbgpd/config.toml"],
                "signals": ["HUP after boot v2 and gRPC socket", "TERM after v3 publication"],
                "exit_code": int(exit_code),
            }, indent=2) + "\n")
        finally:
            original_failure = sys.exception()
            try:
                if not container:
                    container = recover_container(name, nonce, image)
                if container:
                    try:
                        logs = subprocess.run(["docker", "logs", container], capture_output=True, timeout=10)
                        (args.output / "daemon.log").write_bytes((logs.stdout + logs.stderr).rstrip() + b"\n")
                        require(logs.returncode == 0, "docker logs failed; see retained daemon.log")
                    finally:
                        run("docker", "rm", "--force", container)
            except Exception as cleanup_error:
                if original_failure is None:
                    raise
                print(f"capture cleanup failed: {cleanup_error}", file=sys.stderr)


if __name__ == "__main__":
    main()
