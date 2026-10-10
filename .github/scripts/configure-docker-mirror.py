#!/usr/bin/env python3
"""Prefer the Docker Hub cache on an ephemeral CI runner."""

import json
from pathlib import Path
import subprocess
import tempfile


def configure(path):
    config = json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(config, dict):
        raise ValueError("Docker daemon configuration must be an object")
    mirrors = config.get("registry-mirrors", [])
    if not isinstance(mirrors, list) or not all(isinstance(m, str) for m in mirrors):
        raise ValueError("Docker registry-mirrors must be an array of strings")
    mirror = "https://mirror.gcr.io"
    config["registry-mirrors"] = [mirror, *(m for m in mirrors if m != mirror)]
    with tempfile.NamedTemporaryFile(mode="w") as candidate:
        json.dump(config, candidate)
        candidate.flush()
        subprocess.run(["dockerd", "--validate", "--config-file", candidate.name], check=True)
    path.write_text(json.dumps(config) + "\n")


if __name__ == "__main__":
    configure(Path("/etc/docker/daemon.json"))
