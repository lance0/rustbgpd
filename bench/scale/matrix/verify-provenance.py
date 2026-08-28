#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

HASH = re.compile(r"[0-9a-f]{64}")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
COMMON = {
    "bench/scale/provenance.sh",
    "bench/scale/matrix/run-matrix.sh",
    "bench/scale/matrix/verify-provenance.py",
    "bench/scale/matrix/rss-sampler.sh",
    "bench/scale/host-quiet.sh",
    "tests/soak/host-lock.sh",
}
GENERATORS = {
    "rustbgpd": "bench/scale/reloadstall/gen-scenario.py",
    "bird": "bench/scale/reloadstall/gen-bird-scenario.py",
    "openbgpd": "bench/scale/reloadstall/gen-obgpd-scenario.py",
}

def fail(message):
    raise ValueError(message)

def hashed_map(value, expected):
    if not isinstance(value, dict) or set(value) != expected:
        fail("wrong source hash roster")
    if not all(isinstance(v, str) and HASH.fullmatch(v) for v in value.values()):
        fail("malformed source hash")

def verify(path, expected_cell):
    data = json.loads(Path(path).read_text())
    if set(data) != {"schema", "cell", "git", "toolchain", "host", "sources", "workload"} or data["schema"] != 1:
        fail("wrong provenance schema")
    cell = data["cell"]
    if cell not in GENERATORS:
        fail("unknown cell")
    if cell != expected_cell:
        fail("provenance cell does not match requested cell")
    git = data["git"]
    if set(git) != {"commit", "tree", "dirty"} or not re.fullmatch(r"[0-9a-f]{40}", git["commit"]) or not re.fullmatch(r"[0-9a-f]{40}", git["tree"]) or not isinstance(git["dirty"], bool):
        fail("malformed git identity")
    if not isinstance(data["toolchain"], str) or not data["toolchain"] or not isinstance(data["host"], str) or not data["host"]:
        fail("missing toolchain or host")
    sources = data["sources"]
    if set(sources) != {"common", "generator", "reloadstall"}:
        fail("wrong source fields")
    hashed_map(sources["common"], COMMON)
    hashed_map(sources["generator"], {GENERATORS[cell]})
    if set(sources["reloadstall"]) != {"path", "sha256"} or sources["reloadstall"]["path"] != "bench/scale/target/release/reloadstall" or not HASH.fullmatch(sources["reloadstall"]["sha256"]):
        fail("malformed reloadstall identity")
    workload = data["workload"]
    if cell == "rustbgpd":
        if set(workload) != {"binary", "sha256"} or workload["binary"] != "target/release/rustbgpd" or not HASH.fullmatch(workload["sha256"]):
            fail("malformed rustbgpd workload")
    elif set(workload) != {"image_ref", "image_id"} or workload["image_ref"] != {"bird": "bird:3.3.1", "openbgpd": "openbgpd/openbgpd:9.1"}[cell] or not IMAGE.fullmatch(workload["image_id"]):
        fail("malformed competitor workload")

if __name__ == "__main__":
    try:
        if len(sys.argv) != 3 or sys.argv[2] not in GENERATORS:
            fail("usage: verify-provenance.py CELL/provenance.json EXPECTED_CELL")
        verify(sys.argv[1], sys.argv[2])
    except (OSError, ValueError, json.JSONDecodeError, KeyError, TypeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
