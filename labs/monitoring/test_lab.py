#!/usr/bin/env python3
"""Negative BMP snapshot and lab-argument checks; no containers required."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

DIRECTORY = Path(__file__).resolve().parent
ROOT = DIRECTORY.parents[1]
spec = importlib.util.spec_from_file_location("check_bmp", DIRECTORY / "check_bmp.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def message(kind, body, sequence, connection=0):
    raw = struct.pack("!BIB", 3, 6 + len(body), kind) + body
    return {"conn": connection, "seq": sequence, "hex": raw.hex()}


def update(nlri=b""):
    return b"\xff" * 16 + struct.pack("!HBHH", 23 + len(nlri), 2, 0, 0) + nlri


peer = b"\x03" + bytes(41)
valid = [message(4, b"", 0), message(3, peer, 1),
         message(0, peer + update(b"\x18\xc6\x33\x64"), 2),
         message(0, peer + update(), 3)]
assert check.snapshot(valid) == (0, {"198.51.100.0/24"})
invalid = [[], valid[:-1], [valid[0], *valid[2:]], valid[:2] + [valid[3]]]
wrong_prefix = copy.deepcopy(valid)
wrong_prefix[2]["hex"] = message(0, peer + update(b"\x18\xcb\x00\x71"), 2)["hex"]
invalid.append(wrong_prefix)
wrong_type = copy.deepcopy(valid)
wrong_type[2]["hex"] = message(0, bytes(42) + update(b"\x18\xc6\x33\x64"), 2)["hex"]
invalid.append(wrong_type)
for nlri in (b"\x21", b"\x18\xc6"):
    malformed_nlri = copy.deepcopy(valid)
    malformed_nlri[2] = message(0, peer + update(nlri), 2)
    invalid.append(malformed_nlri)
for raw in [bytes.fromhex(valid[2]["hex"])[:-1],
            b"\x04" + bytes.fromhex(valid[2]["hex"])[1:],
            struct.pack("!BIB", 3, 71, 0) + peer + update(b"\x21")]:
    corrupt = copy.deepcopy(valid)
    corrupt[2]["hex"] = raw.hex()
    invalid.append(corrupt)
# Complete old data must not certify an incomplete replacement connection.
invalid.append(valid + [message(4, b"", 0, 1), message(3, peer, 1, 1)])
for interruption in ([message(2, peer, 3), message(3, peer, 4)],
                     [message(3, peer, 3)], [message(5, b"", 3)]):
    invalid.append(valid[:3] + interruption + [message(0, peer + update(), 3 + len(interruption))])
for capture in invalid:
    try:
        check.snapshot(capture)
    except (ValueError, KeyError, struct.error):
        continue
    raise AssertionError("invalid or incomplete BMP snapshot accepted")

with tempfile.TemporaryDirectory() as directory:
    temporary = Path(directory)
    capture = temporary / "capture.jsonl"
    capture.write_text("\n".join(json.dumps(m) for m in valid) + "\n")
    docker = temporary / "docker"
    docker.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
Path(os.environ["CALLS"]).touch()
scenario = os.environ.get("SCENARIO", "healthy")
probe = Path(os.environ["CALLS"] + ".probe")
if "stop" in sys.argv:
    sys.exit(0)
if "vtysh" in sys.argv:
    if sys.argv[-1] == "network 203.0.113.0/24" and scenario != "ignored-probe":
        probe.touch()
    if sys.argv[-1] == "no network 203.0.113.0/24" and scenario != "stuck-probe":
        probe.unlink(missing_ok=True)
    sys.exit(0)
if "neighbor" in sys.argv:
    print(json.dumps([{"address": "10.96.0.20", "remote_asn": 65002,
        "state": "Idle" if scenario == "idle" else "Established"}]))
elif "rib" in sys.argv:
    prefix = sys.argv[sys.argv.index("--prefix") + 1]
    present = probe.exists() if prefix == "203.0.113.0/24" else scenario != "no-route"
    print(json.dumps([{"prefix": prefix, "best": True, "peer_address": "10.96.0.20"}]
                     if present else []))
elif "receiver" in sys.argv:
    if scenario == "stopped": sys.exit(1)
    print("" if scenario == "empty" else Path(os.environ["CAPTURE"]).read_text())
else:
    sys.exit(99)
''')
    docker.chmod(0o755)
    sleep = temporary / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o755)
    calls = temporary / "calls"
    environment = os.environ | {"PATH": f"{temporary}:{os.environ['PATH']}",
                                "CALLS": str(calls), "CAPTURE": str(capture)}
    for scenario in ("healthy", "idle", "no-route", "stopped", "empty"):
        result = subprocess.run(["bash", str(DIRECTORY / "lab.sh"), "verify"], cwd=ROOT,
                                env=environment | {"SCENARIO": scenario}, capture_output=True)
        assert (result.returncode == 0) == (scenario == "healthy"), (scenario, result.stderr)
    for scenario in ("healthy", "ignored-probe", "stuck-probe"):
        result = subprocess.run(["bash", str(DIRECTORY / "lab.sh"), "break"], cwd=ROOT,
                                env=environment | {"SCENARIO": scenario}, capture_output=True)
        assert (result.returncode == 0) == (scenario == "healthy"), (scenario, result.stderr)
    calls.unlink()
    for args in ([], ["../up"], ["verify", "extra"], ["$(touch unexpected)"]):
        result = subprocess.run(["bash", str(DIRECTORY / "lab.sh"), *args], cwd=ROOT,
                                env=environment, capture_output=True)
        assert result.returncode == 2 and not calls.exists(), result.stderr
print("Monitoring snapshot, verification, and argument checks passed.")
