#!/usr/bin/env python3
"""Check lab verification and argument boundaries without starting containers."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]

with tempfile.TemporaryDirectory() as directory:
    temporary = Path(directory)
    docker = temporary / "docker"
    docker.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
Path(os.environ["CALLS"]).touch()
scenario = os.environ.get("SCENARIO", "healthy")
fault = scenario in ("rejected", "leaked-long-prefix")
if "neighbor" in sys.argv:
    result = [{"address": address, "remote_asn": asn,
        "state": "Idle" if scenario == "idle" else "Established",
        "stale": scenario == "stale"}
        for address, asn in (("10.98.0.20", 65002), ("10.98.0.30", 65003))]
    if scenario == "one-member": result.pop()
elif "caches" in sys.argv:
    result = {"caches": [{"address": "10.98.0.40:3323", "connected": scenario != "cache-down",
        "accepted": {"vrp_v4_count": 0 if scenario == "empty-vrps" else 1}}]}
elif "--rejected" in sys.argv:
    result = {"retention_enabled": True, "evictions_since_reset": 0,
        "rejected_routes": [
            {"prefix": "198.51.100.0/24", "reason": "policy_reject",
             "reason_detail": "reject-rpki-invalid", "rpki_validation": "invalid"},
            {"prefix": "203.0.113.0/25", "reason": "policy_reject",
             "reason_detail": "reject-long-prefixes", "rpki_validation": "not_found"}]}
elif "rib" in sys.argv:
    result = [] if scenario == "missing-route" or fault else [{
        "prefix": "198.51.100.0/24", "best": scenario != "not-best",
        "peer_address": "10.98.0.30" if scenario == "wrong-peer" else "10.98.0.20",
        "validation_state": "invalid" if scenario == "invalid" else "valid"}]
elif "member-b" in sys.argv:
    result = {"paths": [] if scenario == "not-exported" else [{
        "valid": scenario != "unusable",
        "aspath": {"string": "65500 65002" if scenario == "as-prepend" else "65002"},
        "nexthops": [{"ip": "10.98.0.10" if scenario == "next-hop-self" else "10.98.0.20"}]}]}
    if fault and not (scenario == "leaked-long-prefix" and "203.0.113.0/25" in sys.argv[-1]):
        result = {"paths": []}
elif "member-a" in sys.argv:
    sys.exit(0)
else:
    sys.exit(99)
print(json.dumps(result))
''')
    docker.chmod(0o755)
    sleep = temporary / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o755)
    calls = temporary / "calls"
    environment = os.environ | {"PATH": f"{temporary}:{os.environ['PATH']}", "CALLS": str(calls)}
    script = str(ROOT / "labs/ixp/lab.sh")
    for scenario in ("healthy", "idle", "stale", "one-member", "cache-down", "empty-vrps",
                     "missing-route", "not-best", "wrong-peer", "invalid", "not-exported",
                     "unusable", "as-prepend", "next-hop-self"):
        result = subprocess.run(["bash", script, "verify"], cwd=ROOT,
                                env=environment | {"SCENARIO": scenario}, capture_output=True)
        assert (result.returncode == 0) == (scenario == "healthy"), (scenario, result.stderr)
    for scenario in ("rejected", "leaked-long-prefix"):
        result = subprocess.run(["bash", script, "break"], cwd=ROOT,
                                env=environment | {"SCENARIO": scenario}, capture_output=True)
        assert (result.returncode == 0) == (scenario == "rejected"), (scenario, result.stderr)
    calls.unlink()
    for arguments in ((), ("../up",), ("verify", "extra")):
        result = subprocess.run(["bash", script, *arguments], cwd=ROOT, env=environment,
                                capture_output=True)
        assert result.returncode == 2, result.stderr
        assert not calls.exists(), "invalid phase reached Docker"
    sentinel = temporary / "injected"
    for name, phase in (("../ixp", "up"), (f"$(touch {sentinel})", "up"),
                        ("ixp", f"$(touch {sentinel})")):
        result = subprocess.run(["just", "lab", name, phase], cwd=ROOT, env=environment,
                                capture_output=True)
        assert result.returncode != 0, result.stdout
        assert not calls.exists(), "invalid lab or phase reached Docker"
        assert not sentinel.exists(), "lab argument was executed by the shell"
print("IXP verification and argument checks passed.")
