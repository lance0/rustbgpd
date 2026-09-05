#!/usr/bin/env python3
"""Reject wrong winners, missing reflection, and unsafe lab arguments without Docker."""
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
duplicate = scenario.startswith("duplicate")
winner = "10.97.0.30" if duplicate else "10.97.0.20"
originator = "10.97.0.10" if duplicate else "10.97.0.20"
if "neighbor" in sys.argv:
    result = [{"address": address, "remote_asn": 65001,
        "route_reflector_client": scenario != "not-client",
        "state": "Idle" if scenario == "idle" else "Established"}
        for address in ("10.97.0.20", "10.97.0.30")]
    if scenario == "missing-peer": result.pop()
elif "advertised" in sys.argv:
    if "--explain" in sys.argv:
        result = {"decision": "deny", "route_peer_address": winner,
            "gates": [{"gate": "split_horizon", "verdict": "stop"}]}
        if scenario == "wrong-gate": result["gates"][0]["gate"] = "policy"
    else:
        result = [{}] if scenario in ("source-export", "duplicate-source-export") else []
elif "rib" in sys.argv:
    route = {"prefix": "198.51.100.0/24", "peer_address": winner, "best": True}
    result = {"best_route": route, "candidates": [],
        "best_reason": "lower_bgp_identifier" if duplicate else "only_path"}
    if duplicate or scenario == "extra-candidate":
        result["candidates"].append({"route": {"peer_address": "10.97.0.20"},
            "vs_best_reason": "lower_bgp_identifier", "vs_best_ordering": "worse"})
    if scenario == "wrong-winner": route["peer_address"] = "10.97.0.30"
    if scenario == "duplicate-wrong-reason": result["candidates"][0]["vs_best_reason"] = "higher_local_pref"
    if scenario == "duplicate-missing-candidate": result["candidates"].pop()
elif "show bgp ipv4 unicast 198.51.100.0/24 json" in sys.argv:
    result = {"paths": [{"valid": True, "originatorId": originator,
        "peer": {"peerId": "10.97.0.1"}, "clusterList": {"list": ["10.97.0.1"]},
        "nexthops": [{"ip": winner}]}]}
    if scenario in ("missing-reflection", "duplicate-missing-reflection"): result["paths"] = []
    if scenario == "wrong-originator": result["paths"][0]["originatorId"] = "10.97.0.99"
    if scenario == "missing-cluster": result["paths"][0]["clusterList"]["list"] = []
    if scenario == "wrong-next-hop": result["paths"][0]["nexthops"][0]["ip"] = "10.97.0.1"
    if ("client-b" if duplicate else "client-a") in sys.argv:
        result = {"paths": [] if scenario != "source-received" else [{"peer": {"peerId": "10.97.0.1"}}]}
elif "client-b" in sys.argv:
    sys.exit(0)
else:
    sys.exit(99)
print(json.dumps(result))
''')
    docker.chmod(0o755)
    # Fail the first retry so a negative snapshot is tested without waiting a minute.
    sleep = temporary / "sleep"
    sleep.write_text("#!/bin/sh\nexit 97\n")
    sleep.chmod(0o755)
    calls = temporary / "calls"
    environment = os.environ | {"PATH": f"{temporary}:{os.environ['PATH']}", "CALLS": str(calls)}
    script = str(ROOT / "labs/rr/lab.sh")
    for scenario in ("healthy", "idle", "not-client", "missing-peer", "wrong-winner",
                     "extra-candidate", "missing-reflection", "wrong-originator", "missing-cluster",
                     "wrong-next-hop", "wrong-gate", "source-export", "source-received"):
        result = subprocess.run(["bash", script, "verify"], cwd=ROOT,
                                env=environment | {"SCENARIO": scenario}, capture_output=True)
        assert result.returncode == (0 if scenario == "healthy" else 1), (scenario, result.stderr)
    for scenario in ("duplicate", "duplicate-wrong-reason", "duplicate-missing-candidate",
                     "duplicate-missing-reflection", "duplicate-source-export"):
        result = subprocess.run(["bash", script, "break"], cwd=ROOT,
                                env=environment | {"SCENARIO": scenario}, capture_output=True)
        assert result.returncode == (0 if scenario == "duplicate" else 97), (scenario, result.stderr)
    calls.unlink()
    for arguments in ((), ("../up",), ("verify", "extra"), ("$(touch injected)",)):
        result = subprocess.run(["bash", script, *arguments], cwd=ROOT, env=environment,
                                capture_output=True)
        assert result.returncode == 2, result.stderr
        assert not calls.exists(), "invalid phase reached Docker"
    sentinel = temporary / "injected"
    for name, phase in (("../rr", "up"), (f"$(touch {sentinel})", "up"),
                        ("rr", f"$(touch {sentinel})")):
        result = subprocess.run(["just", "lab", name, phase], cwd=ROOT, env=environment,
                                capture_output=True)
        assert result.returncode != 0, result.stdout
        assert not calls.exists(), "invalid lab or phase reached Docker"
        assert not sentinel.exists(), "lab argument was executed by the shell"
print("RR verification and argument checks passed.")
