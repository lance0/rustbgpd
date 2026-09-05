#!/usr/bin/env python3
"""Check verification and argument boundaries without starting containers."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(*args, **env):
    return subprocess.run(args, cwd=ROOT, env=os.environ | env, capture_output=True, text=True)


with tempfile.TemporaryDirectory() as directory:
    temporary = Path(directory)
    docker = temporary / "docker"
    docker.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
Path(os.environ["CALLS"]).touch()
scenario = os.environ.get("SCENARIO", "healthy")
if "neighbor" in sys.argv:
    print(json.dumps([{"address": "10.99.0.20", "remote_asn": 65002,
        "state": "Idle" if scenario == "idle" else "Established",
        "stale": scenario == "stale"}]))
elif "rib" in sys.argv:
    print(json.dumps([] if scenario == "missing" else [{
        "prefix": "192.168.2.0/24" if scenario == "wrong-prefix" else "192.168.1.0/24",
        "peer_address": "10.99.0.30" if scenario == "wrong-peer" else "10.99.0.20",
        "best": scenario != "not-best"}]))
else:
    sys.exit(99)
''')
    docker.chmod(0o755)
    calls = temporary / "calls"
    environment = {"PATH": f"{temporary}:{os.environ['PATH']}", "CALLS": str(calls)}
    script = str(ROOT / "labs/quickstart/lab.sh")
    for scenario in ("healthy", "idle", "stale", "missing", "wrong-prefix", "wrong-peer", "not-best"):
        result = run("bash", script, "verify", **environment, SCENARIO=scenario)
        assert (result.returncode == 0) == (scenario == "healthy"), (scenario, result.stderr)
    calls.unlink()
    for arguments in ((), ("../up",), ("verify", "extra")):
        result = run("bash", script, *arguments, **environment)
        assert result.returncode == 2, result.stderr
        assert not calls.exists(), "invalid phase reached Docker"
    sentinel = temporary / "injected"
    for name, phase in (("../quickstart", "up"), (f"$(touch {sentinel})", "up"),
                        ("quickstart", f"$(touch {sentinel})")):
        result = run("just", "lab", name, phase, **environment)
        assert result.returncode != 0, result.stdout
        assert not calls.exists(), "invalid lab or phase reached Docker"
        assert not sentinel.exists(), "lab argument was executed by the shell"
print("Quickstart verification and argument checks passed.")
