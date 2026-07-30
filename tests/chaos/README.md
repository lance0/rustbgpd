# Chaos harnesses

Targeted stress harnesses that bounce specific subsystems hard and assert
post-storm health. These are *not* the M33 long-running soak — they're
short, focused, and meant to flush bugs the steady-state soak doesn't.

Each script:

- runs against an already-deployed containerlab topology (the script
  states which one in its header)
- writes a per-run dir under `tests/chaos/runs/<UTC-timestamp>/` with
  the chaos driver log, script-specific sample/probe CSV or log output,
  and a final `report.json` (`tests/chaos/runs/` is gitignored and stays
  local, parity with `tests/soak/runs/`)
- exits 0 on clean pass, non-zero on a gate failure or harness setup error

## Available harnesses

| Script | Topology | Closes | Notes |
|---|---|---|---|
| [`chaos-flap-storm.sh`](chaos-flap-storm.sh) | M33 (synthetic peers) | Peer flap storms | Bounces a synthetic tester via `EnableNeighbor`/`DisableNeighbor` in a tight loop; verifies gRPC `GetHealth` stays OK throughout, memory growth stays under 10 MB above the pre-storm baseline, no process restart, and at least 3 successful Established-after-Disable cycles. |
| [`chaos-grpc-churn.sh`](chaos-grpc-churn.sh) | M33 (synthetic peers) | gRPC churn | Fires concurrent `AddNeighbor` + `DeleteNeighbor` + `SoftResetIn` calls against the daemon; verifies no deadlock, gRPC stays responsive throughout, no panic. |
| [`chaos-gr-cycles.sh`](chaos-gr-cycles.sh) | M16 (FRR LLGR) | Repeated GR recovery | Bounces FRR's BGP daemon repeatedly with GR negotiated; verifies the RR's stale-sweep / LLGR-promote / clear-on-reconnect lifecycle works correctly across N cycles. |

## Prerequisites

- `containerlab deploy -t tests/interop/<topology>.clab.yml` — each
  script's header states which.
- The rustbgpd daemon running inside the topology. Each script sources
  `tests/interop/scripts/test-lib.sh` for `resolve_grpc_addr` /
  `grpc_health`; the scripts do NOT start the daemon — they fail if it
  is not already up.
- `grpcurl` on the host (flap-storm, grpc-churn); `jq` (flap-storm).
  Arithmetic uses `awk` — no `bc` needed.

## Usage

```bash
# Default 60 s smoke run
bash tests/chaos/chaos-flap-storm.sh

# Longer sustained run
CHAOS_DURATION_SEC=300 bash tests/chaos/chaos-flap-storm.sh

# All three, sequential
for s in flap-storm grpc-churn gr-cycles; do
  bash tests/chaos/chaos-$s.sh || echo "$s failed"
done
```

Topology setup is the operator's responsibility — these scripts assume
the topology is up. They auto-clean their own state but never deploy
or destroy clab.
