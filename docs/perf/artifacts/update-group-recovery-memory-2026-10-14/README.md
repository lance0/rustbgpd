# Update-group recovery memory artifacts (14 October 2026)

Compact public evidence for the [dated receipt](../../update-group-recovery-memory-2026-10-14.md).
All eight measured legs and 32 phase samples are retained. The earlier CI
configuration failure occurred before any build or measurement.

| File | Contents |
| --- | --- |
| [`comparison.json`](comparison.json) | Original validator output with only scope paths replaced by distinct aliases; exact numeric phase values, recovery gauges, inventory, withdrawals, peaks and mean ratios are unchanged |
| [`provenance.json`](provenance.json) | Measured source, binary and instrumentation hashes; build and environment; exact before/end snapshots; owned process identities and original evidence hashes; prior attempt and hosted artifact retention |

The original scope identities are SHA-256 hashed over their stripped UTF-8
paths and mapped to `scope-01` through `scope-08`. Process executable paths are
reduced to basenames. Hostnames and machine-specific filesystem paths are
omitted. Numeric PID/start identities and memory/inventory values are retained.
The original comparison and ownership-log hashes identify the unsanitized
evidence; the public extracts cannot replay its complete ownership checks.

From this directory, recompute the two mean-peak ratios without measuring:

```bash
python3 - <<'PY'
import json
from pathlib import Path
data = json.loads(Path("comparison.json").read_text())
for cell in ("dataset-reevaluate", "peer-down"):
    peaks = {
        role: [row["scope_memory_peak_bytes"] for row in data["rows"]
               if row["cell"] == cell and row["role"] == role]
        for role in ("baseline", "candidate")
    }
    assert all(len(values) == 2 for values in peaks.values())
    print(cell, sum(peaks["candidate"]) / sum(peaks["baseline"]))
PY
```

The [hosted job](https://github.com/lance0/rustbgpd/actions/runs/38495536388/job/115630552079)
published artifact `11864360496`, expiring on 2026-11-13. Its original ZIP was
privately archived and checksum-verified; the digest is in `provenance.json`.
Full build/process logs and frozen source overlays remain in that separate
archive. The existing `bench/scale/recovery_memory.py summarize` command
replays validation against the full original campaign, not these compact
extracts.
