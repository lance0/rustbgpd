# Shared recovery memory evidence (14 October 2026)

Compact evidence for the [dated receipt](../../update-group-shared-recovery-memory-2026-10-14.md): eight fresh hosted profile/cell VMs, all 64 legs and 256 phases. Candidate status: **passed**.

`comparison.json` retains exact numeric rows, supported matched ratios, charged
proofs and every strict validation/fallback result. `provenance.json` retains
compiled source identity, binary/build/frozen hashes, each original ZIP digest,
before/end snapshots, process identities and local correctness-control hashes.

Scope paths map to globally unique aliases with SHA-256 over their original
stripped UTF-8 paths. Numeric PID/start identities are namespaced by source/profile/cell/job;
they may legitimately repeat across separate VMs. Executable paths become
basenames. No hostnames, private machine paths or tracker text is copied.
Full original archives remain separate; public extracts cannot replay ownership.

To recompute supported matched ratios without running a workload:

```python
import json
from pathlib import Path
for summary in json.loads(Path("comparison.json").read_text())["summaries"]:
    if summary["candidate_to_control_mean_peak_ratio"] is None:
        continue
    peaks = summary["peaks_bytes"]
    print(summary["profile"], summary["cell"], summary["comparator"],
          sum(peaks["candidate"]) / sum(peaks[summary["comparator"]]))
```

This is manager-direct RIB memory with harness consumers and export preflight,
not a timing, component RSS, whole-daemon, final-wire, TCP or deployment receipt.
