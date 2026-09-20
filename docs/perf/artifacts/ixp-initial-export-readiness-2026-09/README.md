# Initial-export readiness artifacts

These files preserve the [readiness-corrected cell](../../ixp-initial-export-readiness-2026-09.md), whose sole qualification failure is a teardown `ConnectionReset` warning.

- [Full compressed evidence](readiness-fixed-original-helper.tar.gz).
- [Original qualification](readiness-fixed-original-helper-qualification.json), [split source/binary provenance](split-provenance.json), and retrospective [host metadata](host.json).
- [SHA-256 checksums](SHA256SUMS).

The archive retains daemon and harness logs, probe captures, memory samples, quiet-host admission, configurations, before/after session evidence, dataset status and metrics, lifecycle exits, restored-binary proof, and the original helper/checker under `replay/`. Deterministic generated member-policy and dataset inputs are omitted with their original hashes retained. The raw preflight resource snapshot is omitted in favor of sanitized metadata. The publication manifest records every omission or transformation.

Public copies replace machine-specific paths, remove the final raw policy JSON's dataset `path` fields, and normalize build-artifact paths. Original measurements, failure rows, warnings and timestamps remain unchanged. The separate dataset-status receipts used by the checker are complete. Original private evidence is untouched.

From this directory:

```bash
sha256sum -c SHA256SUMS
receipt_dir=$(mktemp -d)
tar -xzf readiness-fixed-original-helper.tar.gz -C "$receipt_dir"
# Expected exit 1 and exactly one writer warning error:
python3 "$receipt_dir/candidate-initial-export-readiness-702/replay/check_membership_cell.py" \
    "$receipt_dir/candidate-initial-export-readiness-702" 700 400400 200200 600 0 4
```

The expected error is `unclassified/active WARN: writer: write/flush failed`, classified in the retained result as `teardown`. This remains a failed qualification even though all readiness and route-delivery checks passed.
