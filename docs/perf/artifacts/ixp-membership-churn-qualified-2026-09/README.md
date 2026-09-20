# Qualified membership cell artifacts

These files retain the [passing fresh membership cell](../../ixp-membership-churn-qualified-2026-09.md) with initial-export readiness service and the corrected Python terminal lifecycle.

- [Full compressed evidence](fresh-terminal-drain-702.tar.gz) and [original passing qualification](fresh-terminal-drain-702-qualification.json).
- [Split source/binary provenance](split-provenance.json), [candidate/merged source equivalence](source-equivalence.json), and retrospective [host metadata](host.json).
- [SHA-256 checksums](SHA256SUMS).

The archive includes complete daemon and wire logs, probes, memory samples, quiet-host admission, configurations, observed session/dataset/metric receipts, lifecycle exits, original-file restoration, and frozen replay sources. The helper in `replay/` is exactly the measured reviewed helper; the checker is unchanged from the earlier cells.

Deterministic generated member-policy and dataset input files are omitted, with original hashes retained. The raw preflight resource snapshot is represented by sanitized host metadata. Public copies normalize machine-specific paths and omit the final raw policy JSON's dataset `path` fields. The publication manifest identifies each transformation or omission and both hashes where applicable. Observed results, timestamps, warnings and failure rows are untouched; original private evidence remains intact.

From this directory:

```bash
sha256sum -c SHA256SUMS
receipt_dir=$(mktemp -d)
tar -xzf fresh-terminal-drain-702.tar.gz -C "$receipt_dir"
python3 "$receipt_dir/fresh-terminal-drain-702/replay/check_membership_cell.py" \
    "$receipt_dir/fresh-terminal-drain-702" 700 400400 200200 600 0 4
```

Expected exit is zero, `pass` is true, and `errors` is empty. Both original red receipts remain linked from the main report; neither was overwritten or reclassified.
