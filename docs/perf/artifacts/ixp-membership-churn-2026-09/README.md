# Membership churn cell artifacts

These archives retain the passing 20+2 preparation, failed 702-member qualification, and expected v0.70.0 first-reload rejection described in the [receipt](../../ixp-membership-churn-2026-09.md).

- [Preparation archive](preparation-20-cli-contract.tar.gz) and [qualification](preparation-20-cli-contract-qualification.json): complete PASS.
- [702-member archive](positive-702.tar.gz) and [qualification](positive-702-qualification.json): complete **FAIL**, eight health deadlines. The historical directory name `positive-702` denotes the current-source test, not a passing outcome.
- [v0.70.0 archive](negative-702-v0.70.0.tar.gz): exact initial inventories followed by the intended first-reload rejection, with the controlled-stop record.
- [Build receipt](build-receipt.json), retrospective [host metadata](host.json), and [SHA-256 checksums](SHA256SUMS).

Each archive includes the full daemon and wire logs, CLI probe captures, memory samples, quiet-host evidence, configuration files, before/after session snapshots, dataset metrics, lifecycle exits and provenance. The two checker/helper sources are frozen under `replay/`. Generated per-member policy and dataset input files are omitted: their hashes remain in the publication manifest, and the pinned generator, helper and workload parameters reproduce them. The observed dataset status and metrics needed for replay remain complete.

Public copies replace machine-specific checkout, evidence and host-lock paths with placeholders. They remove only the `path` field from the raw final policy-status JSON; the qualification uses the separate path-free dataset receipts. Each archive's `publication-manifest.json` records original and published hashes and identifies transformed and omitted files. Original local evidence is untouched. Timestamps, measurements, failure rows and error messages are unchanged.

From this directory, verify and extract into an empty temporary directory:

```bash
sha256sum -c SHA256SUMS
receipt_dir=$(mktemp -d)
tar -xzf preparation-20-cli-contract.tar.gz -C "$receipt_dir"
tar -xzf positive-702.tar.gz -C "$receipt_dir"
tar -xzf negative-702-v0.70.0.tar.gz -C "$receipt_dir"
python3 "$receipt_dir/preparation-20-cli-contract/replay/check_membership_cell.py" \
    "$receipt_dir/preparation-20-cli-contract" 20 11440 5720 16 0 4
# Expected exit 1 and exactly ["probes.csv failure"]:
python3 "$receipt_dir/positive-702/replay/check_membership_cell.py" \
    "$receipt_dir/positive-702" 700 400400 200200 600 0 4
```

The negative control intentionally stops at its first rejected reload. Inspect `rustbgpd/reloadstall.log`, `rustbgpd/daemon.log`, `rustbgpd/scenario/membership-0.json`, and `controlled-stop.json`; it is not input for a four-successful-reload qualification.
