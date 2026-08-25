# Reload-generation phase attribution artifact

This directory is the checked-in summary of two sequential, immutable full
campaigns. `phase-timings.csv` copies the eight verifier-bound terminal records
without timestamps. `verification.json` binds the candidate, fetched base,
source identity, original root and phase-file hashes, daemon identities, gates,
and causal arithmetic. `SHA256SUMS` seals these three files.

Both original roots remain at the paths recorded in `verification.json`. Their
root and cell checksum rosters passed before this summary was produced. Each
root has four rows, 320/320 sessions, no decode errors or session loss, and a
distinct daemon PID/start identity.

`authoritative_fallback=true` is the outer peer-manager classification expected
for this per-client-best workload. It does not mean the inner authoritative RIB
batch degraded per member: all eight matching RIB terminal records report
`n_fallback_members=0`, `n_shared_members=320`, and one destination group.

The receipt localizes the curve to the synchronous batched authoritative RIB
transition but does not identify its internal mechanism or claim an
improvement. The next discriminator is non-overlapping timing and deterministic
work counts inside `apply_export_policy_replacements_synchronously` and
`apply_batched_group_transition`, first reproduced in-process in deterministic
RIB tests. No optimization is authorized by this receipt.
