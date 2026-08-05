# IRR reload comparison 2026-08 — compact evidence extract

Compact extract from the four green sealed artifact roots behind
[`../../irr-reload-comparison-2026-08.md`](../../irr-reload-comparison-2026-08.md).
The full roots (multi-MB daemon logs, RSS streams, per-cell manifests,
quiet samples, seals) are retained read-only off-repo in the campaign
artifact archive; this directory carries the independent verifier's
output and the digests needed to recognize the sealed originals (listed
in the receipt's provenance section).

| File | Source | Contents |
|---|---|---|
| `verification.json` | `verify-receipt.py campaigns` `--output-dir` | verdict: `status: "pass"`, 24 comparison rows + 8 grouped-control rows, commit + dataset binding, validated A/B/B/A root order |
| `comparison.csv` | verifier `--output-dir` | all 24 cross-daemon reload rows (4 reloads × 3 cells × 2 roots), repeat-tagged, exactly as re-derived by the verifier |
| `grouped-control.csv` | verifier `--output-dir` | all 8 standalone grouped-control rows (4 reloads × 2 roots), repeat-tagged, exactly as re-derived by the verifier |
| `SHA256SUMS` | this directory | digests of every extract file above |

Every extract is byte-identical to the file the verifier emitted over
the sealed roots. Verify this directory with `sha256sum -c SHA256SUMS`.
