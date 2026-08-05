# Realistic-mix IRR reload 2026-08 — compact evidence extract

Compact extract from the eight green sealed artifact roots behind
[`../../irr-reload-realistic-mix-2026-08.md`](../../irr-reload-realistic-mix-2026-08.md)
(four roots per announcement-overlap point, `F = 0.1` and `F = 0.5`).
The full roots (multi-MB daemon logs, RSS streams, received views,
per-cell manifests, quiet samples, seals) plus the preserved
environmental red root are retained read-only off-repo in the campaign
artifact archive; this directory carries the independent verifier's
output and the digests needed to recognize the sealed originals
(listed in the receipt's provenance section).

| File | Source | Contents |
|---|---|---|
| `ov10-verification.json` / `ov50-verification.json` | `verify-receipt.py campaigns` `--output-dir` | verdict per overlap point: `status: "pass"`, 24 comparison rows + 8 grouped-control rows, commit + dataset binding, validated root order, embedded received-view delta |
| `ov10-comparison.csv` / `ov50-comparison.csv` | verifier `--output-dir` | all 24 cross-daemon reload rows per overlap point (4 reloads × 3 cells × 2 roots), repeat-tagged, exactly as re-derived by the verifier |
| `ov10-grouped-control.csv` / `ov50-grouped-control.csv` | verifier `--output-dir` | all 8 standalone grouped-control rows per overlap point (4 reloads × 2 roots), repeat-tagged, exactly as re-derived by the verifier |
| `ov10-received-view-delta-{A,B}.json` / `ov50-received-view-delta-{A,B}.json` | `verify-receipt.py received-view-delta` | standalone pointwise-subset verdict per A/B repeat: overlap allocation, suppressed runner-up pair count, `status: "pass"` |
| `SHA256SUMS` | this directory | digests of every extract file above |

Every extract is byte-identical to the file the verifier emitted over
the sealed roots. Verify this directory with `sha256sum -c SHA256SUMS`.
