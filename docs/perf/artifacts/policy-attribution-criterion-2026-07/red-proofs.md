# Verifier red proofs

Each mutation was applied independently, checked with the command shown, and
restored before the next mutation.

Command except where noted:

```console
python3 docs/perf/artifacts/policy-attribution-criterion-2026-07/verify.py
```

| Guard | Mutation | Exact failure (exit 1) |
|---|---|---|
| Source SHA | `manifest.json` control SHA replaced with forty zeroes | `policy attribution receipt error: wrong control source SHA` |
| Parent SHA | `manifest.json` isolated base SHA replaced with forty zeroes | `policy attribution receipt error: wrong isolated parent SHA` |
| Governor/pinning | `metadata.txt` governor changed from `performance` to `powersave` | `policy attribution receipt error: governor metadata drift` |
| Task pinning | `metadata.txt` `use_taskset` changed from `1` to `0` | `policy attribution receipt error: taskset/core metadata drift` |
| Host preflight | `metadata.txt` host lock changed from `acquired` to `busy` | `policy attribution receipt error: host lock was not acquired` |
| Host load | `metadata.txt` preflight load changed from `0.22` to `2.00` | `policy attribution receipt error: preflight load was not below 2` |
| Host competitors | `metadata.txt` no-competitor flag changed from `true` to `false` | `policy attribution receipt error: competing-workload preflight failed` |
| Attempt cardinality | `manifest.json` attempts changed from `6` to `5` | `policy attribution receipt error: attempt count must be exactly six` |
| Six-attempt alternating order | Manifest attempt 1 changed from `base-first` to `head-first` | `policy attribution receipt error: attempt order is not alternating` |
| Exact four-row inventory | Added `policy_chain_eval/extra` to the manifest | `policy attribution receipt error: manifest must contain exactly the four graded rows` |
| Missing measurement | Deleted control `/1` attempt 1 from the TSV | `policy attribution receipt error: missing or extra attempt/row data` |
| Corrupted measurement | Changed one TSV delta while leaving both medians unchanged | `policy attribution receipt error: corrupted estimate delta: ('control', 'policy_chain_eval/1', 1)` |
| Claim/control agreement | Changed `/1` verdict from `inconclusive` to `supported` | `policy attribution receipt error: claim/verdict mismatch for policy_chain_eval/1: expected inconclusive, got supported` |
| Public claim surface | Changed the `docs/RECEIPTS.md` controlled-negative row to claim a measured CPU win, then ran the exact CI verifier command | `policy attribution receipt error: RECEIPTS policy-attribution row drift` |
| Checksummed evidence | Added one line to `commands.txt`, then ran `sha256sum -c SHA256SUMS` from this directory | `commands.txt: FAILED` and `sha256sum: WARNING: 1 computed checksum did NOT match` |

The clean verifier and checksum results after restoration are retained in
`verification.txt`.
