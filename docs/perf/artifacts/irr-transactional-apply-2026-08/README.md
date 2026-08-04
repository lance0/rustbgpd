# IRR transactional apply 2026-08 — compact evidence extract

Compact extract from the two green sealed artifact roots behind
[`../../irr-transactional-apply-2026-08.md`](../../irr-transactional-apply-2026-08.md).
The full roots (multi-MB daemon logs, RSS streams, scenario rosters, seals)
are retained off-repo; this directory carries the verifier output, the
per-root provenance, the complete transaction-lifecycle evidence, and the
identity digests needed to recognize the sealed originals.

| File | Source (inside each root) | Contents |
|---|---|---|
| `verification.json` | four-way verifier `--output-dir` | `verify-receipt.py transactions` verdict: `status: "pass"`, 8 rows, commit + dataset binding |
| `transactions.csv` | verifier `--output-dir` | all 8 measured reload rows (4 per root), repeat-tagged, exactly as re-derived by the verifier |
| `provenance-root-A.json` / `provenance-root-B.json` | `provenance.json` | schema-3 provenance: commit, dirty state, tool/script/binary digests, environment, full input knobs, fingerprint |
| `lifecycle-A.json` / `lifecycle-B.json` | `rustbgpd-txn/transactions/lifecycle.json` | schema-2 abort / timeout-auto-revert / restored-plan-NOOP evidence with v3 authority object digests and sizes |
| `cycles-A.jsonl` / `cycles-B.jsonl` | `rustbgpd-txn/transactions/cycles.jsonl` | per-measured-cycle streamed Plan/Apply, pending v3 state, and confirmed-terminal evidence |
| `quiet-A.tsv` / `quiet-B.tsv` | `rustbgpd-txn/quiet.tsv` | the accepted pre-cell quiet-host sample pair (load, swap counters, ports, disk) |
| `SHA256SUMS` | this directory | digests of every extract file above |

Sealed-root identity (recognize the originals by these digests):

| Root | `SHA256SUMS` seal digest | `COMPLETED` digest |
|---|---|---|
| `irrreload-txn-20260804T131946Z-A` | `a80cef82c920366e7505e612986230a3103cdc5314f536c46291c60c3abce471` | `24480887ab585c595770b8094a216e41c5d9a4562cfc3b4ad228cf7376a65463` |
| `irrreload-txn-20260804T135502Z-B` | `c2d248f06fbcc3438ac57ee514c27d3d0aef638dd65e46cf7d30469c6ec8f5c6` | `5390a92773aac38589fd5d218ae620979e06bf6e552d24236c9d13d08a9511e2` |

Every extract is byte-identical to the file inside its sealed root (each is
covered there by the root's `SHA256SUMS`), so any copy of a sealed root
re-derives this directory exactly. Verify this directory with
`sha256sum -c SHA256SUMS`.
