# Policy attribution allocation: isolated Criterion receipt

This receipt isolates the change from owned `String` policy attribution to an
`Arc<str>` clone per attributed evaluation. It compares
`9a7b64615fd0a81572fc75e938dd2084890fecbe` with
`e49d1c87d64cd1e9ca5e8c9d4f2be021be8ecf14`, alongside a fresh same-SHA
control at the latter commit.

Both runs used `bench/compare-criterion.sh` unchanged: six alternating
attempts, CPU 8 pinned with `taskset`, the `performance` governor,
`rustbgpd-policy`'s `policy_eval` bench, and filter `policy_chain_eval`.

| Row | Same-SHA mean, sd, range | Isolated mean, sd, range | Classification |
|---|---|---|---|
| `policy_chain_eval/1` | -3.95%, 12.80%, -23.65%..+13.14% | -6.24%, 10.21%, -26.84%..-0.36% | inconclusive; no claim |
| `policy_chain_eval/8` | -2.84%, 5.46%, -11.97%..+3.26% | -1.84%, 4.63%, -10.62%..+3.24% | inconclusive; no claim |
| `policy_chain_eval/32` | +0.78%, 6.10%, -7.58%..+9.68% | -0.23%, 7.17%, -7.73%..+9.46% | inconclusive; no claim |
| `policy_chain_eval/early_deny` | -0.40%, 7.72%, -13.49%..+10.09% | -14.82%, 6.34%, -25.94%..-7.73% | inconclusive; no claim |

The `/1` and `early_deny` isolated ranges are wholly negative and match the
source mechanism: attributed terminal policy names now clone an existing
`Arc<str>` instead of allocating an owned label. They still overlap their
same-SHA control ranges, so the observation does not license a CPU claim.
`/8` and `/32` also overlap their controls. All four rows are inconclusive.

This controlled run therefore does not substantiate attribution of a measured
CPU gain at these four shapes. It makes no claim about convergence, reload
latency, throughput, or end-to-end daemon performance.

The [retained package](artifacts/policy-attribution-criterion-2026-07/README.md)
contains sanitized metadata, all per-attempt median estimates, exact commands,
checksums, and a fail-closed verifier.
