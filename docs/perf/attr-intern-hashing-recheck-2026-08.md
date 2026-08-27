# Attribute-intern hashing noise-floor recheck (August 2026)

## Result

**Not evaluated.** This same-source recheck does not authorize a fingerprint
cache or another production optimization.

The rich/shared-`Arc` decision rows were stable: their four-median ranges were
0.76% to 1.30%, below the predeclared 3% isolated and 5% end-to-end limits.
The complete 35-row matrix did not pass, however. Six controls exceeded their
unchanged limits, including four isolated hash-only rows. The largest was the
10k typical/shared hash-only row at 32.72% range and 16.15% CV. Because the
protocol requires every input row to pass before attribution is evaluated,
the derived ratios are marked `NOT_EVALUATED`. No row was removed and the
campaign was not rerun for a better number.

This is a measurement-limit finding, not a performance or regression claim.
It changes no production or benchmark code.

## Frozen decision rule

The recheck retained the August receipt's rules without rounding exceptions:

1. isolated rows must have at most 3% range across the four medians;
2. end-to-end rows must have at most 5% range;
3. every across-attempt CV must be at most 5%; and
4. only after all controls pass may the existing attribution rule be applied.

The existing attribution rule remains: rich/shared hash-only time must be at
least 20% of isolated intern time, its conservative ceiling must be at least
5% of insert, bulk-load, and scaled churn time, and each signal must exceed
twice its control noise. This campaign does not evaluate those requirements.

## Environment and identity

- source: `fba9ad12079158c15fd4855bf5452f31c0d6db42`;
- AMD Ryzen Threadripper 7970X, CPU 15 (physical core 15, socket 0), pinned with
  `taskset -c 15`;
- Linux 6.17.0-35-generic, x86_64;
- `amd-pstate-epp`, `performance` governor throughout the campaign;
- rustc 1.98.0 (`88d9e12ae178fab0fb5cc050a94da85685d449ea`), Cargo 1.98.0
  (`797e8a9bc`), Criterion 0.8.2;
- `Cargo.lock` SHA-256
  `98b6d83ed8b5dc4c048118c30345485c60349a3c96a2bbbcfb459cef853ca740`;
- `crates/rib/benches/rib_ops.rs` SHA-256
  `14dc9042e8db8f54d2cb8c596e696fb7f4723e127bbd18feac56d3a6009bdd38`;
  and
- sealed `rib_ops` binary SHA-256
  `437c8e7f7fe2ff075764f90132ac25f22882abbb761d452cc049182e8c8358b4`.

No competing Cargo, rustc, Criterion, or network measurement process was
present at the start. `/tmp/rustbgpd-perf.lock` was held continuously across
all four arms. The 2,038 CPU-frequency samples ranged from 4.145 to 5.167 GHz
(mean 5.049 GHz); frequency sampling changed no Criterion argument.

## Command and order

Each arm used the exact retained command shape:

```text
taskset -c 15 cargo bench -p rustbgpd-rib --bench rib_ops -- attr_ \
  --save-baseline <baseline> --warm-up-time 1 --measurement-time 2 \
  --sample-size 10 --noplot --quiet
```

The same binary ran in counterbalanced A/B/B/A order:

| Order | Baseline | Start (America/New_York) | End |
|---:|---|---|---|
| 1 | `lan800_a1` | 15:57:12 | 15:59:21 |
| 2 | `lan800_b1` | 15:59:21 | 16:01:31 |
| 3 | `lan800_b2` | 16:01:31 | 16:03:40 |
| 4 | `lan800_a2` | 16:03:40 | 16:05:49 |

`A` and `B` are identical same-SHA controls, not different implementations.

## Gate results

All five rich/shared decision rows passed their individual stability gates:

| Row | Mean of medians | Range | CV | Limit |
|---|---:|---:|---:|---:|
| Hash only | 0.952 ms | 0.88% | 0.42% | 3% |
| Intern | 0.976 ms | 1.30% | 0.64% | 3% |
| Adj-RIB-In insert | 1.354 ms | 0.89% | 0.41% | 5% |
| Bulk initial load | 2.392 ms | 0.76% | 0.36% | 5% |
| Route churn | 0.372 ms | 0.80% | 0.34% | 5% |

The complete-matrix gate failed on these six rows:

| Row | Count | Range | CV | Limit |
|---|---:|---:|---:|---:|
| Hash only, many unique | 10k | 21.13% | 10.46% | 3% |
| Hash only, typical/independently equal | 10k | 20.92% | 10.41% | 3% |
| Hash only, typical/independently equal | 100k | 4.77% | 2.15% | 3% |
| Hash only, typical/shared | 10k | 32.72% | 16.15% | 3% |
| Adj-RIB-In insert, typical/independently equal | 100k | 6.64% | 3.62% | 5% |
| Route churn, typical/independently equal | 100k | 15.87% | 7.28% | 5% |

The first four entries fail the isolated range gate; the last two fail the
end-to-end range gate, and the last route-churn row also fails the CV gate.

## Artifacts and next step

[`artifacts/attr-intern-hashing-recheck-2026-08.csv`](artifacts/attr-intern-hashing-recheck-2026-08.csv)
retains 140 attempt rows, 35 summaries, the withheld derived rows, and the
single `NOT_EVALUATED` decision. The external campaign artifact retains every
Criterion estimate tree, four command logs, timestamps, and the frequency
trace.

The unchanged short-window full-matrix protocol still cannot support an
attribution verdict. A future re-adjudication requires a separately approved
measurement-method change that can stabilize all isolated controls; this
receipt does not choose that method and does not authorize a production
prototype.
