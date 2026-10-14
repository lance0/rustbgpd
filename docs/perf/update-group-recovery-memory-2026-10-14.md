# Update-group recovery memory (14 October 2026)

> **Document class: HISTORICAL.** This receipt covers one hosted VM, two source
> trees, and a synthetic IPv4 recovery workload. It is not a deployment memory
> or timing guarantee.

All eight measured legs passed the recovery and accounting checks. The
candidate's mean scope peak was **4.13×** the baseline for dataset reevaluation
and **3.95×** for full-table peer-down. The candidate therefore has a
substantial measured scope-peak increase at this shape. The **64 MiB per-peer and
512 MiB daemon budgets remain unchanged**; this receipt does not justify
increasing them.

## Workload and source identity

The baseline was `c862af9338aa828b7462f3cf85781f63b0e79fe8`; the measured
candidate was `ee50db161b98def127629eca8a30d9fc23a0320a`. Each received the
same frozen candidate harness source. Only the two `TestQueryOutboundHealth`
observer configuration gates were opened for measurement; each tree retained
its original manifests, dependency pins and lockfile. Builds used the `scale`
profile, locked dependencies, and four build jobs. The baseline predates the admitted-key parity fixes; this compares complete
revisions with intervening changes, not the unbounded intermediate implementation
or one isolated allocation owner. Exact binary, build-input
and frozen-instrumentation hashes are in
[`provenance.json`](artifacts/update-group-recovery-memory-2026-10-14/provenance.json).

The real `RibManager` and production exact-export preflight served **256
receivers × 100,000 IPv4 prefixes**, or **25,600,000 receiver-route entries**.
The receiver queues had capacity eight. Consumers paused and filled the queues
before the operation, establishing 256 simultaneously dirty group members.
Each cell ran baseline, candidate, candidate, baseline in fresh scopes.

The dataset cell directly invoked dataset-driven reevaluation while preserving
the export policy. The peer-down cell removed the full-table source. Four
barriers per leg recorded population-ready, retained, operation-end and settled
state: **32 phase samples across eight distinct process/scope identities**.
The measured scope included the manager, export preflight, harness consumers,
and scoped launcher/checker. It did not run a daemon or TCP transport session,
or exercise the complete dataset-publication/SIGHUP path.

## Memory result

The primary measure was the kernel cgroup v2 `memory.peak`, including the whole
owned scope. Each fresh scope had `MemorySwapMax=0`; every phase and end snapshot
recorded zero swap and zero OOM events. Phase peaks were monotonic, and the
final scope peak covered the before snapshot and all four phases.

Values below are MiB, rounded to three decimals from exact bytes in
[`comparison.json`](artifacts/update-group-recovery-memory-2026-10-14/comparison.json).

| Cell | Leg | Source | Scope peak (MiB) |
| --- | ---: | --- | ---: |
| Dataset reevaluation | 1 | Baseline | 191.641 |
| Dataset reevaluation | 2 | Candidate | 806.859 |
| Dataset reevaluation | 3 | Candidate | 803.391 |
| Dataset reevaluation | 4 | Baseline | 198.477 |
| Full-table peer-down | 1 | Baseline | 213.191 |
| Full-table peer-down | 2 | Candidate | 847.477 |
| Full-table peer-down | 3 | Candidate | 861.656 |
| Full-table peer-down | 4 | Baseline | 219.055 |

The exact candidate-to-baseline mean-peak ratios were 4.12760588765395 and
3.9540734716009216. Each arm has two repetitions per cell; the individual peaks
above retain their observed spread. These are whole-scope readings, not an
attribution of the difference to one allocation owner.

Every candidate retained **12,700,000 admitted recovery keys**, charged
**532,699,192 bytes (508.022 MiB)** at the retained and operation-end barriers.
Peak reservation was **535,844,944 bytes (511.022 MiB)**, leaving
**1,025,968 bytes (0.978 MiB)** below the 536,870,912-byte daemon budget.
These credits bound admitted-key storage and overlapping reservations, not the
whole process or scope peak.
Each candidate recorded **129 `daemon_limit` fallback episodes**, with zero
`peer_limit`, `allocation_failure` or `missing_proof` episodes. This shape
reached the daemon limit; it did not reach the per-peer limit. The per-peer
boundary is covered by correctness tests rather than this measurement.

## Recovery and accounting

- Dataset reevaluation kept all 25,600,000 receiver-route entries and produced
  zero withdrawals, including zero unchanged-policy withdrawal/reannouncement
  flaps.
- Full-table peer-down delivered exactly 25,600,000 withdrawals and settled
  every receiver to an empty inventory.
- Candidate population-ready and settled states both had zero retained
  recovery entries and **56 charged bytes**, the healthy empty-ledger header.
  Ordinary residue also returned to zero. The peak reservation gauge remained
  a historical high-water mark.
- The candidate EVPN provenance-exhaustion counter stayed at zero; EVPN was
  inactive in these plain-unicast cells.

The settled phase sampled the live workload. Final scope snapshots were taken
after the Rust workload exited and must not be interpreted as live retained
RIB memory. The original validation bound the executed binary digest and its
compiled source/instrumentation identity, checked owned Bash/Python/Rust
membership before, during and after execution, and rejected populated
descendant cgroups. Membership checks were sampled, not an atomic ownership
guarantee against an unrelated privileged actor.

## Environment and attempts

The [passing hosted job](https://github.com/lance0/rustbgpd/actions/runs/38495536388/job/115630552079)
ran on a fresh GitHub-hosted Ubuntu 24.04 VM using Rust and Cargo 1.99.0.
Before either build, the host inventory reported 16,766,414,848 total memory
bytes and 15,534,874,624 available bytes. That inventory is not a
contemporaneous workload-headroom reading. Swap was available on the host but
disabled for each measured scope. Host OOM counters were zero before and
after the campaign. The driver and all leg launchers/workloads exited zero;
offline validation of the full downloaded campaign also passed.

The [first attempted run](https://github.com/lance0/rustbgpd/actions/runs/38494992846)
failed before building or measuring because a toolchain input was missing.
The correction changed CI configuration only. That attempt supplied no
measurement rows; none of the eight completed measured legs was excluded.

This receipt makes no timing, full-daemon, TCP, EVPN, component-memory or
deployment-capacity claim. It establishes bounded admitted-key accounting and
complete recovery for this workload while disclosing the roughly fourfold
scope-peak increase.

## Evidence and reproduction

The [compact public evidence](artifacts/update-group-recovery-memory-2026-10-14/README.md)
retains all phase values, before/end scope snapshots, source and binary hashes,
and a sanitized ownership summary. Scope paths are aliased and hashed; these
extracts cannot replay the full original ownership checks. The original hosted
artifact expires on 2026-11-13; a checksum-verified private archive preserves
the original campaign separately.

On a fresh hosted runner, the job invokes the
[existing driver](../../bench/scale/compare-recovery-memory.sh) from the clean
measured source:

```bash
bash bench/scale/compare-recovery-memory.sh \
  --head ee50db161b98def127629eca8a30d9fc23a0320a \
  --output-dir "$RUNNER_TEMP/update-group-recovery-memory/campaign"
```

The driver refuses dev-box or soak-host measurements. Public numeric ratios
can be recomputed from the compact evidence without running a workload.
