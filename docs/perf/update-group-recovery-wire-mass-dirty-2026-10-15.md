# Wire-driven recovery under mass dirty (15 October 2026)

> **Document class: LOCAL RECEIPT DRAFT. Hosted results and qualification verdict: PENDING.** Local correctness and causal-control prerequisites are complete; hosted observations are awaited.

This draft defines a matched whole-system comparison of recovery under wire-driven churn. The remotely verified qualification source is `23fe8425b3b3b7783a44b180b37ec3af91974275`, including the common-capture readiness repair and consumer evidence checks described below. [Hosted run 38717584948](https://github.com/lance0/rustbgpd/actions/runs/38717584948) was dispatched at **2026-10-15T10:04:06Z**, with its API-reported head verified as that source. All four cell results, hosted build/artifact identities and frozen-consumer replay remain **PENDING**. Local controls at the same source are recorded separately below. This document makes no whole-system, release-candidate-soak or EVPN-activation claim and does not measure containing main.

## Qualification status

Every hosted result below must come from the frozen campaign and its independently replayed retained evidence. `PENDING` is unavailable evidence, never zero or a successful outcome.

| Cell | Routes | Receivers | Run / frozen artifacts | Dirty-overlap and exact-fold result | Readiness / convergence bar | Retained / peak memory and proof credit | Fallback observations | Verdict |
| --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| full-uc / no-refusal12 | 1,000,000 IPv4 + 230,000 IPv6 | 12 | [38717584948](https://github.com/lance0/rustbgpd/actions/runs/38717584948); artifacts PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| full-uc / cap-pressure24 | 1,000,000 IPv4 + 230,000 IPv6 | 24 | [38717584948](https://github.com/lance0/rustbgpd/actions/runs/38717584948); artifacts PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| full-vpn / no-refusal12 | 1,000,000 IPv4 + 230,000 IPv6 | 12 | [38717584948](https://github.com/lance0/rustbgpd/actions/runs/38717584948); artifacts PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| full-vpn / cap-pressure24 | 1,000,000 IPv4 + 230,000 IPv6 | 24 | [38717584948](https://github.com/lance0/rustbgpd/actions/runs/38717584948); artifacts PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |

Candidate and explicit-flat arms must use identical locked, default-feature build commands in isolated targets. Record each complete command, arm source and controlled source difference, workspace inputs, instrumentation hash and actual executable SHA-256. The two actual daemon hashes must differ before any cell starts and in the frozen consumer. A build label or requested option does not prove that different recovery paths ran. The measured schedule fixes three repetitions with alternating flat/candidate arm order: six legs per cell, with B then A in every leg. The verified local five-build command and hash records are in the [control summary](artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/local-correctness-controls.json). Hosted arm command transcripts, executable hashes and artifact identities remain **PENDING**; local binary hashes are not substituted for hosted ones.

Keep the existing 64 MiB per-peer / 512 MiB daemon provenance limits. The campaign retains its declared 10 GiB / 2 GiB scope limits, zero-swap setting and 12 GiB available-memory preflight; the frozen manifest must identify each scope, its members and its assigned limit. No budget or fixed deadline is relaxed to obtain a result.

## Static configuration and wire stimulus

Policy, configuration and the preloaded `generation_b` dataset stay byte-identical throughout a cell. There is no SIGHUP or dataset mutation. The stimulus changes route attributes on the wire, so this method cannot establish correctness of dataset-reevaluation acknowledgement.

Each full generation has 80 NLRI per chunk: 12,500 IPv4 chunks and 2,875 IPv6 chunks, for **15,375 distinct origin values**. For global chunk index `c`, generation A uses four-byte origin AS `4200100000 + 2*c`; B uses A plus one. These values exclude local AS 64512. The static dataset contains all 15,375 B origins. The receiver derives the exact AS_SEQUENCE origin from family, key, chunk and generation, including only the explicitly permitted previous-value replay.

The initial A feed ends each family with EoR. Every subsequent B or A chunk is followed by a matching-family EoR: **15,375 EoRs per operation, 30,750 per B/A leg, plus two initial EoRs**. With GR/LLGR inactive, this is the source-pinned non-route boundary for the preceding distribution window; it adds neither source export refresh nor a per-chunk API round trip. EoR receipt alone does not prove that the receiver has its full expected route inventory.

Every receiver requests `SO_RCVBUF=4096` before connect. Record and require Linux's actual 8192-byte receive buffer. The source retains its existing socket behavior. Configuration, exact key/path-ID inventories and session identities must be bound to the raw transcript.

## Operation and actual common-dirty witness

Each leg performs B, then A. Before either operation, require exact initial route truth, all target sessions Established and clean in the same unchanged target group, and a clean continuous source session. Record the actual empty-proof baseline and counters. For each operation, retain the source identity/state check before its metrics baseline; the source must be clean and continuous. Pause every receiver, acknowledge all pauses, then arm the target bitmaps.

Record the controller's `CLOCK_MONOTONIC` trigger **before** sending the generation command. The native instrument streams through its existing bounded source channel. Its FIFO drain marker acknowledges only after TCP `write_all` and flush of the final EoR, and records exact generation/key/chunk/EoR/origin cardinalities. This is a **source-writer drain acknowledgement**, not an actor or RIB acknowledgement.

While all receivers remain paused, collect **two stable complete detail sweeps**. Every exact target must report `pending=true`, unchanged group/session identity, and the source must remain clean and continuous. For each current dirty episode, retain the raw query start/end and reported age. Its conservative interval is:

```text
[query_end - floor(dirty_seconds), query_begin]
```

Require a nonempty intersection across **all targets in each sweep**, and a nonempty stable intersection across **all rows from both sweeps together**. The ordered query windows must lie after source-writer drain and before receiver resume. This establishes an actual common dirty instant from bounded intervals; sequential API queries are not treated as an atomic snapshot. Preserve both per-sweep intersections, the cross-sweep stable intersection, every contributing bound and the sampled daemon-wide proof charge. A source drain or an isolated pending observation cannot substitute for this witness.

Resume every receiver and require its complete exact per-key generation fold. Native `mass_dirty_complete.withdrawals` is **cumulative across B then A within a leg**. The required no-refusal count is zero at both folds. For cap-pressure24, the required raw cumulative count is **192 at B and 192 at A**, or eight per receiver across the whole leg; the labeled per-operation deltas are **192 for B and zero for A**. Report both raw cumulative values and derived deltas without adding the two cumulative counts. These are required values, not hosted observations in this draft. Require an actual `dirty=true`, `force=false` resync log receipt in the **post-resume** window for each target, unchanged group/session identities, clean source and targets, and final proof entries/current charge equal to the recorded empty baseline. Do not require proof retirement while the receivers are intentionally held dirty. Preserve the retained completeness, attribute/transition, withdrawal, decode and session-continuity evidence even on failure. Native validation checks exact keys, attributes and permitted per-key transitions online with three bitmaps, then emits compact complete-fold receipts. It does not persist the complete ordered packet stream; independent replay checks retained receipts rather than reconstructing raw packets.

The primary endpoint is the controller's observation of the exact final fleet fold. Report all three phase durations and their sum:

```text
trigger → source-writer drain → receiver resume → observed exact fleet fold
```

Thus trigger-to-fold includes ingress filling, first cold capture and witness collection. Queue admission, local proof settlement and source-writer drain are separate events; none is the remote-delivery endpoint.

## Counter windows and collected resources

Retain all four conservative-fallback causes: `peer_limit`, `daemon_limit`, `allocation_failure` and `missing_proof`. Each must be monotone across all six edges of:

```text
initial → before B → paused B → settled B → before A → paused A → settled A
```

An operation's delta is its settled value minus **its own before value**. Startup remains separate. No-refusal cells forbid every fallback, including startup. In cap-pressure cells, explicit-flat arms and the already-flat VPN candidate must exercise `daemon_limit` during operations; the indexed unicast candidate must have zero operation fallback deltas. These are requirements, not observed counter values.

Retain daemon-wide proof `entries`, `bytes` and `peak_bytes` at their actual sampled boundaries. No-refusal held entries must equal `receivers × 1,230,000`; final entries and current bytes must return to the actual empty baseline. Peak credit includes attempted/rolled-back allocation overlap. It is not a separately observed attempted-credit gauge.

The instrument collects sampled process RSS/HWM and CPU seconds, plus cgroup current/peak/stat/swap/OOM observations. Independent per-peer credit, a separate attempted gauge, reset/strategy counts, allocator bytes and per-operation CPU attribution are **unavailable**. CPU clock-tick granularity is used but not retained by this instrument. Report those limits explicitly, rather than inventing zeros or deriving uncollected fields. Logical proof credit, process measurements and cgroup scope measurements remain separate.

## Fixed bars and causal controls

Readiness runs at a one-second cadence with a contiguous sequence and actual monotonic successful start/end timestamps. Each successful probe requires HTTP 200 and latency **at most 250 ms**. Each B and A trigger-to-fold interval requires a preceding and following successful bracketing probe, with **at most 1.25 s between consecutive probe starts including those brackets**. Retain raw probes, actual count and maximum start gap; omit no failed or late probe. This absolute availability bar applies to **both measured cohorts**, including pressure. Correctness-only mode still enforces actual watcher status/deadline failures while publishing null observer clocks.

For **measured no-refusal cells only**, both median and worst observed convergence must satisfy:

```text
candidate ≤ explicit-flat × 1.10 + 30 ms
```

Report the actual same-cell no-refusal arm samples, medians, worst values and comparison outcome. Cap-pressure cells assess correctness and resource behavior with the **same absolute readiness bar** and fixed **1,800-second whole-leg deadline**; the relative convergence comparison is not their acceptance bar and no equivalent storage-performance claim follows. Do not infer distributions from a finite sample or pool earlier attempts. The protocol EOF tail wait stays 10 ms; other existing deadlines remain fixed and must be recorded in the frozen manifest.

The final compiled causal mutation is **timestamp-only**: within fresh dirty insertion for the B episode, it removes `dirty_since` while preserving dirty-set insertion, proof capture and resync machinery. From a healthy full baseline and actual current-pending B witness, the validator must reject the missing current dirty age. A readiness failure, setup failure or unrelated process error is invalid causal evidence. The actual timestamp-only RED and byte-identical restored controls completed as described below. Earlier broad-bookkeeping HTTP 503 failures remain invalid. No capture-bypass result is asserted.

## Completed local correctness and causal controls

The [derived local-control summary](artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/local-correctness-controls.json) binds source, role-build inputs, actual binaries, control/result hashes and the independent review. The sequence used **1,000,000 IPv4 + 230,000 IPv6 keys and two receivers**, with B then A in each healthy leg. All published cost/clock/RSS fields are null. These are correctness prerequisites, not timing or memory comparisons.

| Ordered control | Actual outcome | Driver exit | Completed healthy legs / B+A folds |
| --- | --- | ---: | --- |
| Unicast, flat and candidate | CORRECTNESS_ONLY | 0 | 2 / 4 |
| B-episode timestamp-only mutant | CAUSAL_RED: `invalid current dirty episode` | 1 | Not completed; expected witness rejection |
| Byte-identical restored unicast, flat and candidate | CORRECTNESS_ONLY | 0 | 2 / 4 |
| VPN, flat and candidate | CORRECTNESS_ONLY | 0 | 2 / 4 |

The six healthy legs completed **12 exact B/A folds**, with zero withdrawals, continuous sessions and zero operational fallback deltas for all four causes. Each paused operation retained 2,460,000 actual proof entries and settled back to the recorded empty baseline. Numeric proof bytes/peaks in the compact file are logical-credit correctness diagnostics, not RSS or a measured memory gain. All 14 owned processes were reaped.

The mutant completed the full clean baseline and B writer drain, then both Established targets remained pending in the same group with their current dirty ages absent; the source remained Established and clean. The real episode validator failed with exit 1, without a readiness, wire or session failure. Restored sources and all full build inputs matched exactly before the following healthy controls. All five locked/default-feature builds were verified, including genuine RIB compilation for each daemon role; candidate, flat and mutant actual executable hashes are distinct. Those local identities remain separate from future hosted binary identities.

An external naive socket-bind preflight reported `EADDRINUSE`, and its shell continued without `set -e`. Historical socket state was not retained, so **TIME_WAIT is not established**. Preserve this launcher caveat: it is not the causal RED. Subsequent actual daemon-owned startup, full clean baseline, sessions and strict missing-age witness succeeded and were independently checked.

The compact JSON is a sanitized **derived** control summary. Its source-summary, build-summary, review and result hashes bind separately retained raw local archives; the archives themselves are not included. The compact file cannot rerun raw log-slice, path or process-ownership checks. Hosted convergence, readiness latency, memory and cost results remain **PENDING**.

## Correctness-only escalation and invalid attempts

The earlier two-receiver trial with 8,000 IPv4 and 2,000 IPv6 keys, one NLRI per chunk and 10,000 origins/EoRs per operation did not establish pending dirty peers. It remains **INVALID saturation evidence**; it is neither a causal control nor a qualified result.

The declared escalation uses the same full 1,000,000 / 230,000-key, 80-key-chunk stimulus as the hosted matrix, with **two receivers**. All cost, RSS and published observer phase clocks stay null; publish null interval clock bounds and only a boolean overlap proof. Actual watcher status/deadline enforcement remains active. Only the correctness witness can be assessed. Native unit fixtures remain explicitly small. This changes neither the hosted 12/24-member cohorts nor their bars, deadlines or causal requirements. This full-shape two-receiver correctness-only path completed for both unicast and VPN in the local controls above; it does not establish the hosted cohort results.

Earlier attempted whole-system A/B qualifications remain **INVALID** and outside final comparisons. Preserve each original identity and failure envelope without pooling it into later data. The following history has different evidence classes:

| Prior evidence | Classification and limit |
| --- | --- |
| Small two-receiver 8k/2k trial | INVALID saturation evidence; no actual common-dirty witness |
| Full-shape unicast candidate and flat, using earlier runtime `d04d562e87b8467489d88fc9b6f7eba1fd1db8d5` and consumer `2a4ef7ddf5eb0640a483c0b1220466250a3bf035` | Retained valid **CORRECTNESS_ONLY** B/A controls, with null published measurement clocks; neither the new-source control nor a four-cell cost/readiness qualification |
| Prior compiled dirty-bookkeeping mutant | INVALID causal attempt: HTTP 503, rather than the required dirty-witness failure |
| Prior restored normal candidate | INVALID qualification attempt: HTTP 503 after B writer drain, with a 200 ms RIB readiness timeout |
| Dataset acknowledgement failure | Separate unresolved defect; unchanged-dataset wire churn neither resolves nor refutes it |

The prior normal-candidate logs establish readiness exposure, but do not identify the exact blocked stack frame. The final timestamp-only RED and restored normal controls are now recorded separately above; none changes the classification of these earlier failures. Historical raw archive hashes and full attempt metadata are **PENDING** in this local draft; preserve the retained controls and invalid attempts separately, never as new measured samples.

## Prior measured component facts and modeled limits

The [component receipt](update-group-recovery-slot-capture-scans-2026-10-15.md) measured source `03ee2ad6d905df3c32e1537ccf3d1646de0d856c`, not this intended whole-system source. Indexed unicast warm capture took **0.671–0.752×** its same-source flat control for shuffled OLD; across both input orders it took 0.151–0.752×. VPN-negotiated groups actually selected exact flat at **0.991–1.008×** flat, not a VPN sharing gain. Each leg had one anchor and one full capturing member; all other records were empty. Six dormant EVPN cells missed the component bar and ownership remains disabled. Those observations are not populated-fleet or wire-convergence evidence and are not samples for this campaign.

Shuffled unicast cold pool construction measured **739.603–818.664 ms**, approximately 740–819 ms. The same profile-selected cold policy preceded both warm arms: shared unicast or flat VPN. There is no attributable cold sharing-on/off ratio. The hint is non-owning and last-reference release frees the pool, so later capture can rebuild it. The duration is measured component evidence; recurrence follows from source lifecycle, not an observed whole-system rebuild count. Whole-system frequency and cost remain **PENDING**.

Flat-proof capacity is a **key-storage model**, using the component build's 32-byte common key. Exactly 1,230,000 keys require **39,360,000 bytes** of payload (39.36 MB decimal; 37.537 MiB), before charged headers and other state. Replacing capacity `N` by `N+1` reserves the new allocation while the old remains charged: approximately `32 × (2N+1)` bytes of key-only overlap. That approaches the 64 MiB peer cap near **1.05 million keys**, with metadata causing earlier refusal. At 1.23 million, the modeled overlap is 78,720,032 bytes (75.073 MiB), although the final key payload is below the cap. This describes capacity growth; an existing-key reannouncement need not grow or fail.

The 512 MiB daemon cap contains approximately thirteen such settled flat proofs' **key payload**: thirteen total 511,680,000 bytes; fourteen total 551,040,000 bytes, exceeding 536,870,912 bytes. This is a modeled upper bound, not measured fleet capacity. Headers, other proofs/pools, sparse storage and allocation overlap can cause earlier refusal. The limits and conservative no-proof withdrawal contract stay unchanged. Logical provenance credit, allocator bytes, process RSS and cgroup memory are distinct quantities; final measurements must retain their scopes separately.

## Frozen source checks and new-source control requirement

The frozen consumer records `daemon_log_bytes` with `start`, `resume` and `end` byte positions. Its ordered, nonoverlapping operation ranges bind both the complete operation log and post-resume extract to exact slices of the retained full `daemon.log`. A real B-window-as-A substitution control was rejected before restoration. This validates retained log evidence, not raw packet replay.

The consumer also requires `raw_sha256` to list **every actual top-level raw file except `result.json`**, before checking individual digests. A matching partial roster cannot omit the full daemon log or make required consumed files optional. The 30 consumer tests and seeded old-behavior rejection controls cover these evidence checks; they do not substitute for new-source daemon causal controls or final artifact replay.

The runtime repair registers an executor handoff and a dedicated readiness owner around common OLD capture, after its cheap existing-state guard. It preserves an already active nested owner's age and services dedicated readiness at existing capture checkpoints; ordinary queries and mutations stay queued. The controlled cold-capture regression rejected the old behavior and accepted the repair. This is source/regression evidence, not a whole-system timing result or proof of the prior failure's exact blocked frame.

The actual same-source local daemon causal and restored correctness prerequisites are complete. The [readiness repair](https://github.com/lance0/rustbgpd/pull/3167) is integrated with its three runtime-file blobs identical to the frozen qualification head; the qualifier was not rebased or relabeled as a containing-main measurement. All four hosted cells and their independent artifact replay remain **PENDING**. Each hosted artifact must identify its actual executable inputs; local role binaries and fixture suites do not replace them.

## Evidence and remaining qualification

The [evidence directory](artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/README.md) contains the completed local-control summary and requirements for hosted evidence. Hosted raw archives, compact receipts/rows, comparisons, provenance and independent-replay verdict are **PENDING**. No empty artifact or null field should be interpreted as a zero failure count.

The final receipt must bind source/build/runtime/instrumentation/configuration hashes, actual executable identities, hosted metadata and archive digests to the retained online-validation receipts, log windows, readiness, phase-cost, sampled memory and ownership evidence. Retain all complete, failed and incomplete legs, collected raw fields and unavailable-value reasons. Independent replay must use the exact frozen consumer and compare its complete outputs with the original artifacts; it does not replay an unretained packet stream.

Even a passing four-cell campaign would establish only its exact source, cohorts, stimulus and fixed bars. It would not establish arbitrary churn, dataset-acknowledgement recovery, fleet capacity beyond those cells, or an **actual release-candidate soak**. That soak remains **PENDING**. EVPN group ownership remains **OFF**; neither these unicast/VPN cells nor earlier dormant EVPN component shapes qualify EVPN activation. See [ADR-0099's wire qualification amendment](../adr/0099-update-groups-v2.md#amendment-2026-10-15-wire-driven-mass-dirty-qualification).
