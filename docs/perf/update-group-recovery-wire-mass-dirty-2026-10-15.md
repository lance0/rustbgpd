# Wire-driven recovery under mass dirty (15 October 2026)

> **Document class: FAILED QUALIFICATION RECEIPT — full matrix UNQUALIFIED.** At `72549e20`, all four cells are INVALID and no paired comparison qualifies. The historical `a1854eee` UC no-refusal pass remains separate. Release qualification stays held, including the actual release-candidate soak; EVPN group ownership remains off.

## Recorded `72549e20`: four INVALID cells

[Run 38761990909](https://github.com/lance0/rustbgpd/actions/runs/38761990909), attempt 1 at exact published source **`72549e20deb639cb75cd10cf28b46010dbd8bed8`**, leaves all four cells **INVALID** under independent replay with the frozen consumer. Five legs were attempted out of 24 required. Only the first **UC-pressure flat leg / two operations** is eligible; six native fold records exist, but four belong to incomplete legs. There is **no qualified paired convergence, cost or memory ratio**.

| Cell | Eligible legs / operations | Native folds | Recorded failure |
| --- | --- | ---: | --- |
| full-uc / no-refusal12 | 0 / 0 | 2, ineligible | Post-fold sampler ownership guard; required final exits/footer absent |
| full-uc / cap-pressure24 | 1 flat / 2 | 4; candidate's 2 ineligible | Candidate post-fold sampler ownership guard; final exits/footer absent |
| full-vpn / no-refusal12 | 0 / 0 | 0 | First flat/B native 250 ms readiness deadline; secondary sampler failure |
| full-vpn / cap-pressure24 | 0 / 0 | 0 | Held-source compound guard before saved witness/resume; failing row absent |

The sampler error does not prove actual PID reuse, cgroup movement or an underlying runtime cause: its mismatch operands are not retained. The VPN source guard combines address, Established state, slow-peer and pending checks; the exact failed predicate is **unknown** because the successful-query row and interval were not saved. The VPN native deadline likewise supplies no initiating blocked stack. Nine ordinary snapshot failures match the strict retry ledger; retry does not convert either native or semantic failure into success.

The overall workflow concludes **CANCELLED**, while all four receipt jobs conclude **FAILURE** and each actual invocation/finalizer exits 1. Retained job logs contain no delivered-signal/cancellation annotation. The cancellation initiator, exact event instant and influence on the failures remain unknown; neither causal attribution nor exclusion is justified.

[hosted-725-attempt.json](artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/hosted-725-attempt.json) preserves all **296 raw-file digests**, fifteen source/workspace pins, ten instrument/support inputs and four actual binaries per cell, plus four API-linked ZIPs totaling **200,458,241 bytes**. It retains the sole valid flat boundary and incomplete evidence without turning missing resources, settlement, exits, reaping or reset totals into zeros. The pressure flat leg's withdrawals are cumulative **192 at B / 192 at A**, meaning **192 new B / zero new A**. Raw archives remain necessary for path/ownership/log-slice checks; no complete ordered packet stream was archived.

### V5 local controls and containing-main scope

The separate [V5 local controls](artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/local-correctness-controls-v5.json) at `72549e20` are **CLEAR for correctness only**: six healthy two-receiver legs / twelve exact B/A folds, actual timestamp-only causal rejection and restored UC/VPN success, seven empty snapshot journals and fourteen reaped owned processes. Their 9,018-entry tracked input roster and five binary/build identities are pinned. Local timing, RSS and CPU-cost fields are null. These prerequisites do not qualify the failed hosted matrix.

Main `a04497026215ff6ee79543f2ba84e285bd92bb25` contains the reviewed export-retirement/prior-key reservation repair and sampler fix. Its production-source delta from `72549e20` is the later BGP-LS/ORR API/CLI/protobuf, topology/cache and table/advertised-page invalidation change; the qualification harness/workflow is not all present on main. Ordinary main checks separately record five successful workflows, 105 passed checks and two skips, plus [bounded M122 phase/wire witnesses](https://github.com/lance0/rustbgpd/actions/runs/38763504109/artifacts/11990451776). They do not qualify this manual campaign or establish literal-tree, performance or release-candidate equivalence.

The full matrix and an **actual release-candidate soak remain required**. The separate dataset acknowledgement defect remains outside this receipt. Historical `a1854eee`, `baf70825` and `23fe8425` data are neither pooled nor relabeled to `72549e20`; the scoped historical UC pass below does not close the current decision.

## Recorded `a1854eee`: one valid cell, three INVALID

[Hosted run 38744510988](https://github.com/lance0/rustbgpd/actions/runs/38744510988), attempt 1 at exact published source **`a1854eee2f5b67d4a6198999f7e497e9ff9924fe`**, completed with one successful job and three failed jobs. Independent frozen replay and actual invocation/finalizer/job/cleanup review establish **PASS for full-UC no-refusal only**. The full four-cell campaign remains **UNQUALIFIED**. The two earlier failed campaigns remain separate and unpooled.

| Cell | Receivers | Eligible legs / operations | Observed native folds | Within-cell verdict |
| --- | ---: | --- | ---: | --- |
| full-uc / no-refusal12 | 12 | 6 / 12 | 12 | PASS; complete original bars, resources and cleanup |
| full-uc / cap-pressure24 | 24 | 1 flat / 2 | 4; candidate's 2 are ineligible | INVALID; post-fold sampler cleanup/footer failure |
| full-vpn / no-refusal12 | 12 | 0 / 0 | 0 | INVALID; first flat/B native readiness deadline, then secondary sampler failure |
| full-vpn / cap-pressure24 | 24 | 0 / 0 | 0 | INVALID; first flat/B native readiness deadline |

The actual campaign attempted **10 legs** of the required 24. **Seven legs / fourteen operations** are eligible. Sixteen native fold records exist; two belong to the ineligible UC-pressure candidate leg and cannot raise that coverage to eight legs or sixteen qualified operations. Only the UC no-refusal cell supports a candidate/flat comparison.

### UC no-refusal: scoped comparison

This cell completes three alternating-arm repetitions, six legs and B then A per leg, at **1,000,000 IPv4 plus 230,000 IPv6 keys per receiver × 12 receivers**. Each arm supplies six trigger-to-fleet-fold observations from three legs. The original median **and** worst bar is `candidate ≤ flat × 1.10 + 0.030 seconds`.

| Trigger-to-fleet-fold statistic | Flat (s) | Candidate (s) | Candidate / flat | Candidate limit (s) | Bar |
| --- | ---: | ---: | ---: | ---: | --- |
| Median | 45.504123 | 43.305023 | 0.951673 | 50.084535 | PASS |
| Worst | 46.836414 | 44.428562 | 0.948590 | 51.550056 | PASS |

These durations include ingress, cold capture, witness collection and remote convergence. There are **five whitelisted ordinary snapshot retries: four flat and one candidate**. Ratios describe this finite run and protocol; they do not attribute a CPU or allocator speedup to the storage change or establish a latency distribution.

| Complete-leg resource maximum | Flat | Candidate |
| --- | ---: | ---: |
| Daemon cgroup peak (bytes) | 2,345,836,544 | 1,972,015,104 |
| Harness cgroup peak (bytes) | 40,964,096 | 39,006,208 |
| Held logical proof charge (bytes) | 472,322,272 | 46,127,368 |
| Attempted reservation peak credit (bytes) | 472,322,296 | 46,127,392 |
| Held proof entries | 14,760,000 | 14,760,000 |

Each arm's cgroup peak is the maximum of its three complete legs, with daemon and harness scopes kept separate. Logical held charge and attempted overlapping-reservation credit are ledger quantities, not allocated bytes, per-receiver RSS or attribution of the total daemon peak to one component. Both scopes retain their fixed **10 GiB daemon / 2 GiB harness** caps. Validated before/after boundaries record zero OOM events and zero swap for these six legs; that observation does not cover invalid legs.

All **542 readiness probes return HTTP 200**, with maximum recorded latency **45.264656 ms** and maximum start gap **1.001071167 s**. The twelve operation brackets pass the fixed 250 ms / one-second cadence / 1.25-second gap bar. All twelve exact online native folds retain key/attribute and session-continuity checks, own ordered B/A log-byte windows and post-resume dirty receipts. All four conservative-fallback causes stay zero, including startup, and each operation retires proof entries/current charge to the actual empty baseline. Captured malformed-update/session-reset disposition series and inactive EVPN exhausted-series maxima are scoped raw metrics, **not a general all-family reset total**.

The cell's actual outer invocation and frozen finalizer both exit 0; its job succeeds and cleanup/ownership evidence independently clears. Acceptance does not rely on the early `driver.exit=0` marker alone. The independent scoped-cell receipt binds this verdict to SHA-256 `c13a7735e3690c6d36f1ffb8847b400ede60d8116d9a870981a2f55e47468175`.

### Three invalid cells and remaining qualification

UC-pressure candidate B and A reach exact native folds, final native PASS and successful readiness checks. Its **primary failure follows those folds**: the owned sampler raises `KeyError: VmRSS` during cleanup. The candidate lacks final daemon/harness exit fields, its fixture and a complete final row roster covering cleanup/memory/sampler files. Its provisional folds and observed resource samples do not qualify the leg, cell, or a memory/cost ratio. The flat leg remains independently valid. Pressure withdrawal counters in both observed arms are cumulative **192 at B / 192 at A**, meaning **192 new B / zero new A**, not 384; candidate values remain diagnostic.

Both VPN cells fail in **initial flat leg 0/B**, after baseline, source-writer drain and a saved current-dirty witness, before the first fold, on the native **250 ms readiness checkpoint deadline**. Neither is an ordinary CLI snapshot timeout. VPN no-refusal also suffers a **secondary** sampler `VmRSS` cleanup failure; VPN pressure records no secondary cleanup error. Neither has a completed operation or validated final resource boundary. Successful probe prefixes, held proofs and partial counters cannot become final zeros or cost comparisons. No initiating blocked stack or proven runtime cause is retained.

These `a1854eee` findings prompted later reviewed sampler and retirement repairs, recorded with the separate `72549e20` attempt above. They do not prove the cause of the recorded VPN timeout. Actual release-candidate soak remains pending; the separate dataset acknowledgement defect and EVPN ownership-off boundary remain unchanged.

### Frozen source and evidence

The [mixed-outcome attempt summary](artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/hosted-a185-attempt.json) retains **497 verified raw-file digests**, fifteen source/workspace inputs, ten instrument/support pins per cell, guarded flat derivation and all four actual binary identities per cell. Four API-linked ZIPs total **205,421,237 bytes**. The compact preserves all twelve valid UC observations, per-leg counters/charges/cleanup, seven-leg eligible extrema and failed/incomplete evidence. It cannot replace raw archives for log-slice or process-ownership checks, nor replay an unretained full per-key packet stream.

| Cell | Original artifact | ZIP bytes | ZIP SHA-256 |
| --- | --- | ---: | --- |
| full-uc / no-refusal12 | [11979189206](https://github.com/lance0/rustbgpd/actions/runs/38744510988/artifacts/11979189206) | 55118432 | `74e842ab1c6eb08f266de135c1fbf19db6bfcecd2e16c9ec11c2312b6f309ade` |
| full-uc / cap-pressure24 | [11980053040](https://github.com/lance0/rustbgpd/actions/runs/38744510988/artifacts/11980053040) | 51019830 | `8dded519b3c90c6526947a46f0f420421ad507f0c735f6fe736bafa3ef47b772` |
| full-vpn / no-refusal12 | [11979454043](https://github.com/lance0/rustbgpd/actions/runs/38744510988/artifacts/11979454043) | 49568138 | `31fc23a0bc3d68fc12090c1d0b298f34cb95ea030bd179a5c741ac92e2b23145` |
| full-vpn / cap-pressure24 | [11980232989](https://github.com/lance0/rustbgpd/actions/runs/38744510988/artifacts/11980232989) | 49714837 | `8e865e2e5ed2bf3d87dbe44beeb7cc0dc56541ec2e542c87cf77620637c10fd4` |

The source stays `a1854eee`. The production/contract equality check is against **historical main `594b0ceb30896c7a864b1a0d730df4051ef080d7` only**. It does not establish equality or measurement of later main, including `ed1d70d3a7363058ca73f300feff1af88d920dd8`. Cleanup-only follow-up `987ed07828df2227f6ffd48ef9f4230cd689b2b3` changes the late EXIT handler and tests; no data is relabeled to that head.

The separate immutable [v4 local-control summary](artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/local-correctness-controls-v4.json) remains CLEAR_LOCAL_CORRECTNESS_ONLY: six healthy two-receiver legs / twelve folds around a genuine timestamp-only causal RED, all seven empty journals and all fourteen reaped local processes. Its 9,016-entry **tracked input roster** is not an exhaustive list of compiler-opened/generated inputs. Local timing/RSS/cost fields remain null. The five older compact JSON files stay byte-identical and unpooled.

## Recorded `baf70825` attempt: four INVALID cells

[Run 38728500056](https://github.com/lance0/rustbgpd/actions/runs/38728500056) was dispatched at **2026-10-15T11:36:09Z**, attempt 1, at exact published source **`baf7082560d2b8318cbe99e9fed8c1104b06f1bb`**. All four jobs failed. Independent replay with its frozen consumer reproduced all four original **INVALID** finalizers. API-linked ZIP digests, source/support inputs, actual binaries and all **317 retained file digests** verify; evidence integrity is separate from qualification.

The campaign completed **2 of 24 required legs and 4 of 48 required operations**, all in UC **flat** arms. Both UC candidate arms started but failed before their first B fold; no candidate leg or operation completed. Neither VPN cell completed a leg. There is no eligible whole-campaign median, worst, cost, RSS or cgroup-memory comparison.

| Cell at `baf70825` | Receivers | Completed legs / operations | Initiating failure | Frozen verdict |
| --- | ---: | --- | --- | --- |
| full-uc / no-refusal12 | 12 | 1 flat / 2; candidate 0 / 0 | Candidate leg 1/B: actual HTTP 503; daemon RIB probe timed out at 200 ms | INVALID |
| full-uc / cap-pressure24 | 24 | 1 flat / 2; candidate 0 / 0 | Candidate leg 1/B: native 250 ms readiness checkpoint deadline | INVALID |
| full-vpn / no-refusal12 | 12 | 0 / 0 | Flat leg 0/B: native 250 ms readiness checkpoint deadline | INVALID |
| full-vpn / cap-pressure24 | 24 | 0 / 0 | Flat leg 0/B: native 250 ms readiness checkpoint deadline | INVALID |

Each failed B reached a full baseline, source TCP-write/flush drain, a saved complete held-dirty witness and the receiver-resume command. None reached its B fold. Whole-daemon resync log entries are diagnostics for these failed operations: without completed saved operation/post-resume byte-cursor slices, they do not establish full operation replay or final session continuity. The logs establish readiness failures, not a blocked stack or a proven per-peer-loop cause.

The two completed flat legs independently pass frozen full-leg validation. UC no-refusal retains 83 successful bracketed readiness probes; UC pressure retains 119. Their failed candidate legs retain only 14 and 22 preceding successful probes; each failed VPN leg retains 65. Those partial probes cannot qualify a failed readiness window. The completed pressure flat leg reports cumulative withdrawals **192 at B / 192 at A**, meaning **192 new B / zero new A**, 192 total. Its `daemon_limit` deltas are 11 per operation. The completed no-refusal flat leg has zero withdrawals and fallback deltas. These are scoped flat-leg diagnostics, not a paired campaign result.

All **ten actual ordinary snapshot timeout errors** match the closed retry whitelist and mandatory failure journal. Both completed UC flat legs demonstrate retry recovery; the later native readiness failures remain fatal. VPN no-refusal also records **secondary** cleanup failure `sampler exit: 1` with its fixture retained. That does not replace the initiating 250 ms deadline. Only the two completed flat legs have validated final resource boundaries. Failed-leg exit/reaping, OOM/swap, settled-proof and general reset boundaries are unavailable; partial samples and inactive EVPN/malformed-update counters cannot become zero or clean-teardown claims.

The [sanitized `baf70825` failure summary](artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/invalid-hosted-baf-attempt.json) retains four artifact/job identities, source and binary pins, all 317 file digests, exact completed-flat scope and failure-journal/cleanup distinctions. Its four ZIPs total **199,823,071 bytes**. Complete and partial raw records remain in the original archives; the compact cannot replay raw log slices, process ownership or an unretained packet stream.

| Cell | Original artifact | ZIP bytes | ZIP SHA-256 |
| --- | --- | ---: | --- |
| full-uc / no-refusal12 | [11970691222](https://github.com/lance0/rustbgpd/actions/runs/38728500056/artifacts/11970691222) | 50240999 | `613e4874aefe686f18887bc26626f41fca6e1055892fc8d7aa4262df26f9c28c` |
| full-uc / cap-pressure24 | [11970276892](https://github.com/lance0/rustbgpd/actions/runs/38728500056/artifacts/11970276892) | 50392373 | `4fe5903499389c05a3ac60f53cff159a4e4ade68d903e5a1a2a130d9b95f3915` |
| full-vpn / no-refusal12 | [11970836836](https://github.com/lance0/rustbgpd/actions/runs/38728500056/artifacts/11970836836) | 49447456 | `60624e71a1fd8913aef2fea329c5320a29aacdf68b2d7dbabd89cf630dfd1de6` |
| full-vpn / cap-pressure24 | [11971026595](https://github.com/lance0/rustbgpd/actions/runs/38728500056/artifacts/11971026595) | 49742243 | `fb285b675b9122ffd7952742ac7a8fb74f479adf46a739197541ec64e3458bd0` |

The later `a1854eee` attempt is recorded separately above. The failed `baf70825` result is not reassigned to that source. The actual release-candidate soak remains separate and pending; EVPN ownership remains off.

### Frozen `baf70825` source behavior

The [peer-budget repair](https://github.com/lance0/rustbgpd/pull/3169) selects one dirty peer per distribution replay transaction and checks the existing work budget after that complete replay. Cheap peers may continue within the same poll budget. Dirty peers outside the selected slice retain both their dirty age and any dirty-force flag; unrelated force-only work keeps its prior scheduling. This does not interrupt work inside one peer replay. The existing stalled-operation detector still applies to an individual replay and any enclosing transition. The three changed runtime-fix blobs match the merged fix and qualification head; that is limited source equivalence, not a containing-main measurement.

Ordinary snapshot polling now retries only a `CalledProcessError` with exit 1, empty stdout and stripped stderr exactly `Error: deadline exceeded: RIB snapshot query timed out`. Each leg creates `ordinary-snapshot-failures.jsonl` even when empty. Query failures retain their phase, peer, sequence, attempt, exception class, return code and stdout/stderr; frozen replay requires the file and verifies the closed retry vocabulary and derived counts. Other subprocess/OS/JSON failures stop the leg. Snapshot queries remain bounded by the smaller of 30 seconds and the original remaining leg deadline. HTTP 503, the 250 ms readiness bound and the 1,800-second leg deadline are not relaxed or converted into successful retries.

Receiver identity, group, session state, pending state and current dirty age are checked immediately after each successful row, before querying another peer. A semantic failure therefore cannot disappear when a later peer query times out and the phase restarts. The actual timestamp-only mutation still fails at the eager missing-current-episode predicate.

### Completed v3 local prerequisites

The separate [v3 control summary](artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/local-correctness-controls-v3.json) binds five default/locked builds, distinct daemon hashes, the 9,015-entry tracked input roster, role changes, exact restoration and four independent local-review receipts. The local control runs use the unchanged full 1,000,000 IPv4 / 230,000 IPv6 shape with two receivers, executing on CPUs 32–63 with daemon/native lanes separated. Published local timing/RSS/CPU-cost fields are null.

| Ordered v3 control | Outcome | Driver exit | Completed healthy legs / B+A folds |
| --- | --- | ---: | --- |
| Unicast, flat and candidate | CORRECTNESS_ONLY | 0 | 2 / 4 |
| Timestamp-only B dirty-age mutant | CAUSAL_RED: eager `invalid current dirty episode` | 1 | Not completed; intended rejection |
| Byte-identical restored unicast, flat and candidate | CORRECTNESS_ONLY | 0 | 2 / 4 |
| VPN, flat and candidate | CORRECTNESS_ONLY | 0 | 2 / 4 |

All four local stages have independent CLEAR receipts. The six healthy legs complete 12 exact B/A folds with zero withdrawals and zero operational fallback deltas. All seven attempted legs have the mandatory ordinary-snapshot failure journal; every journal is empty and its derived failure count is zero. This does **not** exercise actual retry under the 12/24-member workload. Both mutant targets remain Established, in their original group and pending with current dirty age absent; the source stays clean. No readiness, wire, session or confirmation-RPC error is counted as the causal RED. All 14 owned processes are reaped.

Logical held-proof counts/bytes in the compact file are correctness diagnostics, not RSS or a measured gain; VPN full-OLD is already flat in both arms. The compact is derived from separately retained raw control archives and cannot itself replay raw bytes, log slices, paths or process ownership. No new isolated-native result is claimed. The historical `23fe8425` control JSON and invalid-hosted-attempt JSON remain byte-identical and separate; the invalid-attempt JSON's pending-next-source field describes its earlier audit, not the current candidate.

## Recorded old attempt: four INVALID cells

The whole-system attempt at exact source `23fe8425b3b3b7783a44b180b37ec3af91974275` **failed**. [Hosted run 38717584948](https://github.com/lance0/rustbgpd/actions/runs/38717584948), dispatched at **2026-10-15T10:04:06Z**, finished with all four cells failed. Independent replay with its frozen consumer reproduced all four original **INVALID** verdicts without mutating raw evidence. Source, instrumentation/support inputs, four binary identities per cell and API-linked archive digests are verified; that evidence integrity does not make the attempt a qualification pass.

In that old hosted attempt, no operation or leg completed and no candidate arm started. There is no qualified median, worst, cost, RSS or cgroup-memory comparison. The earlier same-source local controls remain historical correctness-only evidence at their two-receiver shape, separate from this failed 12/24-receiver attempt. Neither evidence class measures containing main or establishes release-candidate-soak or EVPN-activation acceptance.

All cells used 1,000,000 IPv4 plus 230,000 IPv6 keys. Each stopped in **flat leg 0, operation B**. The original plan was 24 legs / 48 operations; the actual attempt completed **zero legs and zero operations**, with **zero candidate arms started**.

| Cell | Receivers | Last completed phase | Failure | Qualified comparison | Verdict |
| --- | ---: | --- | --- | --- | --- |
| full-uc / no-refusal12 | 12 | Full initial baseline and B writer drain | Ordinary held-dirty neighbor snapshot deadline, before witness | Unavailable | INVALID |
| full-uc / cap-pressure24 | 24 | Full initial baseline and B writer drain | Ordinary held-dirty neighbor snapshot deadline, before witness | Unavailable | INVALID |
| full-vpn / no-refusal12 | 12 | Full baseline, B drain, held witness and receiver resume | Actual readiness HTTP 503; daemon `RIB export-policy transition stalled` | Unavailable | INVALID |
| full-vpn / cap-pressure24 | 24 | Full baseline, B drain, held witness and receiver resume | Actual readiness HTTP 503; daemon `RIB export-policy transition stalled` | Unavailable | INVALID |

The two unicast failures are ordinary operator-query deadlines, distinct from an HTTP readiness-latency failure; their native stderr was empty. Both VPN failures include actual HTTP 503 after the held witness and resume. Neither class produced a completed B fold or settled operation receipts. Partial successful readiness probes do not supply a completed fold bracket. Pre-abort memory samples do not supply final cgroup/cap/OOM/swap boundaries. Withdrawal completion and transient parity are unavailable, rather than zero.

The [sanitized invalid-attempt summary](artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/invalid-hosted-attempt.json) preserves all four job/artifact identities, source and binary hashes, all 236 raw-file digest entries, verified failure phases and independent audit binding. The four retained ZIPs total **197,639,945 bytes**. Raw pre-abort statistics remain in those original archives; they are not qualified cost or memory results and are not copied into comparison tables.

| Cell | Original artifact | ZIP bytes | ZIP SHA-256 |
| --- | --- | ---: | --- |
| full-uc / no-refusal12 | [11964642882](https://github.com/lance0/rustbgpd/actions/runs/38717584948/artifacts/11964642882) | 49198241 | `676ce79c29c6238bbc9f339d4f9305048a1ca010afe6246e9c6f4bcf75ed12bd` |
| full-uc / cap-pressure24 | [11964512672](https://github.com/lance0/rustbgpd/actions/runs/38717584948/artifacts/11964512672) | 49196610 | `285314926f0be6dfccf2155a280f6140cb30199e5d20f5ad1d2548b34a56e576` |
| full-vpn / no-refusal12 | [11965765967](https://github.com/lance0/rustbgpd/actions/runs/38717584948/artifacts/11965765967) | 49500154 | `4374456b9eded00e00caab33f716e8ab3c2dff6b7d3a0571b9252e9a8eb67e30` |
| full-vpn / cap-pressure24 | [11964248843](https://github.com/lance0/rustbgpd/actions/runs/38717584948/artifacts/11964248843) | 49744940 | `72e6166b7be6155f3d8bca0651a26c95fee8701529b9386f4c8c97a0c049935a` |

Artifact availability and expiry are recorded as observed at the audit; hosted links can expire. The raw archives are retained separately. Compact hashes cannot replay the original log-slice, process-ownership or path checks.

## Recorded method and fixed acceptance bars

The method below describes the failed attempt's fixed protocol and unchanged acceptance requirements. It is not a passing result. Any next source must be recorded separately and complete new controls plus all four cells; the earlier method review and successful docs checks do not waive that requirement.

Candidate and explicit-flat arms must use identical locked, default-feature build commands in isolated targets. Record each complete command, arm source and controlled source difference, workspace inputs, instrumentation hash and actual executable SHA-256. The two actual daemon hashes must differ before any cell starts and in the frozen consumer. A build label or requested option does not prove that different recovery paths ran. The measured schedule fixes three repetitions with alternating flat/candidate arm order: six legs per cell, with B then A in every leg. The historical local five-build command and hash records are in the [control summary](artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/local-correctness-controls.json). The old hosted identities are verified separately in the invalid-attempt summary. In the old `23fe8425` attempt, candidate binaries were built and distinct but no candidate arm started. Current v3 local build identities are recorded separately above. The separate `baf70825` hosted identities verify, but all four finalizers are INVALID as recorded above. Old binaries do not establish a later source.

Keep the existing 64 MiB per-peer / 512 MiB daemon admitted-key recovery proof limits. The campaign retains its declared 10 GiB / 2 GiB scope limits, zero-swap setting and 12 GiB available-memory preflight; the frozen manifest must identify each scope, its members and its assigned limit. No budget or fixed deadline is relaxed to obtain a result.

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

Resume every receiver and require its complete exact per-key generation fold. Native `mass_dirty_complete.withdrawals` is **cumulative across B then A within a leg**. The required no-refusal count is zero at both folds. For cap-pressure24, the required raw cumulative count is **192 at B and 192 at A**, or eight per receiver across the whole leg; the labeled per-operation deltas are **192 for B and zero for A**. Report both raw cumulative values and derived deltas without adding the two cumulative counts. These remain required values for every qualifying leg; the completed UC flat pressure leg above supplies only its own scoped observation. Require an actual `dirty=true`, `force=false` resync log receipt in the **post-resume** window for each target, unchanged group/session identities, clean source and targets, and final proof entries/current charge equal to the recorded empty baseline. Do not require proof retirement while the receivers are intentionally held dirty. Preserve the retained completeness, attribute/transition, withdrawal, decode and session-continuity evidence even on failure. Native validation checks exact keys, attributes and permitted per-key transitions online with three bitmaps, then emits compact complete-fold receipts. It does not persist the complete ordered packet stream; independent replay checks retained receipts rather than reconstructing raw packets.

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

## Historical local correctness and causal controls at `23fe8425`

The [derived local-control summary](artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/local-correctness-controls.json) binds source, role-build inputs, actual binaries, control/result hashes and the independent review. The sequence used **1,000,000 IPv4 + 230,000 IPv6 keys and two receivers**, with B then A in each healthy leg. All published cost/clock/RSS fields are null. These are correctness prerequisites, not timing or memory comparisons.

| Ordered control | Actual outcome | Driver exit | Completed healthy legs / B+A folds |
| --- | --- | ---: | --- |
| Unicast, flat and candidate | CORRECTNESS_ONLY | 0 | 2 / 4 |
| B-episode timestamp-only mutant | CAUSAL_RED: `invalid current dirty episode` | 1 | Not completed; expected witness rejection |
| Byte-identical restored unicast, flat and candidate | CORRECTNESS_ONLY | 0 | 2 / 4 |
| VPN, flat and candidate | CORRECTNESS_ONLY | 0 | 2 / 4 |

The six healthy legs completed **12 exact B/A folds**, with zero withdrawals, continuous sessions and zero operational fallback deltas for all four causes. Each paused operation retained 2,460,000 actual proof entries and settled back to the recorded empty baseline. Numeric proof bytes/peaks in the compact file are logical-credit correctness diagnostics, not RSS or a measured memory gain. All 14 owned processes were reaped.

The mutant completed the full clean baseline and B writer drain, then both Established targets remained pending in the same group with their current dirty ages absent; the source remained Established and clean. The real episode validator failed with exit 1, without a readiness, wire or session failure. Restored sources and the tracked input roster matched exactly before the following healthy controls. All five locked/default-feature builds were verified, including genuine RIB compilation for each daemon role; candidate, flat and mutant actual executable hashes are distinct. Those local identities remain separate from future hosted binary identities.

An external naive socket-bind preflight reported `EADDRINUSE`, and its shell continued without `set -e`. Historical socket state was not retained, so **TIME_WAIT is not established**. Preserve this launcher caveat: it is not the causal RED. Subsequent actual daemon-owned startup, full clean baseline, sessions and strict missing-age witness succeeded and were independently checked.

The compact JSON is a sanitized **derived** control summary. Its source-summary, build-summary, review and result hashes bind separately retained raw local archives; the archives themselves are not included. The compact file cannot rerun raw log-slice, path or process-ownership checks. The old hosted attempt supplies no qualified convergence, readiness, memory or cost result. Neither failed hosted attempt establishes whole-system qualification.

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
| Hosted four-cell attempt at `23fe8425`, run 38717584948 | All four INVALID; zero complete operations/legs and no candidate arms. Preserved in the separate invalid-attempt summary above; not a later-source result |
| Dataset acknowledgement failure | Separate unresolved defect; unchanged-dataset wire churn neither resolves nor refutes it |

The prior normal-candidate logs establish readiness exposure, but do not identify the exact blocked stack frame. The final timestamp-only RED and restored normal controls are now recorded separately above; none changes the classification of these earlier failures. The four old hosted ZIP identities and digests are now recorded above. Earlier pre-hosted archives remain separately retained; their identities are not invented or reassigned to this run. Preserve all controls and invalid attempts separately, never as new measured samples.

## Prior measured component facts and modeled limits

The [component receipt](update-group-recovery-slot-capture-scans-2026-10-15.md) measured source `03ee2ad6d905df3c32e1537ccf3d1646de0d856c`, not this intended whole-system source. Indexed unicast warm capture took **0.671–0.752×** its same-source flat control for shuffled OLD; across both input orders it took 0.151–0.752×. VPN-negotiated groups actually selected exact flat at **0.991–1.008×** flat, not a VPN sharing gain. Each leg had one anchor and one full capturing member; all other records were empty. Six dormant EVPN cells missed the component bar and ownership remains disabled. Those observations are not populated-fleet or wire-convergence evidence and are not samples for this campaign.

Shuffled unicast cold pool construction measured **739.603–818.664 ms**, approximately 740–819 ms. The same profile-selected cold policy preceded both warm arms: shared unicast or flat VPN. There is no attributable cold sharing-on/off ratio. The hint is non-owning and last-reference release frees the pool, so later capture can rebuild it. The duration is measured component evidence; recurrence follows from source lifecycle, not an observed whole-system rebuild count. Whole-system pool-rebuild frequency and attributable cold-pool cost remain unmeasured.

Flat-proof capacity is a **key-storage model**, using the component build's 32-byte common key. Exactly 1,230,000 keys require **39,360,000 bytes** of payload (39.36 MB decimal; 37.537 MiB), before charged headers and other state. Replacing capacity `N` by `N+1` reserves the new allocation while the old remains charged: approximately `32 × (2N+1)` bytes of key-only overlap. That approaches the 64 MiB peer cap near **1.05 million keys**, with metadata causing earlier refusal. At 1.23 million, the modeled overlap is 78,720,032 bytes (75.073 MiB), although the final key payload is below the cap. This describes capacity growth; an existing-key reannouncement need not grow or fail.

The 512 MiB daemon cap contains approximately thirteen such settled flat proofs' **key payload**: thirteen total 511,680,000 bytes; fourteen total 551,040,000 bytes, exceeding 536,870,912 bytes. This is a modeled upper bound, not measured fleet capacity. Headers, other proofs/pools, sparse storage and allocation overlap can cause earlier refusal. The limits and conservative no-proof withdrawal contract stay unchanged. Logical provenance credit, allocator bytes, process RSS and cgroup memory are distinct quantities; final measurements must retain their scopes separately.

## Verified old-source checks and remaining qualification

The frozen consumer records `daemon_log_bytes` with `start`, `resume` and `end` byte positions. Its ordered, nonoverlapping operation ranges bind both the complete operation log and post-resume extract to exact slices of the retained full `daemon.log`. A real B-window-as-A substitution control was rejected before restoration. This validates retained log evidence, not raw packet replay.

The consumer also requires `raw_sha256` to list **every actual top-level raw file except `result.json`**, before checking individual digests. A matching partial roster cannot omit the full daemon log or make required consumed files optional. The 30 consumer tests and seeded old-behavior rejection controls cover these evidence checks; they do not substitute for new-source daemon causal controls or final artifact replay.

The runtime repair registers an executor handoff and a dedicated readiness owner around common OLD capture, after its cheap existing-state guard. It preserves an already active nested owner's age and services dedicated readiness at existing capture checkpoints; ordinary queries and mutations stay queued. The controlled cold-capture regression rejected the old behavior and accepted the repair. This is source/regression evidence, not a whole-system timing result or proof of the prior failure's exact blocked frame.

The old-source local daemon causal and restored correctness prerequisites completed at `23fe8425`. They are not controls for the separate `baf70825` source. The [readiness repair](https://github.com/lance0/rustbgpd/pull/3167) is integrated with its three runtime-file blobs identical to the old `23fe8425` qualification head; the qualifier was not rebased or relabeled as a containing-main measurement. All four old hosted cells and their independent frozen replay are **INVALID**. The new `baf70825` source and its local controls are recorded separately above. All four `baf70825` hosted finalizers and their frozen replay are also **INVALID**. Each later artifact must identify its actual executable inputs; local controls, role binaries and fixture suites do not replace them.

## Evidence and remaining qualification

The [evidence directory](artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/README.md) contains the historical local-control summary and sanitized invalid hosted-attempt summary. The latter is bound to independent audit SHA-256 `ec8f1617a2497baf15fb889391d1d401369cde8c36adf542487b0fcba99384e6` and frozen consumer SHA-256 `4fe88c2613523a97e53031b3f855379535e6f57acb794209e0c24b63997cdb2a`. All four original INVALID finalizers were reproduced without raw mutation. The older attempts have no eligible numerical comparisons; null is not a zero observation. The historical v3 local controls remain valid correctness-only history in their own immutable JSON. The separate `baf70825` invalid-attempt summary binds independent failure closure SHA-256 `4c0504d6f97b765eb27fbbdf5be5b299da7521ad4042ea4efbff185c70919a1a` and frozen consumer SHA-256 `4f4fb5707c70386b4b996ba2fb5c2f9bb4f2c720c8ebde275a029fee62b424f9`. Both older failed campaigns remain unpooled. The separate `a1854eee` summary adds only its valid within-cell UC no-refusal comparison; the full matrix stays unqualified.

The final receipt must bind source/build/runtime/instrumentation/configuration hashes, actual executable identities, hosted metadata and archive digests to the retained online-validation receipts, log windows, readiness, phase-cost, sampled memory and ownership evidence. Retain all complete, failed and incomplete legs, collected raw fields and unavailable-value reasons. Independent replay must use the exact frozen consumer and compare its complete outputs with the original artifacts; it does not replay an unretained packet stream.

The earlier failed campaigns, the three INVALID cells at `a1854eee` and all four INVALID cells at `72549e20` leave full-matrix acceptance open. The scoped historical UC cell pass and V5 local controls cannot close it. Even a later passing four-cell campaign would establish only its own exact source, cohorts, stimulus and fixed bars. It would not establish arbitrary churn, dataset-acknowledgement recovery, fleet capacity beyond those cells, or an **actual release-candidate soak**. That soak remains **PENDING**. EVPN group ownership remains **OFF**; neither these unicast/VPN cells nor earlier dormant EVPN component shapes qualify EVPN activation. See [ADR-0099's wire qualification amendment](../adr/0099-update-groups-v2.md#amendment-2026-10-15-wire-driven-mass-dirty-qualification).
