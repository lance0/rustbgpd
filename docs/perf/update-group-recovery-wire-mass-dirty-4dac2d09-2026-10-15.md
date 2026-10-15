# Wire-driven mass-dirty recovery at `4dac2d09` — 2026-10-15

> **Document class: HISTORICAL RECEIPT.** Two unicast cells pass; both VPN cells
> are INVALID. The full qualification remains **UNQUALIFIED**.

The exact-source hosted campaign completes both unicast comparisons at the full
1.23-million-key shape. The no-refusal cell meets the original convergence bar.
The pressure control passes correctness and resource requirements, but candidate
convergence is **1.430931 times flat by median**, a measured cost that the pressure
cell's acceptance rules do not constrain. Both VPN cells stop on their first
flat-control readiness deadline. VPN qualification and an actual identified
release-candidate soak remain required; release qualification remains held and
EVPN ownership stays disabled.

Measured source: [`4dac2d09f661501ef476196c7b68d5ec3df2e1be`](https://github.com/lance0/rustbgpd/commit/4dac2d09f661501ef476196c7b68d5ec3df2e1be).
[Run 38792877066](https://github.com/lance0/rustbgpd/actions/runs/38792877066), attempt 1,
started **2026-10-15T19:18:56Z** and finished **19:55:04Z**, with workflow FAILURE:
two receipt jobs SUCCESS and two FAILURE. Frozen replay independently reproduces
the two PASS and two INVALID verdicts. All four archives, 29-file build seals,
ten instrumentation/support inputs, four actual products per cell and **686
raw-file hashes** verify. Evidence integrity does not qualify the failed cells.

## Results and retained decision

Each receiver starts with 1,000,000 IPv4 and 230,000 IPv6 routes. Each cell requires
six fresh daemon legs, three per arm, in flat/candidate/candidate/flat/flat/candidate
order. Every leg applies B then A. The actual aggregate is **14 attempted legs,
12 eligible complete legs, 24 completed operations and 24 exact native folds**,
against 24 legs / 48 operations required for the four-cell campaign.

| Cell | Receivers | Eligible legs / operations | Candidate / flat median | Candidate / flat maximum | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| Unicast, no-refusal | 12 | 6 / 12 | 0.950252 | 0.938036 | PASS, original relative bar |
| Unicast, cap-pressure | 24 | 6 / 12 | **1.430931** | **1.406350** | PASS, correctness/resources only; descriptive cost |
| VPN, no-refusal | 12 | 0 / 0 | Unavailable | Unavailable | INVALID, initial flat/B readiness deadline |
| VPN, cap-pressure | 24 | 0 / 0 | Unavailable | Unavailable | INVALID, initial flat/B readiness deadline |

The retained choice is indexed shared proofs for pure unicast and exact flat
full-OLD proofs whenever VPN is negotiated. The
[component receipt](update-group-recovery-slot-capture-scans-2026-10-15.md)
and the passing unicast no-refusal comparison support that bounded choice.
There is **no passing VPN whole-system result**, general deployment acceptance,
or full-matrix cost claim. The pressure comparison uses different recovery
coverage after flat cap refusal; it is not an equivalent-storage speed comparison.

### Convergence and memory

The primary clock is source churn command send to observation of the exact final
fleet fold. It includes ingress fill, cold proof capture and the held-dirty
witness, rather than timing only the post-resume drain.

| Cell / statistic | Flat (s) | Candidate (s) | Candidate / flat | Relative limit (s) |
| --- | ---: | ---: | ---: | ---: |
| No-refusal median | 43.160010 | 41.012901 | 0.950252 | 47.506011 |
| No-refusal maximum | 44.685757 | 41.916867 | 0.938036 | 49.184333 |
| Pressure median | 41.546098 | 59.449590 | **1.430931** | Not applied |
| Pressure maximum | 43.398191 | 61.033036 | **1.406350** | Not applied |

Both no-refusal statistics satisfy `candidate ≤ flat × 1.10 + 0.030 seconds`.
The same relative bar does not apply to pressure. These are finite observations
from three complete legs / six operations per arm, not latency distributions or
attributed capture CPU costs.

| Complete unicast resource boundary, maximum per arm | No-refusal flat | No-refusal candidate | Pressure flat | Pressure candidate |
| --- | ---: | ---: | ---: | ---: |
| Daemon cgroup peak (bytes) | 2,333,253,632 | 1,919,614,976 | 2,397,327,360 | 1,970,249,728 |
| Native harness cgroup peak (bytes) | 38,944,768 | 39,055,360 | 46,800,896 | 48,881,664 |
| Held logical proof charge (bytes) | 472,322,272 | 46,127,368 | 511,684,448 | 47,974,568 |
| Attempted proof reservation high-water (bytes) | 472,322,296 | 46,127,392 | 511,686,784 | 47,974,592 |
| Held proof entries | 14,760,000 | 14,760,000 | 15,990,000 | 29,520,000 |
| Ordinary snapshot retries | 4 | 3 | 6 | 6 |

Logical proof credit is neither RSS nor attribution of total cgroup memory.
Pressure flat's lower proof cardinality reflects bounded fallback, not a smaller
wire table. All 24 completed operations settle to **zero proof entries / 96
charged bytes**. Both complete UC cells verify their 10 GiB daemon / 2 GiB native
scope limits, zero-swap settings, no OOM events and successful exits/cleanup.
All four candidate fallback causes stay zero, including startup. No-refusal flat
also stays zero. Pressure flat counts **66 `daemon_limit` fallbacks** across six
operations; its other three causes stay zero. Native pressure withdrawal readings
are cumulative **192 at B / 192 at A per leg**: **192 new B, zero new A**, not 384.
No-refusal records zero withdrawals.

The no-refusal cell retains 516 successful HTTP 200 probes, maximum 25.122 ms
and maximum start gap 1.000998334 s. Pressure retains 618, maximum 25.248 ms
and gap 1.001026281 s. Full operation brackets and native session continuity
pass. All nineteen ordinary snapshot failures in the two UC cells match the
closed retry journal and recover under the original deadlines; retry work is
included in the convergence clock. Only captured malformed-update/session-reset
disposition and inactive EVPN exhaustion series are zero; those series are not a
general all-family reset counter.

### VPN failures and unavailable scope

Both VPN jobs stop in **flat leg 0/B before the first fold**. The no-refusal
native attempt 99 and pressure attempt 135 connect and write the HTTP request,
then receive **zero response bytes** in `response_read_to_eof` before the unchanged
250 ms deadline. The observed abort intervals are 251.517 ms and 251.481 ms;
eventual server response latency is unknown. The retained outer readiness warning
does not identify a RIB, peer-manager or runtime scheduling cause. No initiating
blocked stack or daemon cause is established.

Neither VPN candidate arm starts. There is no complete VPN operation, session
continuity receipt, final resource/cap/OOM/swap boundary, cost ratio or memory
comparison. Successful probe prefixes and partial raw samples remain diagnostic;
missing boundaries are **unavailable**, not zero or a clean-teardown claim.
Execution, driver, actual outer invocation and finalizer all return 1; both jobs
fail and the original archives are retained. Full VPN qualification is still open.

## Fixed method and source boundaries

The [frozen method](https://github.com/lance0/rustbgpd/blob/4dac2d09f661501ef476196c7b68d5ec3df2e1be/bench/scale/reloadstall/README.md)
uses real daemon TCP sessions and native receivers. Targets pause reads, source
attribute churn fills their queues, and two current-episode dirty-age interval
intersections establish a common held interval across every receiver. After
resume, saved per-member dirty resync receipts and exact native folds establish
recovery. Source route counts are checked before operation metrics. Four fallback
counters must remain monotonic across all six before/held/settled edges.

All cells enforce HTTP 200 within 250 ms, contiguous one-second sampling with
at most a 1.25-second gap, complete fold brackets and a fixed 1,800-second leg
deadline. Pressure keeps these absolute availability, correctness and resource
bars; only the relative convergence comparison is no-refusal-only. Common
admitted-key recovery proof limits remain **64 MiB per peer / 512 MiB per daemon**.
The separate dormant EVPN ledger is not qualified by this campaign.

Candidate and flat daemons are genuinely built in separate checkouts and targets
with the same `cargo build --release --locked --bin rustbgpd` default-feature
command. The sole flat derivation changes optional full-OLD sharing from
`!group.stages_vpn()` to `false`; VPN already selects exact flat in both arms.
The native harness uses profile `scale`. Every actual candidate and flat
executable hash differs, and all closed build evidence is archived before legs.
The manual workflow runs all **50** frozen controller tests in each cell.
Rust/Cargo are 1.99.1; daemon CPUs are 0–1 and native CPUs 2–3 on four distinct
fresh hosted runners.

Production tracked modes, types and Git blobs match historical main
`f95dd04df0eca75b1ccaefae060e68c557771d56` outside exactly ten qualification
harness/workflow paths: **9,023 common entries**. The qualification tree and main
tree are not identical. Main's separate five ordinary workflows pass, with
105 successful checks and two expected skips; this does not turn ordinary CI
into the manual native campaign or an actual release-candidate soak.

Local prerequisites honestly remain at
`123847d75037be153ac567a17767e7df1418f6c1`: healthy UC → timestamp-only causal RED
→ byte-identical restored UC → healthy VPN, exits **0 / 1 / 0 / 0**. They complete
six healthy two-receiver legs / twelve folds, verify four 29-file seals and
all fourteen owned processes reaped. Their tracked input roster has 9,033 entries;
it is not an exhaustive list of compiler-opened/generated inputs. A reviewed
three-file terminal-only follow-up leads to `4dac2d09`; it changes neither
Rust/native behavior nor operational bars. Local timing/RSS/cost remain null,
and none of those local controls is relabeled as a `4dac2d09` measurement.

## Artifacts, history and limits

The [artifact directory](artifacts/update-group-recovery-wire-mass-dirty-4dac2d09-2026-10-15/README.md) contains compact
[per-leg/operation comparisons](artifacts/update-group-recovery-wire-mass-dirty-4dac2d09-2026-10-15/comparison.json) and
[provenance plus all 686 raw hashes](artifacts/update-group-recovery-wire-mass-dirty-4dac2d09-2026-10-15/provenance.json).
Original API-linked archives total **210,219,428 bytes**.

| Cell | Original artifact | ZIP bytes | ZIP SHA-256 |
| --- | --- | ---: | --- |
| full-uc-no-refusal | [12003031488](https://github.com/lance0/rustbgpd/actions/runs/38792877066/artifacts/12003031488) | 55224082 | `a5afcc0263e9a97c19ad4c77ed5c9b9ff9c53a4c417be21131644e0736ee799d` |
| full-uc-cap-pressure | [12001444534](https://github.com/lance0/rustbgpd/actions/runs/38792877066/artifacts/12001444534) | 55365130 | `467fcf4fe8fcb145848db962ed407ef15800597712e6c1a3d7813e105b7cf2e1` |
| full-vpn-no-refusal | [12002880547](https://github.com/lance0/rustbgpd/actions/runs/38792877066/artifacts/12002880547) | 49653513 | `5588942f600b39e2837dcee68a614cdf832cc35c04391e1093a75538b088afcc` |
| full-vpn-cap-pressure | [12001124914](https://github.com/lance0/rustbgpd/actions/runs/38792877066/artifacts/12001124914) | 49976703 | `4cb4145b7203e809d131eaae2214a299267c3c045a958c2bec0bda625ac30e43` |

The native receiver validates complete inventory, attributes, transitions and
sessions online. Archived compact folds, dirty receipts and exact operation log
slices are replayed with the frozen consumer; a full ordered packet stream is
**not** archived or independently replayed. Compact hashes do not replace the raw
archives for process-ownership, exact log-byte and path checks. Hosted artifacts
can expire. Per-operation CPU and per-peer allocator attribution are unavailable.

The [earlier failed-qualification receipt](update-group-recovery-wire-mass-dirty-2026-10-15.md),
its four attempts and the historical single-cell pass remain unchanged, separate
and unpooled. This new UC evidence neither supplies missing VPN results nor
qualifies the separate dataset-acknowledgement path, actual release-candidate
soak, EVPN ownership or latest main beyond the explicitly compared source.
