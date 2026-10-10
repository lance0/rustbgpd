# Shared encoding slice fairness — 2026-10-10

Yielding after two complete 2,048-route shared-encoding slices shortens the
measured daemon reload completion and neighbor RPC, with a visible median
full observer-delivery cost of **66.9 ms (3.4%)**. Earlier first output and
shorter operator completion coexist with that cost. The actor timer remains
near 55–56 ms, and individual completion ranges overlap. This receipt supports
a scoped fairness change on the measured workload, with the delivery tradeoff
noted for the release.

This follows the [policy reload attribution receipt](policy-transition-release-followup-2026-10-10.md),
which identified a longer post-transition continuation with concurrent reads.
That historical receipt and its original measurements are unchanged.

## Final two-slice comparison

The final measured source is
`8df8f397c7a77e0b1e3cecf8e4e628915d4f64e6`, tree
`a00331032f5abca54e88ffbbed8b4f17e20b8976`. It yields after **two complete
2,048-route slice publications** while keeping each publication, notification,
follower budget and cancellation guard at its existing boundary. Whole-table
source grouping remains upfront. The comparison baseline is still
`436de7a9f18580620a0da6c42b20e3385a4c4658`, measured again in this window.

The canonical-lock window was **16:13:19–16:42:25 EDT** on 2026-10-10.
All four native cells pass, each with eight complete in-band pairs and eight
committed 1,000-member transitions. All 16 runtime exits, four leg exits,
build/outer exits and end-of-window integrity checks are zero. Quiet gates
pass, with no missing audit or read deadline miss. This is two process
launches and 16 correlated reloads per arm at the same default shape. The
following process medians [ranges] are the primary comparison.

| Process | Actor, ms | Cohort, ms | Prestage/session apply, ms | Daemon SIGHUP → complete, ms | Neighbor RPC, ms |
|---|---:|---:|---:|---:|---:|
| Baseline r1 | 56.000 [53.000–59.000] | 166.930 [54.558–276.109] | 552.062 [503.809–741.147] | 793.680 [681.695–1065.133] | 277.060 [25.318–313.266] |
| Two-slice r1 | 56.000 [54.000–57.000] | 98.578 [57.929–151.619] | 541.715 [512.791–620.741] | 718.374 [669.876–795.549] | 118.362 [92.239–199.188] |
| Two-slice r2 | 56.000 [55.000–58.000] | 117.817 [56.950–162.981] | 539.144 [485.147–564.771] | 717.065 [613.106–813.369] | 140.308 [111.576–172.683] |
| Baseline r2 | 55.000 [54.000–56.000] | 158.967 [54.654–282.072] | 571.669 [483.796–666.959] | 810.666 [643.524–943.758] | 283.567 [244.210–305.680] |

Pooled all-reload daemon completion is 810.666→717.065 ms, cohort
166.930→105.859 ms and neighbor RPC 282.195→133.567 ms. Both candidate
process medians improve on both baseline process medians for these clocks.
Actor 55→56 ms has overlapping ranges and no demonstrated improvement.
Prestage is 559.130→540.850 ms. Complete-reload ranges overlap:
643.524–1065.133 ms baseline and 613.106–813.369 ms candidate. No reload is
excluded, and faster process medians do not mean every reload is faster.

### Visible observer delivery cost

These observer clocks are separate from the daemon completion clock.

| Process | Completion p50, s [range] | Completion p95, s [range] | Completion max, s [range] | First-generation UPDATE p50, ms [range] |
|---|---:|---:|---:|---:|
| Baseline r1 | 1.961106 [1.936133–2.184296] | 2.930358 [2.859986–3.205965] | 3.031992 [2.948287–3.285090] | 1815.995 [1740.392–1873.225] |
| Two-slice r1 | 2.007817 [1.943743–2.096079] | 2.896510 [2.845440–3.025102] | 2.985727 [2.938081–3.139773] | 1050.524 [710.248–1315.465] |
| Two-slice r2 | 2.023904 [1.898407–2.110527] | 2.898627 [2.832110–2.988712] | 2.978483 [2.925027–3.058990] | 1108.133 [679.154–1261.437] |
| Baseline r2 | 1.934234 [1.829270–2.241814] | 2.932564 [2.840860–3.144210] | 3.022445 [2.936722–3.206498] | 1808.967 [1723.137–1895.626] |

Primary pooled completion p50 is **1.955879→2.0227825 s**, an observed
**+66.9035 ms (+3.4206%)** cost. Both candidate process medians exceed both
baseline process medians. Individual reload ranges overlap. Completion p95
is 2.930358→2.8986275 s and max 3.0305485→2.978483 s; both tail-quantile
process medians improve in this window, with overlapping individual ranges.
First-generation UPDATE p50 is 1811.356→1060.753 ms with disjoint all-reload
ranges, 1723.137–1895.626 and 679.154–1315.465 ms. Earlier first output and
shorter operator completion coexist with a slower median full inventory.

The baseline's cohort distribution changed between the two valid windows,
despite the same baseline binary. The initial 6.2% wire-p50 cost and final
3.4% cost belong to their own windows. Their difference is not an isolated
estimate of the tuning effect, and the earlier baseline is not substituted
for the final window's baseline.

### Descriptive first-two split and contrary rows

This split retains the first **two reloads per process** versus the remaining
six, giving four versus 12 correlated reloads per arm. It is descriptive;
all 16 remain primary. First-two pooled daemon completion is
947.141→748.256 ms; remaining completion is 756.310→717.065 ms.
For remaining reloads, r1 daemon medians are 719.759→718.374 ms, nearly flat,
while r2 is 800.773→717.065 ms. The remaining pooled cohort **median reverses
70.0305→107.580 ms**, because the baseline has many short-cohort cases;
its mean is 149.439→106.102 ms. Neither that reversal nor the nearly flat
r1 completion subset is hidden by the all-reload comparison.

First-two pooled observer completion p50 is 2.093784→2.048171 s;
remaining completion p50 is 1.940954→1.9915105 s, **+50.5565 ms (+2.6047%)**.
The all-reload median wire cost survives the remaining subset, while the
first-two direction differs. The full distributions are retained in the
[final summary](artifacts/shared-encoding-slice-fairness-2026-10-10/final-summary.json).

Seven baseline rows have cohort clocks within 5 ms of the actor timer;
neighbor reads on those rows still take 159.652–313.266 ms. Total neighbor
RPC time does not identify the admitted first-stage peer-manager handler.
Baseline policy-stats outliers of 276.323 and 281.257 ms, candidate outliers
of 58.215, 58.077 and 62.040 ms, and all their audit/offset evidence remain
in the bundle. Policy-stats medians stay near 11.9 ms, and every call meets
the native deadline. RIB-log-to-phase spans over 100 ms fall from eight to
one across the 16 correlated reloads per arm; those counts are descriptive,
not independent trial counts.

### Additive final-window accounting

Per-row phase components sum to the daemon span. The table uses all-reload
means in ms; medians are not added.

| Component | Baseline mean | Two-slice mean | Change |
|---|---:|---:|---:|
| Before generation phase | 61.129 | 59.234 | -1.895 |
| Preflight | 0.121 | 0.129 | +0.008 |
| Cohort selection | 11.417 | 12.297 | +0.880 |
| Prestage/session apply | 576.293 | 546.185 | -30.108 |
| Actor timer within cohort | 55.562 | 56.062 | +0.500 |
| Cohort elapsed outside actor timer | 108.950 | 48.845 | -60.105 |
| Remainder apply | 0.001 | 0.001 | -0.000 |
| Refresh dispatch | 0.006 | 0.007 | +0.000 |
| Convergence check | 0.117 | 0.134 | +0.016 |
| Unattributed phase time | 1.305 | 1.371 | +0.066 |
| After generation phase | 3.635 | 4.104 | +0.469 |
| Daemon SIGHUP → complete | 818.538 | 728.370 | -90.168 |

The mean daemon reduction is 90.168 ms: about 60.105 ms less cohort elapsed
outside the actor timer and 30.108 ms less prestage elapsed, with the remaining
components recorded above. This locates the wall-time difference without
proving CPU cost, the exact encoding/scheduler split, reply publication or
readiness-cleanup duration. Rounded rows can differ slightly from the rounded
total.

### Final identities and scoped decision

Final daemon SHA-256 is
`ed7eefa9c6b3e985f7f0c8632db4ac15f960851d8ca946fcf1c14c5d985bf10e`.
Actual build/ABBA driver SHA-256 is
`7123e4921bce880066dc9f5d92125188d7d2f794d843f79077ecf906187c16f8`.
The baseline daemon, common immutable CLI and cell/harness are the identities
listed below. Both final arm builds use the same daemon+CLI package command,
input-refresh selection and toolchain as the initial matched campaign.
The [final actual-unit audit](artifacts/shared-encoding-slice-fairness-2026-10-10/final-feature-audit.json)
independently matches 227 artifact units per arm: 226 library fingerprints
plus the daemon binary. The normal/build resolution
graph was captured for the baseline and initial source; the two-slice source
changes no Cargo manifest or lockfile input. No new resolution graph was run
for it. The historical missing API build-script fingerprint still limits
reconstruction of the old complete build-script closure.

This supports a **scoped go for the bounded fairness change**, with the
observed median full-delivery cost noted for the release. It supports faster
operator completion and earlier first output at this cell, without a general
wire-delivery improvement, an actor CPU gain or a maximum-latency guarantee.
The remaining-reload cohort-median reversal and completion overlap constrain
that conclusion. No further tuning or a broader architecture change is
implied by this receipt. The separate quiet-host main-versus-release S2/IRR
comparison remains prepared and unrun.

## Initial one-slice comparison and common controls

The baseline is `436de7a9f18580620a0da6c42b20e3385a4c4658`; the measured
initial candidate is its direct child
`f4df7aaf18edb1987aebbd6a12038772ada2f948`. The producer becomes asynchronous
and yields after publishing a complete 2,048-route slice and releasing its
stream mutex. Publication and follower cursors retain their existing slice
boundaries. The producer owns its cancellation guard across each suspension:
dropping it publishes `Failed`, notifies followers, and permits ordinary
encoding fallback. Read/FIFO command checkpoints remain on their existing
path. Whole-inventory source grouping still runs before the first slice,
so this change does not bound every unit of work or prove a maximum request
latency at other shapes.

The native policy-stats cell uses 1,000 changed peers and 400,000 IPv4 prefixes,
all-community A/B changes, 15 s control and 40 s quiescence. Daemon/engine/probe
CPU sets are 2–3, 4–5 and 8–15. One concurrent neighbor/policy-stats pair is
aimed 110 ms before the next commit predicted from the previous reload;
one quiescent policy-stats read follows completion by 20 s. Pairs fire after cohort session hot-apply completes, with offset
`max(0, previous hot-apply → RIB commit − 110 ms)`. The first pair, or one
whose previous transition is shorter than 110 ms, fires immediately after
hot-apply, not after SIGHUP. Pair coverage uses actual starts.

The initial ABBA window was **15:27:39–15:56:46 EDT** on 2026-10-10. It has two
process launches per arm and eight correlated reloads per process. All four
native cells pass with eight complete in-band pairs each and eight committed
1,000-member transitions. Every process/leg exit, the outer ABBA and the
end-of-window instrument/binary integrity checks are zero. Quiet gates pass
before every leg. No retained call misses its 2 s deadline, no audit is
incomplete, and no daemon error invalidates a cell.

The unchanged native bars include at least six complete pair starts in
−220..0 ms from the RIB log, reply/audit shape checks, successful daemon
settlement and exact observer inventory. In-band policy-stats stage sums
remain flat under `in_band_max <= 2 × quiescent_median + 50 ms`. In the initial
comparison, the observed stage sum is zero in both arms; external RPC durations
below remain separate from that millisecond-resolution audit clock.

### Matched build inputs and the discarded comparison

Both measured daemons use the same locked release package command:
`cargo build --release --locked -j 4 -p rustbgpd -p rustbgpctl` with Rust
1.99.0. Their tracked Rust, protobuf and Cargo input timestamps were refreshed
under the host and shared-target build locks, without content changes. The
781-path input lists have identical hashes. Daemons were copied and hashed;
both arms use the same immutable baseline CLI and shared cell/harness.
The cell's source identity describes the instrument, not the daemon.

| Identity | Baseline | Initial candidate |
|---|---|---|
| Source tree | `43ce7f0b4ba9fa83054802e7d570524ecffa28d3` | `13a215adf6185add5cbad634f777557e97232c81` |
| Daemon SHA-256 | `777c4224139477f8b8267281478ee97e7b9760f9e982f99f51df700d8104c71e` | `6351db7220d90f01ef8b185b5d2e644fc5bde4f19ffd56dbe5b9ed571ac4ff40` |
| Shared CLI SHA-256 | `8fc6ac7c24009ba6455ddc492a0e6ebf83198686ce481b517456651155001338` | Same bytes |

The instrument source is `591ac39d4b50fc2c647942713a9ea99c0588a51a`;
shared `reloadstall` SHA-256 is
`2701b6b81deca419dbcb55692cc74a9e976b73bcc628507dfa6c284116880b30`.
The actual build/ABBA driver SHA-256 is
`fcac5543c652a16e8f3d1490a3f388dfa7b81753a9bd750dfe1eac4f5d07181e`.

[The feature audit](artifacts/shared-encoding-slice-fairness-2026-10-10/feature-audit.json)
binds each immutable daemon to its retained release artifact and follows its
dependency fingerprint signatures. All 227 artifact units per arm—226
library fingerprints plus the daemon binary—match in activated features,
configuration and dependency identities.
Normal/build resolution graphs, excluding dev edges, are identical at
17,893 lines and SHA-256
`b6420a7fa2214159d187cb6e133d012a56324e092ae9c1f7f330d08f9f20173b`.
This does not claim identical compiled artifact signatures: source changes
and regenerated build outputs can change those signatures. The old retained
baseline lacks one API build-script fingerprint, so a complete historical
build-script closure cannot be reconstructed. The actual library closure
and the resolved normal/build graph support their separately stated scopes.

An earlier attempt built the baseline daemon+CLI but the candidate daemon
alone. Six dependency units had different features, including `either`, two
`hashbrown` versions, `mio`, `nix` and `time`. It is
**INVALID / ABORTED_BUILD_CONFOUND**, and all its timing observations are
excluded from isolated fix claims. Three native cells had passed when the
comparison was stopped before the closing baseline started. The actual
process exit was 143; an EXIT trap wrote zero from the previous command.
That raw trap record is preserved alongside the abort manifest, and no
window-finish exists. A native PASS or that zero cannot establish a complete
valid comparison. The [invalid history](artifacts/shared-encoding-slice-fairness-2026-10-10/invalid-build-confound.json)
records the discrepancy and original-file hashes.

## Initial one-slice daemon and RPC results

Process rows are the primary replication view. Each cell is a median
[minimum–maximum] in ms. Pooled reloads are correlated; they do not provide
16 independent repetitions or establish statistical significance.

| Process | Actor | Cohort | Prestage/session apply | Daemon SIGHUP → complete | Neighbor RPC |
|---|---:|---:|---:|---:|---:|
| Baseline r1 | 55 [54–57] | 259.666 [57.582–292.324] | 573.890 [520.150–645.639] | 913.142 [671.888–990.657] | 275.821 [181.647–302.355] |
| Initial r1 | 56 [52–57] | 107.035 [53.112–159.355] | 609.579 [541.467–694.828] | 800.916 [706.023–868.226] | 128.639 [87.396–183.438] |
| Initial r2 | 55 [53–57] | 115.093 [57.156–131.409] | 581.765 [535.580–724.207] | 785.338 [676.523–910.258] | 127.869 [88.379–150.743] |
| Baseline r2 | 55.5 [52–57] | 267.730 [55.024–281.625] | 592.774 [493.540–684.206] | 896.207 [695.143–1039.855] | 280.912 [268.094–299.592] |

Pooled actor medians are 55→55.5 ms; cohort 263.924→113.870 ms;
daemon completion 908.383→798.754 ms; prestage 573.890→596.324 ms;
neighbor RPC 279.094→128.639 ms. The actor has no demonstrated gain, and
prestage process medians move in mixed directions. Completion ranges overlap;
this is a process-median improvement, not a claim that every reload is faster.

The first-two versus remaining split is descriptive and does not exclude
warmup or change acceptance. All 32 reloads remain in the primary summaries.
For the remaining six reloads per process, pooled cohort medians are
267.730→118.927 ms and daemon completion 869.919→798.754 ms. The shorter
continuation survives that split. All/first-two/remaining distributions
for every process and arm are in the
[recomputed summary](artifacts/shared-encoding-slice-fairness-2026-10-10/initial-summary.json).

Contrary rows remain visible. Four baseline reloads have cohort clocks near
the actor timer while neighbor reads still take 181.647–299.592 ms. Thus total
neighbor duration alone does not identify the first-stage admitted peer-manager
fanout or its overlap. The initial candidate also retains policy-stats RPC
outliers of 58.683 ms (r1 reload 2) and 21.209 ms (r2 reload 8); its median
stays around 11.8 ms, as in the baseline. No read misses the native deadline.

### Where daemon completion changes

The disjoint per-row phase components sum to the complete daemon span.
Means can be added; phase medians cannot. The following means use all 16
correlated reloads per arm and retain every contrary row.

| Component, ms | Baseline mean | Initial mean | Change |
|---|---:|---:|---:|
| Before generation phase | 60.051 | 63.371 | +3.320 |
| Preflight | 0.122 | 0.139 | +0.017 |
| Cohort selection | 14.036 | 10.297 | −3.739 |
| Prestage/session apply | 582.028 | 605.836 | +23.808 |
| Actor timer within cohort | 55.312 | 55.375 | +0.063 |
| Cohort elapsed outside actor timer | 161.412 | 51.415 | −109.998 |
| Remainder apply | 0.001 | 0.001 | 0.000 |
| Refresh dispatch | 0.010 | 0.007 | −0.003 |
| Convergence check | 0.136 | 0.129 | −0.008 |
| Unattributed phase time | 1.339 | 1.407 | +0.068 |
| After generation phase | 3.933 | 4.185 | +0.252 |
| **Daemon SIGHUP → complete** | **878.381** | **792.163** | **−86.219** |

Rounded rows can differ slightly from the rounded total. The shorter cohort
continuation accounts for most of the completion reduction; increased
prestage elapsed time offsets part of it. These wall clocks do not measure
CPU cost or prove the exact encoding/scheduler split. The 1 Hz daemon CPU
samples qualify concurrent load and record zero compiler processes; they
are not an actor CPU profile.

## Initial one-slice observer wire results and limits

These are medians of retained per-reload observer quantiles, not daemon
reload-completion clocks. Every changed observer must receive its full
expected generation inventory before its completion timestamp. The harness
starts its monotonic timer just before signaling; the daemon clock starts at
its received-SIGHUP log. The later polled `daemon_applied` marker establishes
terminal success separately and does not replace observer receipt timing.

| Process | Completion p50, s [range] | Completion p95, s [range] | Completion max, s [range] | First-generation UPDATE p50, ms [range] |
|---|---:|---:|---:|---:|
| Baseline r1 | 1.946655 [1.848823–2.169801] | 2.939604 [2.885534–3.113581] | 3.032627 [2.988022–3.186392] | 1806.974 [1741.392–1845.728] |
| Initial r1 | 2.087539 [1.983704–2.189134] | 2.967936 [2.892712–3.125888] | 3.057277 [2.967507–3.220258] | 979.897 [744.796–1246.224] |
| Initial r2 | 2.059843 [1.995171–2.367379] | 2.938124 [2.903891–3.118448] | 3.028994 [2.990006–3.213842] | 1153.259 [902.627–1320.970] |
| Baseline r2 | 1.991359 [1.815225–2.202445] | 2.962047 [2.835528–3.199704] | 3.051558 [2.932826–3.269479] | 1829.326 [1742.049–1926.769] |

The candidate's two completion-p50 process medians exceed both baseline
medians. Pooled completion p50 is 1.9518785→2.0732235 s, **+121.345 ms
(+6.2168%)**. Excluding the first two reloads preserves 1.939237→2.0605085 s,
+121.2715 ms (+6.2536%). The process direction and that split support a
workload tradeoff rather than dismissing the difference as noise. Individual
reload ranges overlap, including one same-number countercase; reload number
is not an independently controlled paired experiment.

Pooled completion p95 changes 2.944→2.950 s and max 3.035→3.043 s.
Those small differences reverse direction between process launches, so
this receipt does not establish a full-tail penalty. First-generation
UPDATE p50 improves 1821.315→1088.619 ms with disjoint all-reload ranges
1741.392–1926.769 and 744.796–1320.970 ms. Earlier first output and faster
operator completion coexist with slower median full observer delivery.

The initial campaign remains a measured tradeoff, independently of the
final two-slice comparison above. Its rows and identities are preserved
as a separate valid window. The invalid build-confounded attempt supplies
no timing rows to either comparison.

## Evidence and reproduction

The [artifact bundle](artifacts/shared-encoding-slice-fairness-2026-10-10/README.md)
retains selected original daemon events, RPC starts/ends/audits, engine CSV
rows, native/outer controls, actual source/binary/build/input-refresh/feature
identities and original-file hashes. It provides a standard-library
recomputation and negative controls, without copying full private logs.
Daemon completion ends at `config reload complete`; it does not mean the
later durable settlement or receiver barrier. Cohort includes preparation,
send and reply return; prestage includes the destination round trip and
session hot-apply. Microseconds are divided by 1,000. Any post-commit trace is
a terminal reply-boundary proxy before outer readiness cleanup and actual
reply publication; it supplies no dedicated send timestamp.
