# Boxed MP attributes on a real IPv4 table (October 2026)

> **Document class: HISTORICAL.** These measurements cover one archived table,
> one selected peer, two source trees, and one host. They are not a memory or
> convergence guarantee for another deployment.

The boxed `MP_REACH_NLRI`/`MP_UNREACH_NLRI` change reduced whole-daemon
memory on this high-diversity replay. Across five counterbalanced release-build
pairs, parent-minus-boxed cgroup peak had a median of **86.24 MiB** (range
60.61–91.71 MiB), settled cgroup anonymous memory a median of **80.96 MiB**
(73.64–100.81 MiB), and settled process-tree RSS a median of **81.49 MiB**
(74.52–100.70 MiB). The paired file-memory delta was within 4 KiB. This
closes the real-table memory question left open by the [September structural
receipt](boxed-mp-path-attributes-2026-09.md) for this measured shape.

## Input and arms

The input was the Route Views route-views2 `rib.20260808.0000.bz2` full-table
MRT snapshot. Its compressed SHA-256 is
`03bf1ea39809789576786c61c7ff77d8e1977d04706af1457aaafaf7cb0e95fb`;
the decompressed MRT SHA-256 is
`f6c87b21e0c651d1ec66e8153018234d8981225c4450a8f97551a1cdcbab73d0`.
The selected source peer was ASN 20130: 1,079,184 unique IPv4 prefixes and
148,789 distinct raw attribute hashes when next hop was excluded. The
unfiltered file includes other peers and was not treated as one table.

The parent tree was `82700ff0dfe1b37d4e5a32ec1557e19a10abedab`;
the boxed tree was `aea6e2c77ee5581ff399fc27d6a8ebb816d2ea4d`.
These are the immediate pre-rebase source commits from the September receipt;
their production-code difference is the boxing change. Both arms received the
same uncommitted, campaign-only diagnostic patch to report live interned-set
and attribute-vector counts after settling. The one-time scan was triggered
through readiness, outside the UPDATE path. Its full as-run diff hash and
the exact release/DHAT image IDs are in
[`provenance.json`](artifacts/boxed-mp-real-table-2026-10/provenance.json).
The diagnostic patch is not a published production change.

The replay used the pinned GoBGP 4.8.0 MRT injector with an ASN 20130 source
filter, no record-count limit, one target, and one independent monitor. The
970,000-route checkpoint was an early liveness checkpoint, not the endpoint:
the injector ran through the selected records and exited before settling.
Target and monitor each reached **1,078,977** IPv4 routes. The target retained
175 malformed-AS_SET rejected routes; 32 source-to-target prefixes remain
unclassified by the retained counters. Those 32 are a limit of the correctness
accounting, not an inferred parser or boxing effect. Both arms passed the same
frozen route and inventory guards: **148,667 live interned sets**, **489,537**
attribute-vector elements and capacity slots (**3.293 attributes and allocated
slots per live set on average**), and 229,376 intern-table slots.

Each release cell ran serially in a fresh, swap-disabled cgroup. The five
orders were parent/boxed, boxed/parent, parent/boxed, boxed/parent,
parent/boxed. The runner waited for MRT exit and five stable target, monitor,
and interned-set readings before the one-time diagnostic scan. `memory.peak`
is the cgroup high-water reading before that scan; settled anonymous/file
values and process-tree RSS are post-settlement readings. The process-tree
maximum is sampled at 1 Hz and is not an exact peak. The runner held the
benchmark locks; no two measured daemons ran concurrently.

## Paired release-memory results

Positive numbers mean the parent used more memory. All values below are MiB,
rounded from the retained exact-byte and KiB rows. The file-memory column is
shown in KiB to expose its small signed variation.

| Pair | Order | Cgroup peak Δ | Settled anon Δ | Settled file Δ (KiB) | Settled RSS Δ | Sampled max RSS Δ |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | parent → boxed | +90.45 | +90.93 | 0 | +91.02 | +107.15 |
| 2 | boxed → parent | +60.61 | +73.64 | −4 | +74.52 | +45.68 |
| 3 | parent → boxed | +86.24 | +80.96 | 0 | +81.49 | +77.45 |
| 4 | boxed → parent | +91.71 | +100.81 | 0 | +100.70 | +102.29 |
| 5 | parent → boxed | +79.01 | +80.41 | +4 | +80.45 | −13.80 |
| **Median** | | **+86.24** | **+80.96** | **0** | **+81.49** | **+77.45** |

The last sampled-maximum RSS pair reverses sign even though its settled RSS
and cgroup peak favor boxing. The 1 Hz maximum depends on transient timing;
the five cgroup peaks and settled readings support the memory result without
turning that sampled maximum into an exact peak claim. Exact individual cells
and signed pair differences are in [`release-runs.csv`](artifacts/boxed-mp-real-table-2026-10/release-runs.csv)
and [`release-pairs.csv`](artifacts/boxed-mp-real-table-2026-10/release-pairs.csv).

The prior estimate of 126–252 MiB used 206,571 interned sets, four to eight
attributes per set, and a 160-byte reduction per stored `PathAttribute`.
The replay's actual **489,537 capacity slots × 160 bytes = 78,325,920 bytes
(74.70 MiB)**. That smaller measured shape explains why the real-table
whole-daemon delta is below the earlier range. It is a structural estimate,
not a claim that allocator overhead, fragmentation, or every process byte
must equal 74.70 MiB.

## Allocation attribution

A separate pair of `dhat-heap` builds replayed the same frozen input and
route/inventory guards. At each profile's own `t_gmax`, parent live allocation
was 1,284,548,878 bytes and boxed live allocation was 1,204,432,668 bytes:
an **80,116,210-byte (76.40 MiB)** difference. `t_gmax` occurred at different
times in the two processes and may include in-flight allocations. It is an
allocator snapshot, not the release-build settled RSS or cgroup peak.

The frozen automatic classifier assigns **0** bytes to “Interned
attribute-set backing” and assigns a **79,960,745-byte** parent-minus-boxed
delta to “Transport session buffers/scratch.” We retain those original labels
in [`dhat-classes.tsv`](artifacts/boxed-mp-real-table-2026-10/dhat-classes.tsv);
they were not silently corrected after inspection. Source-site inspection of
the two dominant `RawVec → slice::to_vec` stack families instead identifies
`RouteAttrBundle::new` in `crates/transport/src/session/inbound.rs` as the
owner of the outer attribute vector. Its `AttrSet::new` successor moves that
vector into the interner, where shared `Arc` references can retain it. The
four stack rows total **103,986,480** parent bytes versus **24,004,464**
boxed bytes, a **79,982,016-byte (76.28 MiB)** difference. The source trace
supports identifying those allocations as outer attribute vectors; it does
not prove every such vector was interned at the profile peak. The source-site
excerpts are in [`dhat-outer-stacks.tsv`](artifacts/boxed-mp-real-table-2026-10/dhat-outer-stacks.tsv).

This receipt measures import of one IPv4 peer's archived table. It does not
measure export fanout, IPv6, Add-Path, reload, churn, convergence time, or
another table's attribute distribution. Full private DHAT profiles and logs
remain outside this compact public artifact; the published provenance and
machine-readable summaries preserve the paired result and the attribution
limit.
