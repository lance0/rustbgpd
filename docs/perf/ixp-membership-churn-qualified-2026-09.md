# Qualified dual-stack membership cell (2026-09-20)

This 702-member cell passes the unchanged membership, wire, readiness, memory and daemon-log gates after initial-export readiness service and bounded receiver shutdown were corrected.

**Qualification passed with zero errors:** all four membership reloads completed, all 2,039 health probes and 922 RIB-prefix queries succeeded, and final cleanup produced no writer-reset warning. This is one bounded local cell for the recorded binaries, workload and host. It does not establish endurance, announcing-owner churn, comparative performance or a general capacity limit.

The earlier [production readiness failure](ixp-membership-churn-2026-09.md) and [readiness-corrected teardown failure](ixp-initial-export-readiness-2026-09.md) remain intact. The actual v0.70.0 first-reload rejection is retained in the former receipt; it was not rerun for this cell.

## Exact source and binary binding

The daemon is the same immutable production binary used for the immediately preceding red cell. It was built at `7f1f8d864c00078878800825c6f8ad1273614051`, SHA-256 `fd37bc7234d71f02d8e9a867e46b4514d71b08ea1502b431b7685b9f7e450d26`. Candidate commit `7f1f8d864` and merged runtime commit `56cd7983a0eabcff1fb6480f55612d472e2c6911` have the identical Git tree `2b0b189f02af6e6ac1f144753b0269a65bb9445d`; the [source-equivalence record](artifacts/ixp-membership-churn-qualified-2026-09/source-equivalence.json) preserves that check. There is no private timing instrumentation.

The Python receiver helper comes from reviewed commit `23bd7927347eedd81d4fa513d93bb3b91656e2bb` ([PR #2598](https://github.com/lance0/rustbgpd/pull/2598)), SHA-256 `8921bd8e51e87ece8952cf171258ac91c9af9861085bd262acdba678a65a191c`. This complete helper version includes the earlier explicit loop captures as well as terminal draining. The driver and qualification checker remain frozen at `e9bda76907904c07403217f051261a36374a1774`.

| Unchanged executable | Build commit | SHA-256 |
|---|---|---|
| `rbgp` | `d3478c32dd2d320e0c4130f63883ed803f0efa70` | `f50c90fac7f45c05a568655bdc48ff6a4b44da3174d0f33a10836691997bfd39` |
| `reloadstall` | `d3478c32dd2d320e0c4130f63883ed803f0efa70` | `8f5c0b1a6d82b75b572e57f9c036a9969184ef7fa1536c73363de05dc54fa3e0` |

Only the reviewed helper file and candidate daemon were substituted in the frozen driver checkout. Its native `git.dirty=true` records that single tracked helper substitution; its Git source fields are not the daemon's build identity. [Split provenance](artifacts/ixp-membership-churn-qualified-2026-09/split-provenance.json) identifies the components independently. Both original files were restored afterward and their hashes verified.

## Workload, host and criteria

The workload remains 700 unchanged announcing peers plus two rotating receive-only members. Each peer negotiates IPv4 and IPv6 unicast over IPv4 transport; the core announces 200,200 prefixes per family. Four B/A/B/A reloads change export markers for 600 destinations, preserve 100 stable observers, and replace the receiver pair and its referenced datasets. The active roster has 702 neighbors and 1,404 loaded datasets. One receiver per pair uses TCP MD5; the entire fleet uses GTSM. Continuous dual-family churn overlaps every measured reload.

The [harness criteria](../../bench/scale/reloadstall/README.md#membership-and-dataset-churn) remain unchanged: exact inventories and markers, core TCP/flap/uptime continuity, dataset/status/metric rosters, removed-series cleanup, zero health/RIB failures, 60-second new-pair export limit, 16-GiB memory guard, and daemon-log classification. No deadline, warning exemption, threshold or workload changed.

The updated helper stops and joins keepalives before sending its final Cease, flushes it, half-closes the write side, and retains its strict reader through EOF. A single 15-second fleet budget bounds terminal completion and owned cleanup. Config-driven member removals remain separate. All 16 focused helper/gate/TCP tests passed before this native run. Separate immediate-close and swallowed-cancellation controls failed their intended assertions, then restored source passed.

The host is an AMD Ryzen Threadripper 7970X (32 cores, 64 threads), with about 125 GiB visible memory and Linux 7.0.0-30-generic. The driver does not CPU-pin or isolate the daemon and load generator. All compilation and test processes had finished; ports were free and the ordinary two-sample quiet-host gate passed. [Sanitized host metadata](artifacts/ixp-membership-churn-qualified-2026-09/host.json) is retrospective; actual admission samples remain in the archive.

## Completed cell

The live cell ran from 19:53:45 to 19:56:04 UTC. Normal cleanup, 300-second cooldown, qualification replay and restoration completed at 20:01:05 UTC.

| Measurement | Result |
|---|---:|
| Complete qualification | **PASS; zero errors** |
| Health commands / failures | 2,039 / 0 |
| Health CLI p95 / maximum | 20.5 / 181.7 ms |
| RIB-prefix queries / failures | 922 / 0 |
| RIB CLI p95 / maximum | 18.5 / 401.5 ms |
| Maximum sampled daemon-tree RSS | 707,972 KiB |
| Daemon VmHWM | 798,476 KiB |
| Daemon ERRORs / writer warnings | 0 / 0 |

| Reload | Generation phase total (s) | Maximum changed-observer completion (s) | New-pair complete export from staging (s) |
|---|---:|---:|---:|
| 1, B | 1.486535 | 3.323179 | 4.253099 |
| 2, A | 1.488459 | 3.172300 | 3.985101 |
| 3, B | 1.410808 | 3.060467 | 4.093209 |
| 4, A | 1.486790 | 3.208965 | 4.017836 |

All 700 core sessions remained established without reconnects or flap-count changes. All 100 stable observers per family supplied fresh post-completion markers. Every new receiver obtained all 200,200 prefixes in each family with the expected export marker. Exact dataset rosters, nonempty/error-free status rows and removal of obsolete metric series passed at every generation. All parser, leak and unintended-withdrawal counters were zero.

The daemon log contains two accepted warnings: the expected startup RFC 8212 legacy-omission message, and `outbound channel full or closed — marking dirty for resync` at `19:56:02.540454Z`, after core-session shutdown had started at `19:56:02.507392Z`. The original checker already admits that teardown category. There was no `ConnectionReset` or other writer warning, and no classifier change.

Driver, native harness, membership helper, cleanup, daemon, qualification and launcher exits were zero. All owned children were reaped. The previous red results remain failures under their original rules; this fresh cell supplies the passing qualification rather than reclassifying earlier data. Timings have different endpoints and represent one cell; they are not an isolated performance comparison.

The [artifact guide](artifacts/ixp-membership-churn-qualified-2026-09/README.md) provides full compressed evidence, checksums, preserved source/binary identities and exact replay.
