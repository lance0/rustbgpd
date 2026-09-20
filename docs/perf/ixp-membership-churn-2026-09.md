# Dual-stack membership churn receipt (2026-09-20)

This cell replaces two route-server members and their dataset bindings during each policy reload while 700 announcing members retain their sessions.

**The 702-member qualification failed:** eight of 2,017 health commands exceeded the RIB readiness probe's 200 ms deadline. All four membership transitions, wire inventories, unchanged-session checks, dataset gates, and RIB-prefix queries passed. The smaller 20+2 preparation passed the complete gate. The v0.70.0 control rejected the first membership reload for the expected dataset-binding reason.

These are bounded local cells, not endurance qualification or a general scale claim. A passing 702-member qualification remains outstanding; the health failures have no reload-window exemption.

## Source and executable identity

The measured runtime source matches `8a02683f49b6165fc810cf5abeeb2744bb749a8a`. The daemon, CLI and Rust harness were actually built from clean checkout `d3478c32dd2d320e0c4130f63883ed803f0efa70`, which contains that runtime plus the membership harness. Three subsequent helper-only commits produced measurement checkout `e9bda76907904c07403217f051261a36374a1774`; they did not change the daemon, CLI or Rust harness sources. The build used Rust 1.98.1 and normal release artifacts.

| Executable | SHA-256 |
|---|---|
| `rustbgpd` | `4b063af47400c194e72fe95a886cf43b3ac79723045347272be5eda33b6a819d` |
| `rbgp` | `f50c90fac7f45c05a568655bdc48ff6a4b44da3174d0f33a10836691997bfd39` |
| `reloadstall` | `8f5c0b1a6d82b75b572e57f9c036a9969184ef7fa1536c73363de05dc54fa3e0` |

The [build receipt](artifacts/ixp-membership-churn-2026-09/build-receipt.json) records the commands, source identities and hashes. Publication subsequently integrated main through `443be51c0`; these observations remain pinned to the measured runtime above. They do not qualify that later dynamic-peer-group change.

The local host has an AMD Ryzen Threadripper 7970X (32 cores, 64 threads), about 125 GiB visible memory, and Linux 7.0.0-30-generic. The driver does not CPU-pin or isolate the daemon from its load generator. The sanitized [host metadata](artifacts/ixp-membership-churn-2026-09/host.json) is a retrospective hardware check; original admission samples remain in each archive. This is not a dedicated-CPU measurement.

## Workload and gates

The full cell has 700 unchanged announcing peers and two rotating receive-only peers, each negotiating IPv4 and IPv6 unicast over an IPv4 loopback transport. The core peers announce 400,400 unique routes, split equally between the two families. Each B/A/B/A reload changes the export marker for 600 core peers while retaining 100 stable observers, removes the old receiver pair, and adds a new pair of addresses and ASNs. The eight existing churners continue to write in both families during delivery.

Every member has its own ASN dataset and dual-family prefix dataset, both referenced by its import policy. The active roster contains 1,404 datasets. One member of each receiver pair uses TCP MD5, and all 702 members use GTSM. The added peers announce no routes: this proves receiver membership and dataset-binding churn, not announcing-owner churn.

The cell retains exact family inventories, export markers, stable-observer proof, actual churn overlap, zero parse/leak/withdrawal errors, successful health and RIB queries, full daemon-log classification, two quiet-host samples, and the normal cooldown. Membership checks additionally require:

- Each new pair establishes and receives every unique base prefix in both families, carrying the current export marker, within 60 seconds of staging.
- Neighbor and loaded-dataset rosters exactly match the candidate; datasets are nonempty and error-free, and removed dataset metric series disappear.
- All unchanged peers retain paired TCP socket inodes and four-tuples, unchanged flap counts, and nondecreasing uptime. The core harness does not reconnect them and independently checks session continuity. These are transport observations, not exposed internal actor session IDs.
- Every reload uses the owned generation route, with zero daemon ERRORs. Intentional departure applies only to the scheduled pair after its trigger.
- Both sampled daemon-tree RSS and daemon VmHWM remain below 16 GiB.

See the [harness recipe](../../bench/scale/reloadstall/README.md#membership-and-dataset-churn) for the exact command and focused checker tests.

## Results

| Measurement | 20+2 preparation | 702-member cell |
|---|---:|---:|
| Complete qualification | PASS | **FAIL** |
| Completed membership reloads | 4 | 4 |
| Health commands / failures | 1,830 / 0 | 2,017 / 8 |
| Health command p95 / maximum | 9.3 / 16.5 ms | 16.2 / 211.4 ms |
| RIB-prefix queries / failures | 840 / 0 | 932 / 0 |
| RIB command p95 / maximum | 9.1 / 12.0 ms | 19.3 / 217.0 ms |
| New-pair complete-export range from staging | 0.1698–0.1958 s | 3.6396–3.8801 s |
| Maximum sampled daemon-tree RSS | 73,376 KiB | 725,060 KiB |
| Daemon VmHWM | 68,856 KiB | 793,232 KiB |

The full cell initially established all 700 core sessions in 0.7 seconds, without transport retries, and reached exact initial inventories in 6.0 seconds. Every receiver pair obtained all 200,200 prefixes per family. All four cycles retained 700 core sessions, 100 stable observers per family, actual dual-family churn overlap, exact dataset rosters and zero receiver error counters. The full daemon log has no ERRORs and one expected initial RFC 8212 legacy-omission warning.

The eight failed health commands report `RIB manager probe timed out (200ms deadline)`. Two occurred after each reload commit, during the interval in which joining members received their tables. Failed CLI durations were 209.6–211.4 ms; those wall times include CLI overhead and are distinct from the backend deadline. This receipt establishes the repeated failure and timing relationship, not a measured attribution to an individual actor work unit.

Harness, membership helper, daemon shutdown, cleanup and driver exits were zero. The matrix's `status=pass` covers its native harness lifecycle; the separate complete qualification is **false**, with exactly `probes.csv failure`. Both original results are retained. Replaying the published copy produces the same red result.

Two earlier preparation attempts are also retained locally: the native runtime directory inherited unsafe mode 0775 under umask 002, then the helper assumed the CLI emitted a healthy `stale:false` field. Both were corrected with focused regressions before the successful preparation. The latter stopped before any reload; neither is presented as a daemon membership failure.

## v0.70.0 negative control

The official Linux amd64 release archive was checked against its published checksum. Its daemon SHA-256 is `d184d1d0b7eb18f0d62d6319e9ff50041d897b03d5215627425b0bb04e808968`; the tag points to `ee6215af61222a43c3a8019ee0352ecd5df77913`. The CLI, harness, workload, authentication, host admission and configuration generation were identical to the full current-source cell.

All 702 sessions became ready, both receivers obtained 200,200 prefixes per family, the initial 1,404-dataset roster passed, and all 700 core observers reached exact inventories. The first SIGHUP at 18:12:33.890 UTC was rejected at 18:12:34.407 UTC for:

```text
[policy.datasets] names, kinds, file mappings, or handles
```

The harness observed `rejected_no_effect (+1)` and stopped itself with exit 1 before a second reload. This is the intended negative-control outcome, not a qualification pass. The daemon exited cleanly with exit 0. The runner deliberately terminates the membership watcher after a failed harness, which accounts for its recorded cleanup exit 1. After every owned child had finished, only the post-failure cooldown was interrupted; the archive records that controlled stop. The original current-source executable was then restored and its hash verified.

The [artifact guide](artifacts/ixp-membership-churn-2026-09/README.md) provides full archives, source/binary provenance, publication transformations, checksums and replay commands.
