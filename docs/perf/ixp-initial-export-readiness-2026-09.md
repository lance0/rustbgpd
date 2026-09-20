# Initial-export readiness cell (2026-09-20)

This cell repeats the 702-member membership workload with readiness service during initial table export and preserves its failed teardown qualification.

**Overall qualification remains red.** All 2,037 health probes and 920 RIB-prefix queries passed, together with every wire, membership, unchanged-session, dataset and memory gate. The sole remaining error is a writer `ConnectionReset` warning during final shutdown. The original warning rule was retained; this receipt does not establish a passing scale qualification.

## Source, binaries and host

The production daemon was built from clean reviewed commit `7f1f8d864c00078878800825c6f8ad1273614051` ([PR #2597](https://github.com/lance0/rustbgpd/pull/2597)), based on `96fca6e238c4766f06ca53869f748aac41076a0f`. It includes readiness service inside the shared initial-table export path and has no diagnostic instrumentation.

The driver, Python helper and checker remain frozen at `e9bda76907904c07403217f051261a36374a1774`. The CLI and Rust harness retain the exact binaries built from `d3478c32dd2d320e0c4130f63883ed803f0efa70` for the [earlier membership receipt](ixp-membership-churn-2026-09.md). The native driver's Git fields describe its frozen checkout; they do not identify the separately supplied candidate daemon. The [split provenance](artifacts/ixp-initial-export-readiness-2026-09/split-provenance.json) explicitly binds both parts.

| Executable | SHA-256 |
|---|---|
| Candidate `rustbgpd` | `fd37bc7234d71f02d8e9a867e46b4514d71b08ea1502b431b7685b9f7e450d26` |
| Unchanged `rbgp` | `f50c90fac7f45c05a568655bdc48ff6a4b44da3174d0f33a10836691997bfd39` |
| Unchanged `reloadstall` | `8f5c0b1a6d82b75b572e57f9c036a9969184ef7fa1536c73363de05dc54fa3e0` |

The daemon used Rust 1.98.1 and `cargo build --locked --release --bin rustbgpd`, with eight build jobs and an isolated target directory. All compilation, test and hook processes had finished before admission. Only the daemon executable was replaced; the original was restored afterward and its SHA-256 verified.

The host has an AMD Ryzen Threadripper 7970X (32 cores, 64 threads), about 125 GiB visible memory and Linux 7.0.0-30-generic. The driver does not pin or isolate the daemon and load generator to dedicated CPUs. [Sanitized host metadata](artifacts/ixp-initial-export-readiness-2026-09/host.json) is retrospective; the archive retains the actual two accepted quiet-host samples. The preflight found the test ports free and no competing build or daemon processes.

## Unchanged workload and criteria

The workload retains 700 announcing peers, two rotating receive-only members, 400,400 routes split equally between IPv4 and IPv6, four B/A/B/A reloads, 600 changed export destinations, 100 stable observers, and continuous dual-family churn. Each reload replaces the receiver pair and its referenced datasets. One receiver uses TCP MD5 and the whole fleet uses GTSM. The active roster remains 702 neighbors and 1,404 datasets.

The [existing harness recipe and criteria](../../bench/scale/reloadstall/README.md#membership-and-dataset-churn) were unchanged, including exact wire inventories and export markers, session continuity, removed dataset-series cleanup, zero management failures, 60-second complete-export limit, 16-GiB memory guard, full daemon-log classification, and normal cooldown. The helper still uses its original terminal shutdown behavior. Announcing ownership does not rotate.

## Complete results

The live cell ran from 19:35:39 to 19:37:58 UTC. Its normal 300-second cooldown and final replay completed at 19:42:59 UTC.

| Measurement | Result |
|---|---:|
| Health commands / failures | 2,037 / 0 |
| Health CLI p95 / maximum | 21.4 / 183.5 ms |
| RIB-prefix queries / failures | 920 / 0 |
| RIB CLI p95 / maximum | 18.9 / 457.7 ms |
| Maximum sampled daemon-tree RSS | 744,636 KiB |
| Daemon VmHWM | 806,840 KiB |
| Daemon ERROR records | 0 |
| Full qualification | **FAIL: one teardown writer warning** |

| Reload | Generation phase total (s) | Maximum changed-observer completion (s) | New-pair complete export from staging (s) |
|---|---:|---:|---:|
| 1, B | 1.549881 | 3.094723 | 4.426527 |
| 2, A | 1.436662 | 3.022451 | 4.190330 |
| 3, B | 1.539171 | 3.256345 | 4.305443 |
| 4, A | 1.465415 | 3.233591 | 4.053521 |

Every reload retained all 700 unchanged core sessions, 100 stable observers per family, exact dataset/status/metric rosters and complete exports to both new receivers. All four dual-family churn-overlap checks passed. Parse, leak, bystander, stable and duplicate-withdrawal errors were zero. The archive retains each family's separate receiver distributions and original timing rows.

The earlier production cell had eight health failures and joining times of 3.640–3.880 seconds. This candidate had zero health failures and joining times of 4.054–4.427 seconds. Different runtime bases and one cell per candidate limit causal and performance comparisons. CLI timings include client overhead; generation completion, receiver completion and new-pair completion have different endpoints.

## Preserved teardown failure

Peer `127.1.3.110` received Cease / Administrative Shutdown (code 6, subcode 2) at `19:37:58.407897Z`, logged its own session-down at `19:37:58.407918Z`, then produced `writer: write/flush failed` with `error_kind=ConnectionReset` at `19:37:58.407959Z`. The warning followed received Cease by 62 microseconds and its session-down by 41 microseconds, after the measured reload work had completed.

The checker admits a narrowly ordered `BrokenPipe` warning during teardown, but does not admit `ConnectionReset`. The exact retained error is therefore:

```text
unclassified/active WARN: writer: write/flush failed
```

Its recorded phase is `teardown`; the generic error text does not place it in active measured work. No warning was reclassified, removed or exempted. The only other warning is the expected startup RFC 8212 legacy-omission message.

Harness, membership helper, daemon, cleanup and driver exits were zero. Qualification and enclosing launcher exits were one. Full cooldown completed, all owned children were reaped, and the original frozen daemon was restored. The [artifact guide](artifacts/ixp-initial-export-readiness-2026-09/README.md) provides checksums, source binding, full compressed evidence and the unchanged replay.
