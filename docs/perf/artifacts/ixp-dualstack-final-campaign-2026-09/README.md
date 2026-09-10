# Dual-stack final campaign artifacts

These artifacts support the [dated campaign receipt](../../ixp-dualstack-final-campaign-2026-09.md): all 13 measured cells passed supplemental v3, covering one 20-member correctness cell, four 200-member validations and two complete four-cell 700-member campaigns.

## Available evidence

| Cell | Original v2 | Supplemental v3 | Reclassified cleanup WARNs | Health starts / results | Successful retained RIB rows |
|---|---|---|---:|---:|---:|
| [`20-50-F`](20-50-F/summary.json) | PASS | PASS | 0 | 1,862 / 1,862 | 846 |
| [`200-90-P`](200-90-P/summary.json) | PASS | PASS | 0 | 1,924 / 1,924 | 872 |
| [`200-90-F`](200-90-F/summary.json) | PASS | PASS | 0 | 1,912 / 1,912 | 868 |
| [`200-50-P`](200-50-P/summary.json) | PASS | PASS | 0 | 1,922 / 1,922 | 870 |
| [`200-50-F`](200-50-F/summary.json) | PASS | PASS | 0 | 1,907 / 1,907 | 866 |
| [`700-A-90-P`](700-A-90-P/summary.json) | FAIL | PASS | 700 | 2,041 / 2,041 | 924 |
| [`700-A-90-F`](700-A-90-F/summary.json) | PASS | PASS | 0 | 2,026 / 2,026 | 922 |
| [`700-A-50-P`](700-A-50-P/summary.json) | PASS | PASS | 0 | 2,035 / 2,035 | 915 |
| [`700-A-50-F`](700-A-50-F/summary.json) | FAIL | PASS | 700 | 2,054 / 2,054 | 938 |
| [`700-B-90-P`](700-B-90-P/summary.json) | PASS | PASS | 0 | 2,050 / 2,050 | 922 |
| [`700-B-90-F`](700-B-90-F/summary.json) | FAIL | PASS | 700 | 2,056 / 2,056 | 942 |
| [`700-B-50-P`](700-B-50-P/summary.json) | FAIL | PASS | 700 | 2,038 / 2,038 | 918 |
| [`700-B-50-F`](700-B-50-F/summary.json) | FAIL | PASS | 700 | 2,052 / 2,052 | 936 |

Every completed cell has one-to-one health start/result capture, zero failed commands and no health stderr. The eight original passes and five original failures remain intact. Each original failure contains 700 cleanup TCP-refusal warnings; supplemental v3 reclassifies only the individually proven cleanup sequences. The [earlier readiness evidence](../ixp-dualstack-readiness-2026-09/README.md), including its accepted pair and failures, remains unchanged and is not counted as a new campaign cell.

The recorded source is `5dde6775a38bbc3e53a4d75a4a2563890e92f3c6`, tree `28179cfd569d2c56f66cc9faf793d48db84571ce`. All three executables use normal builds from this source. The daemon version is 0.69.0; later release preparation does not change the identity of this measured binary. The separate qualifying soak has its own evidence and verdict.

Each completed cell retains its runner, byte-identical v2 gate, source snapshot script, source inventories before/after execution, build receipt, binary hashes, generated policy/config inputs, complete daemon and receiver logs, health starts/stderr/results, RIB results, quiet samples, RSS/HWM, and actual exit records. Its summary binds all four build/run source snapshots and the three executable hashes to the campaign build. The per-cell `peers`, `mix` and `shape` records identify its exact workload. Every 700-member cell additionally retains the identity of its passing corresponding 200-member mix/shape prerequisite.

Original failures stay visible even when a later analysis changes qualification. No missing row or result is synthesized. Executable binaries and runtime persistence/config-history files remain in the private archive; the generated input policies and configuration are exported.

## Public normalization and integrity

Source paths become `/tmp/campaign-source`; Cargo caches become `/tmp/campaign-build-cache`. Prep, build receipts, immutable binary stores and measured outputs keep distinct `/tmp/campaign-*` paths. The user/toolchain home becomes `/tmp/measurement-user`; private command shims become `/tmp/measurement-user/tool-bin`; the host name becomes `measurement-host`. Source and executable identities, timestamps, addresses, measurements and warning text remain intact.

`original-sha256.json` records original local file bytes, keyed by exported relative path. For gzip outputs, its hashes describe the uncompressed original. Public gzip uses a zero timestamp. Per-cell `summary.json` and `qualification.json.gz` are derived evidence and have no original-byte hashes. `SHA256SUMS` covers all public files except itself, including those derived records and the supplemental checker/tests.

Export validation recomputes metrics from every retained CSV row, checks every health invocation start against exact CSV timestamp strings, and compares each checker's entire replayed JSON result with its corresponding retained result. Health/query percentiles use nearest rank. Whole-command wall times are not RPC durations. RIB query starts are not recorded.

## Original and supplemental classifications

Gate v3 is a supplemental checker, loaded separately; it verifies the original `gate.py` hash before invoking it and does not write bytecode into the raw cell. It removes only exact socket-refusal warnings proven to follow that same peer's received Administrative Shutdown and session-down after measured completion, with no intervening establishment. All other gate outcomes remain intact. The [dated report](../../ixp-dualstack-final-campaign-2026-09.md#first-700-member-cell-retained-classifier-failure) describes the source-level reason and exact rule.

The original `evidence.json.gz` and `gate.exit` continue to report v2. The separate `qualification.json.gz` and summary qualification fields identify v3, its SHA-256 and its explicit correction metadata, including original pass/errors and the classified peers/timestamps. The [supplemental checker](gate_v3.py) has SHA-256 `8e6405fa52d34d2963b1859d59704293d884fe6057263f79f1d69954f64da773`; its [synthetic regressions](test_gate_v3.py) cover 33 cases. Original gate v2 has SHA-256 `9ec25e91d1a2ed9a2a8c55d7a251cff4b3e31214e7e753a4ebf3940dcee16543`.

## Analysis-only replay

Copy the cells and supplemental checker into a fresh temporary directory. Decompress `.gz` files there, preserving relative paths. For example, reproduce one original pass and the first original failure:

```sh
python3 20-50-F/gate.py 20-50-F 20 11440 5720 16 32
python3 700-A-90-P/gate.py 700-A-90-P 700 400400 360360 600 0
python3 gate_v3.py 700-A-90-P 700 400400 360360 600 0
```

The first command returns `pass=true`, empty `errors`, exit 0. The second retains original `pass=false`, 700 TCP-refusal errors, exit 1. The third returns supplemental `pass=true`, zero remaining errors, exit 0, with exactly 700 classified cleanup refusals and the original failure preserved in its metadata. Keep the original and supplemental outputs separately. These commands read retained measurements and launch no workload.

Both checkers take `CELL PEERS TOTAL IPV4 CHANGED FILTER` arguments. Apply the following shape arguments to the corresponding A or B cell, or its 200-member validation:

| Shape | Arguments after CELL |
|---|---|
| 200, 90/10 P | `200 114400 102960 170 0` |
| 200, 90/10 F | `200 114400 102960 170 32` |
| 200, 50/50 P | `200 114400 57200 170 0` |
| 200, 50/50 F | `200 114400 57200 170 32` |
| 700, 90/10 P | `700 400400 360360 600 0` |
| 700, 90/10 F | `700 400400 360360 600 32` |
| 700, 50/50 P | `700 400400 200200 600 0` |
| 700, 50/50 F | `700 400400 200200 600 32` |

The original outcomes are listed above; every supplemental replay returns PASS. Compare the entire JSON output against its own retained `evidence.json` or `qualification.json`, rather than only comparing the pass flag.

## Fresh measurement

Use a clean checkout of the recorded source at `/tmp/campaign-source`. Copy `run.sh`, `gate.py` and `snapshot.py` from a completed cell to `/tmp/campaign-prep`, plus `build.sh` from its `build-receipt` and the archive-root `gate_v3.py`. The retained build script expects exact worktree cache symlinks to `target` and `bench/scale/target` under `/tmp/campaign-build-cache`, or its own complete private executable stage. It builds all three executables, captures source/binary identity and stages immutable copies outside the caches. A rebuilt executable needs fresh provenance; old hashes do not promise bit-for-bit reproduction.

With no competing local build, lab or measurement:

```sh
bash /tmp/campaign-prep/build.sh /tmp/campaign-build-new
runner_rc=0
bash /tmp/campaign-prep/run.sh 20 50 F /tmp/campaign-20-new /tmp/campaign-build-new || runner_rc=$?
printf '%s\n' "$runner_rc" > /tmp/campaign-20-new-wrapper.exit
python3 /tmp/campaign-prep/gate_v3.py /tmp/campaign-20-new 20 11440 5720 16 32 > /tmp/campaign-20-new/qualification.json
```

The original runner intentionally preserves v2 and may exit 1 for cleanup warnings. Retain that real exit and the original `gate.exit`/`evidence.json`; run supplemental qualification separately and retain its own result and exit. V3 does not excuse other driver, receiver, health or cleanup failures. Use the corresponding larger-shape arguments from the replay table, preserving both checker results.

The runner accepts `200` or `700`, mix `90` or `50`, and shape `P` or `F`. A 700-member invocation requires a sixth argument identifying a passing corresponding 200-member cell with the same mix/shape, source and executable hashes. Preserve the published workload, admission gate, abort limits and cooldown. An interrupted run requires cleanup of its owned processes and retention of its actual failure evidence.
