# Dual-stack policy-reload readiness artifacts

These public copies support the [dated readiness receipt](../../ixp-dualstack-readiness-2026-09.md). Seven completed cells are archived. The final normal pair passed the unchanged gate; earlier attempts remain separate:

| Cell | Result | Capture / cleanup evidence |
|---|---|---|
| `200-50-F/` | Initial normal gate PASS | All 1,914 health starts match CSV rows |
| `700-50-F/` | Initial normal gate FAIL: shutdown warning | One final health transport error has no CSV completion |
| `diagnostic-700-50-F/` | Instrumented gate FAIL: 16 writer warnings | Complete health capture; diagnostic scope/capacity records |
| `runner-fixed-200-50-F/` | Probe-cleanup gate FAIL: writer and withdrawal warnings | Complete health capture; native daemon and cleanup exits 0 |
| `client-cleanup-200-50-F/` | Client-cleanup gate PASS | All 1,910 health starts match rows; native exits 0 |
| `shutdown-deadline-200-50-F/` | Final normal 200 gate PASS | All 1,910 health starts match rows; native exits 0 |
| `shutdown-deadline-700-50-F/` | Final normal 700 gate PASS | All 2,027 health starts match rows; native exits 0 |

[Historical observations](../ixp-dualstack-policy-noops-2026-09/README.md) remain in their original archive. The client-cleanup source `01a4d3b856d7588e272805b251e6d9bba5a17728` has harness hash `992e0039279350a3ccb6f44087c50c72cf248e851444facf026382726e280eac`, distinct from the earlier `67ed73d48c3f261b96872de1f67ebacdac488bdd74a5b4d123d72dc007ebf7dc` binary. Daemon/CLI hashes and gate v2 remain unchanged. The harness gives graceful Cease delivery and socket drain a shared 15-second deadline, followed by cooperative cancellation and reaping when needed; this is not a hard wall-clock bound on all cleanup. The later source `a227c61e1b22f4601c0d40bdf335a7006ad0b6a5` adds a 60-second native-daemon shutdown deadline and has a completed build with the same three executable hashes as `01a4d3b85`; its final normal pair is retained separately in `shutdown-deadline-200-50-F/` and `shutdown-deadline-700-50-F/`. Both runs use identical source and executable hashes, verified by the 700-member wrapper against the passing 200-member prerequisite. Merge `c86170ca199319507c96c362ca019fd74648a4fa` has the identical tree, `d4b5d5aea5b1bcd0fdaa8cbcb0f75f0fe835a359`.

Each cell retains the wrapper, unchanged gate, snapshot script, driver/gate/provenance exits, binary checks, complete source inventories before and after execution, generated inputs, full receiver and daemon logs, accepted quiet samples, health stderr and CSVs, RIB-query CSV, RSS samples, and VmHWM. `build-receipt/` inside the cell retains the actual build commands, complete Cargo output, source inventories before and after the build, toolchain, feature mode, executable hashes, immutable binary-store identity, staging/cache checks, and build exits. The three executables were built from the measured source. Binary files themselves and runtime persistence/config-history files are omitted. No measurement or warning rows are removed.

`diagnostic-700-50-F/` retains the same instruments for the separate build with `rustbgpd-rib/bench-internals`, plus its diagnostic wrapper. Its complete scope and capacity rows remain in the full daemon log and derived summary. It is not a normal acceptance row.

The root `summary.json` separates normal and diagnostic cells and tags the source stages separately. `runner-fixed-200-50-F/` uses clean source `dad3c0406130066799fb6dfddc46ff3290d2ff85`; its three executable hashes match the initial normal cells exactly, and its retained native `rustbgpd/daemon.exit` is 0. `audit-probe-capture.py` compares health invocation-start markers with exact CSV timestamp strings. Its results are included in each cell summary: 1,914/1,914 starts/completions at normal 200, 2,023/2,023 in the diagnostic, and 2,028/2,027 at normal 700, whose unmatched start retains its transport-error stderr. The probe-cleanup attempt has 1,909/1,909 health starts/completions and no health stderr; the client-cleanup attempt has 1,910/1,910 with no health stderr. The final pair has 1,910/1,910 and 2,027/2,027 health starts/completions respectively, with no health stderr. None of the recorded runner versions emits RIB-query start markers. Each cell's `summary.json` recomputes command counts and nearest-rank p95 values from all retained CSV rows, collects full-generation and per-family receiver records, and records source/build verification. `historical-reference.json` contains two earlier observations and their existing public source links; those are historical references, not a controlled paired A/B baseline. Historical original/public checksums were verified before extraction.

Private source and build-cache roots become `/tmp/readiness-source` and `/tmp/readiness-build-cache`. Preparation, build, output, and immutable-store directories use distinct `/tmp/readiness-*` paths. The toolchain home and host-lock root become `/tmp/measurement-user`; private command-shim entries in the captured PATH become `/tmp/measurement-user/tool-bin`. The host name becomes `measurement-host` where present. Generic workload paths such as `/tmp/ixp-rustbgpd` remain unchanged. Timestamps, addresses, counters, warning text, source/executable hashes, and measurements are retained. Full daemon logs, gate evidence, and source inventories use gzip with a zero timestamp.

`original-sha256.json` identifies original local bytes before path replacement or compression, keyed by exported relative filename. For gzip files its hash covers the original uncompressed bytes. `SHA256SUMS` covers the exported public files. Embedded source/executable hashes identify the original bytes, not the normalized copy. The summary files, `audit-probe-capture.py`, and this README are derived analysis/documentation and have only public checksums.

## Analysis-only replay

Copy this directory to a fresh temporary location and run the retained checker from that copy:

```sh
gzip -dk */rustbgpd/daemon.log.gz
python3 200-50-F/gate.py 200-50-F 200 114400 57200 170 32 > 200-50-F/replayed-evidence.json
```

Expected result: `pass=true`, empty `errors`, exit 0. Replay the failed normal 700-member cell:

```sh
python3 700-50-F/gate.py 700-50-F 700 400400 200200 600 32 > 700-50-F/replayed-evidence.json
python3 audit-probe-capture.py 700-50-F
```

The unchanged gate returns `pass=false`, exit 1, for the shutdown-grace warning. The separate capture audit retains one unmatched health invocation with transport-error stderr; this audit does not rewrite the gate or add a synthetic CSV completion. Replay the diagnostic separately:

```sh
python3 diagnostic-700-50-F/gate.py diagnostic-700-50-F 700 400400 200200 600 32 > diagnostic-700-50-F/replayed-evidence.json
```

Expected result: `pass=false`, exit 1, and the 16 writer-warning errors retained in the receipt. The probe-cleanup attempt also remains a failed checker result:

```sh
python3 runner-fixed-200-50-F/gate.py runner-fixed-200-50-F 200 114400 57200 170 32 > runner-fixed-200-50-F/replayed-evidence.json
python3 audit-probe-capture.py runner-fixed-200-50-F
```

Expected gate result: `pass=false`, exit 1, for the writer and withdrawal warnings. The capture audit finds no missing health CSV completions.

Replay the successful client-cleanup attempt:

```sh
python3 client-cleanup-200-50-F/gate.py client-cleanup-200-50-F 200 114400 57200 170 32 > client-cleanup-200-50-F/replayed-evidence.json
python3 audit-probe-capture.py client-cleanup-200-50-F
```

Expected gate result: `pass=true`, empty `errors`, exit 0; the capture audit finds all 1,910 health starts completed.

Replay the final normal pair:

```sh
python3 shutdown-deadline-200-50-F/gate.py shutdown-deadline-200-50-F 200 114400 57200 170 32 > shutdown-deadline-200-50-F/replayed-evidence.json
python3 audit-probe-capture.py shutdown-deadline-200-50-F
python3 shutdown-deadline-700-50-F/gate.py shutdown-deadline-700-50-F 700 400400 200200 600 32 > shutdown-deadline-700-50-F/replayed-evidence.json
python3 audit-probe-capture.py shutdown-deadline-700-50-F
```

Both gate results are `pass=true`, empty `errors`, exit 0; all 1,910 and 2,027 health starts respectively match completed rows. These commands only read retained instruments. Export verification ran the unchanged checker against a decompressed public copy and compared the entire JSON result, including every warning classification, with the original result.

## Fresh measurement

For the final pair, use a clean checkout of `a227c61e1b22f4601c0d40bdf335a7006ad0b6a5` at `/tmp/readiness-source` and the scripts from `shutdown-deadline-200-50-F/`. Other cells identify their own recorded source revisions. Keep build caches under `/tmp/readiness-build-cache`, and copy `run.sh`, `gate.py`, `snapshot.py`, and `build-receipt/build.sh` to `/tmp/readiness-acceptance-prep`. The build script accepts only its documented cache symlinks or a complete prior private executable stage; for a fresh checkout create `target` and `bench/scale/target` symlinks pointing to the corresponding existing directories under `/tmp/readiness-build-cache`.

Run the retained build script with a new absolute receipt directory:

```sh
bash /tmp/readiness-acceptance-prep/build.sh /tmp/readiness-build-new
bash /tmp/readiness-acceptance-prep/run.sh 200 /tmp/readiness-200-new /tmp/readiness-build-new
```

The build captures fresh hashes and source inventories, saves immutable executable copies outside the caches, and stages only those executables. Run builds and measurements sequentially, with no competing build or lab. Rebuilt executable bytes require fresh provenance; the old hashes are identifiers, not a promise of bit-for-bit reproduction.

The normal 700-member runner additionally requires the passing 200-member output from the same source and exact executable hashes. Its larger workload is 400,400 routes, 200,200 per family, with 600 changed and 100 stable observers:

```sh
bash /tmp/readiness-acceptance-prep/run.sh 700 /tmp/readiness-700-new /tmp/readiness-build-new /tmp/readiness-200-new
```

The wrapper preserves admission, timeout, and cooldown. An interrupted run requires cleanup of its owned processes; a timeout is not success. The initial three cells have no explicit daemon wait exit. All later attempts retain it, along with distinct native harness/cleanup/cell results in `driver.log`. No standalone outer-wrapper exit file is recorded for these cells. The initial runner left the normal 700-member capture gap described above. Later probe joining repairs that lifecycle, and the capture audit still checks each recorded health start against a completion.

To reproduce the separate characterization after a passing normal 200-member run, copy `diagnostic-700-50-F/run-diagnostic.sh` to `/tmp/readiness-acceptance-prep`, build a new diagnostic stage, and use its wrapper:

```sh
bash /tmp/readiness-acceptance-prep/build.sh /tmp/readiness-diagnostic-build-new diagnostic
bash /tmp/readiness-acceptance-prep/run-diagnostic.sh /tmp/readiness-diagnostic-700-new /tmp/readiness-diagnostic-build-new /tmp/readiness-200-new
```

The diagnostic wrapper checks the passing normal 200-member source identity, while recording its own diagnostic executable hashes. Restore and verify the normal executable bytes before any subsequent normal measurement.
