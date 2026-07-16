# Revision-reproducible RIB rebaseline

This directory pins the CPU-phase and live-heap component mappings used by a
replacement for `docs/perf/rebaseline-2026-07.md`. The historical July tables
remain useful decision evidence, but their harness and measured daemon did not
come from the same revision and their raw inputs were not archived. A new
receipt is valid only when every measured binary and the harness are built from
the SHA recorded in its manifest.

## Cheap checks

From the repository root:

```text
cargo fmt --manifest-path bench/scale/rrharness/Cargo.toml -- --check
cargo fmt --manifest-path bench/scale/reloadstall/Cargo.toml -- --check
cargo test --manifest-path bench/scale/rrharness/Cargo.toml --locked
cargo test --manifest-path bench/scale/reloadstall/Cargo.toml --locked
python3 bench/scale/rebaseline/test_classifiers.py
```

CI runs this exact gate. The fixtures exercise every CPU phase and every DHAT
component, including ownership-sensitive Adj-RIB-In versus group-table trie
allocations, plus the bounded same-run bgperf2 CSV sanitizer.

## CPU classifier

`classify_cpu.py` accepts rrharness's tab-separated folded format. Stacks are
root to leaf. Only the `ribmgr` thread is counted. The classifier walks each
stack leaf first; the first owning-function marker wins:

| Phase | Owning markers |
|---|---|
| exact encode | `probe_exact_export_announcements` |
| ceiling reuse | `reuse_grouped_exact_export_ceiling` |
| overlay reconciliation | `reconcile_exact_export_overlay` |
| group-prior materialization | `materialize_clean_group_prior` |
| channel enqueue | `enqueue_outbound_update` |
| group-table commit | `GroupRibOut::apply_delta`, `GroupRibOut::apply_vpn_delta` |
| member-emit | `emit_group_deltas_for_member`, `emit_vpn_group_deltas_for_member` |
| event-publish | `publish_route_event`, `publish_best_change_events` |
| shared-emit build | `build_shared_emit` |
| staging eval | `distribute_single_best_prefix` |
| staging walk | `stage_group_prefixes`, `stage_update_groups` |
| recompute | `recompute_best_after_announce`, `recompute_best_after_withdraw`, `recompute_best`, `LocRib::recompute` |
| distribute residual | `distribute_changes` |
| ingest + Adj-RIB-In insert | `AdjRibIn::insert`, `process_announce_chunk`, `process_withdraw_chunk`, `process_next_route_chunk` |
| other | no marker matched |

The leaf-first walk is load-bearing. For example, a sample whose stack contains
`process_next_route_chunk`, `recompute_best`, and `publish_route_event` belongs
to event-publish, not ingest or recompute.

rrharness encodes literal `%` as `%25` and literal `;` inside a demangled
symbol as `%3B` before aggregation (for example, `[u8; 32]` becomes
`[u8%3B 32]`). Tabs and newlines still fail closed. This makes valid Rust array
symbols unambiguous without allowing two raw stacks to collide after escaping.

```text
python3 bench/scale/rebaseline/classify_cpu.py \
  receipts/churn-1000-a.folded \
  --output receipts/churn-1000-a.cpu.tsv
```

The output always contains all phases in the table order, integer samples,
six-decimal shares, and an exact total.

## DHAT classifier and sanitized derivative

`classify_dhat.py` accepts DHAT JSON format v2 and sums the `gb` field: bytes
live at the process-wide heap maximum (`t-gmax`). DHAT stores frames leaf to
root, so the same first-owner rule applies. Some allocations share a leaf
implementation; the classifier uses the owning stack to distinguish:

- `prefix_trie`/`FamilyPrefixMap` under `AdjRibIn` from the same code under a
  `GroupRibOut`/`AdjRibOut` group-table commit;
- `AdjRibOut` under `GroupRibOut` from a true per-peer Adj-RIB-Out;
- `RouteSlab` under `AdjRibIn` from other RIB allocations.

The remaining direct owners are `LocRib`, `remember_known_path`,
`register_unicast_announcer`, `ImportDecisionCache`, transport read/write
buffers, daemon constructors, API/peer-manager, RIB, and telemetry/tokio/rest.
Anything without a committed owner is reported as `other`; do not silently add
it to the nearest-looking component.

Raw DHAT JSON contains instruction addresses, command arguments, and source
locations and must not be committed. `--derivative` aggregates every positive
allocation point by component plus symbol-only leaf-to-root stack. It strips
addresses and locations, fails closed on an unrecognized frame, and is
deterministic. Generation immediately reparses and reclassifies the derivative;
capture fails if it cannot reproduce the raw profile totals.

```text
python3 bench/scale/rebaseline/classify_dhat.py dhat-heap.json \
  --output receipts/2p-100k.memory.tsv \
  --derivative receipts/2p-100k.dhat-derivative.tsv

python3 bench/scale/rebaseline/classify_dhat.py \
  --from-derivative receipts/2p-100k.dhat-derivative.tsv \
  --check receipts/2p-100k.memory.tsv
```

The derivative is capped at 10,000 aggregated rows and 8 MiB by default. The
classifier aborts before writing any derivative if either limit is exceeded;
raise a limit explicitly only when the manifest records that expanded command.
The `--from-derivative` check is the reviewer path: it validates canonical
ordering/aggregation, rejects paths and addresses, reclassifies every stack,
checked-sums the byte counts, and rebuilds the table without raw DHAT JSON.
DHAT symbol stacks use the same `%25`/`%3B` canonical encoding as CPU folded
stacks; derivative verification rejects any other percent escape.

## Loaded measurement gate

Use a clean checkout at the candidate SHA. Record `git status --porcelain` and
stop if it is non-empty. Build the daemon, DHAT image, and rrharness from that
checkout without copying binaries from another worktree. Before every loaded
run, wait until the one-minute load average is below `2.0`; record the value
immediately before launch. Do not publish a partial replacement table when the
host lacks the memory, kernel/tooling, or quiet-load window needed for all
shapes.

Build rrharness from the measured checkout with the committed standalone lock:

```text
cargo build --release --locked --manifest-path bench/scale/rrharness/Cargo.toml
```

The bgperf2 DHAT image builder must consume the same clean root checkout and
its root `Cargo.lock`, with cache disabled. Record the exact image-build argv,
the resulting immutable image digest, and the bgperf2 `git rev-parse HEAD` (or
an exact packaged version). A mutable image tag is not artifact identity.

Run each CPU shape twice:

```text
for run in a b; do rrharness flood 256  100000 20 "receipts/flood-256-$run"; done
for run in a b; do rrharness flood 1000 100000 20 "receipts/flood-1000-$run"; done
for run in a b; do rrharness churn 256  256  3000 20 "receipts/churn-256-$run"; done
for run in a b; do rrharness churn 1000 1000 3000 20 "receipts/churn-1000-$run"; done
```

The loops are command-line shorthand only. Record each of the eight expanded
rrharness argv lists separately in the manifest, with the concrete `-a` or `-b`
output stem.

Run the DHAT/bgperf2 `2 peers x 100000 prefixes` shape from
`docs/BENCHMARKS.md` once after convergence. Archive its classified table,
sanitized derivative, and a sanitized same-run bgperf2 CSV. The CSV and DHAT
derivative must describe the same daemon process/run; a nearby RSS run is not
equivalent.

Capture bgperf2's printed header plus result row to a temporary raw CSV, then
reduce it to the fixed receipt schema:

```text
python3 bench/scale/rebaseline/sanitize_bgperf_csv.py /tmp/2p-100k.raw.csv \
  --output receipts/2p-100k.csv
python3 bench/scale/rebaseline/sanitize_bgperf_csv.py /tmp/2p-100k.raw.csv \
  --check receipts/2p-100k.csv
```

The sanitizer accepts exactly one header and one result row (16 KiB input,
4 KiB output), the pinned rustbgpd 2x100k shape, convergence with zero tester
errors/timeouts, and an allowlisted set of numeric metrics. It rejects schema
drift, extra fields, paths, process/container-like IDs, filters, and failed
runs. The current bgperf2 schema emits an unlabeled `tester_timeouts` data
column; the sanitizer pins the known 24-label/25-value shape from
`jauderho/bgperf2` commit
`17216483e779f1484ef38562fb8f6b5ea6ad4d8f` explicitly so an upstream fix
cannot silently shift columns. Never commit the unsanitized temporary CSV.
Review the committed artifact without the raw capture using:

```text
python3 bench/scale/rebaseline/sanitize_bgperf_csv.py \
  --from-sanitized receipts/2p-100k.csv >/dev/null
```

This validates structure, schema, convergence, bounds, and canonical form
only; without the raw capture the numeric values themselves are unanchored.

## Receipt artifact contract

Use a dedicated directory and stable names:

- eight `*.folded` CPU profiles and eight `*.cpu.tsv` classified tables. The
  folded inputs may be retained in one deterministic compressed tar archive
  when the receipt also carries the archive hash and a checksum for every
  extracted member;
- `2p-100k.memory.tsv` and `2p-100k.dhat-derivative.tsv`;
- the sanitized same-run `2p-100k.csv`;
- `manifest.json` and `SHA256SUMS`.

The manifest records at least:

```json
{
  "source_sha": "40 lowercase hex digits",
  "tree_clean": true,
  "commands": ["exact argv for every build and run"],
  "host": {"cpu": "model", "memory_bytes": 0},
  "kernel": "uname -srvm",
  "build": {"rustc": "rustc -Vv", "profile": "release / release-prof+dhat-heap"},
  "executables": {
    "rrharness_sha256": "hash of target/release/rrharness",
    "daemon_sha256_or_image_digest": "sha256:..."
  },
  "bgperf2": {"revision_or_version": "40 lowercase hex digits or exact version"},
  "memory_run": {
    "id": "rib-memory-YYYYMMDDTHHMMSSZ",
    "started_utc": "YYYY-MM-DDTHH:MM:SSZ",
    "bgperf_launch_argv": ["python", "bgperf2.py", "bench", "-t", "rustbgpd", "-n", "2", "-p", "100000"],
    "sigterm_argv": ["exact argv using the stable target name, never a PID/container ID"],
    "copy_argv": ["exact argv used to extract dhat-heap.json"],
    "classify_argv": ["exact classify_dhat.py argv"],
    "csv_sanitize_argv": ["exact sanitize_bgperf_csv.py argv"]
  },
  "load_before_each_run": {"artifact stem": 0.0},
  "classifier_sha256": {"classify_cpu.py": "...", "classify_dhat.py": "..."}
}
```

Record exact commands as arrays or losslessly quoted strings. Do not include
usernames, home-directory paths, container IDs, process IDs, environment
secrets, or raw command lines copied from DHAT. `memory_run.id` is the UTC start
stamp with the fixed `rib-memory-` prefix; `started_utc` is the same second in
RFC 3339 `Z` form. Use that one ID for the raw CSV capture, DHAT extraction,
sanitized CSV, derivative, and memory table, and record the exact launch,
SIGTERM, copy, classify, and sanitize argv. This associates both committed
views with one process without persisting ephemeral PIDs or container IDs.
Finally run `sha256sum` over
every archived artifact (including the manifest) in byte-sorted filename order
and commit the resulting `SHA256SUMS`. Re-run the CPU classifier against each
folded profile and the DHAT classifier in `--from-derivative` mode with
`--check <committed-table>`, and re-run the CSV sanitizer against the temporary
raw capture with `--check receipts/2p-100k.csv`, before accepting the receipt.
