# Reload boundary attribution evidence

Complete compact evidence for the
[failed receiver/publication measurement method](../../reload-boundary-attribution-2026-10.md).

**Overhead failed; production attribution is unqualified.** All six processes,
24 native rounds, 16,800 observer outcomes and 8,400 exact first-frame joins are
retained. Both changed-gap stall estimators exceed the unchanged 2% regression
bar. No retry or runtime optimization was selected.

## Reproduce the receipt

From this directory, with Python 3.11 or later (the ownership tests require Linux):

```sh
sha256sum -c SHA256SUMS
PYTHONDONTWRITEBYTECODE=1 python3 recompute.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -p 'test_*.py' -v
```

The reader verifies the public manifest, reads only declared regular members of
`native-records.tar.gz` into a temporary directory, and checks each member's
normalized hash. It rejects symbolic links, absolute paths, parent traversal,
missing/extra entries and duplicates. It then rechecks native metadata, all
outcomes and tied maximum-gap spans, exact publication/writer/frame joins,
clock bounds, both overhead estimators and separated phase diagnostics. The
recomputed result must exactly match `results.json`, after JSON key
normalization; the 24 rows in `rounds.csv` must match the native logs.

The original receiver reader and its public lint-clean version are both run on
all six complete extracts, and their full analysis results must agree directly.
The only runtime reader delta replaces an unused `(round, peer)` destructuring
loop with iteration over its values. Three companion files also lose an unused
import. `public-reader.patch` records those changes; `executed-*.py.txt` preserves
the exact executed originals. There is no claim that changed public bytes were
used during the measurement. The public diagnostic adapter preserves the
independent post-campaign analysis calculations, omitting raw-identity/hash
metadata already represented by the bundle's provenance.

## Contents and bindings

| File | Purpose |
|---|---|
| `plan.json` | Executed source, workload, six-process order, bounds and unchanged acceptance bars. |
| `rounds.csv` | All 24 native aggregate rows, including per-round p50, p95 and maximum values. |
| `native-records.tar.gz` | All six filtered native logs, three publication traces and compact execution metadata: 123 files. |
| `native-extraction.json` | Original and normalized hashes for every archived member, with its exact filtering/normalization rule. |
| `results.json` | Complete recomputed overhead, per-round summaries, phase ranks, tied-gap associations, encoder records and tail cohorts. |
| `execution-receipts.json` | Source-snapshot equality, raw ownership/check hashes, cleanup receipts and full external archive binding. |
| `build-bindings.json` | Exact executed frozen producer/binary binding, including source, default features, allocator, native helpers and build receipt hashes. |
| `dependency-graph-comparison.json` | Equality across 345 selected semantic dependency nodes and their settings/edges. |
| `execution-methods.sha256` | Exact original execution manifest, using its original relative paths. |
| `method-bindings.json` | Executed/public method hashes, explicit modified-reader mapping and external method roster. |
| `recompute.py`, `diagnostics.py` | Public bundle validation and independent post-campaign diagnostic calculations. |
| `analyze_receiver.py`, `read_publication.py`, `qualify.py`, `collect_campaign.py` | Frozen-method parsing, join, metadata and Decimal qualification logic, with the explicit lint delta above. |
| `test_*.py` | Semantic negatives for joins, clocks, provenance, partial writes, method gates, tied maxima, safe archive reading and public bundle integrity. |
| `SHA256SUMS` | Integrity of the public files; separate from the executed method manifest. |

The executed source is `49abbb0171cbb889b7e2618c2bdcec6ea35699ae` (tree
`c70b6296af9880d350acea376eb1942ba8dbc72d`), including merged
[PR #2952](https://github.com/lance0/rustbgpd/pull/2952). The method manifest hash
is `b28669ef45471c6ea885f8635d4adccc6b329cf6409d887198357386a905b632` and the
frozen binary binding hash is
`c74744cb4f5ddbce45cc29a1d4cd70e81ccc81c9f8f663e62d5d5b896c819def`.
The control daemon has no runtime probe. Both harnesses retain identical common
post-round outcome, maximum-gap and clock reporting; receiver capture is absent
from the control. The daemon build command, default features, allocator and
linked dependency settings match across arms. Build-source and execution-source
snapshots are separately bound.

The full external archive is identified logically as
`campaign-01-null-complete.tar`, SHA256
`1897fda58b1cce23ae03f06f8229b7b2bb358458b43add4357c7677f16d1d69b`. Its 609
entries retain source patches, producer/build receipts, preparation and smoke
failures, startup failure, all six successful full legs, and raw lifecycle
records. The archive is not included in this public bundle. Its hash identifies
retained bytes; it does not make those omitted bytes publicly auditable.

## Preparation and startup history

The retained failures were resolved before the single complete canonical
campaign. They remain in the full archive and in `execution-receipts.json`;
none was selected or discarded based on a canonical performance result.

| Stage | Outcome and disposition |
|---|---|
| Earlier source preparation | The `c4639d757` preparation was superseded by the runtime merge before any smoke or full attempt. |
| Smoke 01 | Harness trace emission was suppressed by an optional evidence-directory early return; changed-gap and all-window-gap reconstruction also needed correction. Bounded preparation fixes preceded the canonical campaign. |
| Smoke 02, probe | CSV stderr interleaved with JSON stdout, corrupting trace records. The full cooldown was retained. Deferred writer output moved to the same stdout stream, and only the probe daemon was rebuilt before the final method/binary freeze. |
| Smoke 03, probe | Full joins and cooldown passed under the final frozen method. |
| Smoke 04, control | A copied daemon had mode `0644`; startup exited 126 before a measured interval. Restoring mode `0755` did not change binary bytes. |
| Smoke 05, control | Complete common outcomes, clocks and cooldown passed; no receiver capture rows appeared. |
| First canonical wrapper invocation | A relative-path invocation was rejected before startup or a native interval. It was retained separately, then the same wrapper launched by its absolute path. |
| Campaign 01 | All six processes and 24 native rounds completed with full cooldowns, successful collector/outer exits and cleanup. Both stall-overhead bars failed. No measured retry followed. |

The smoke cells validate emitters and lifecycle only. Their timings are excluded
from the canonical comparison. The final method and binary hashes above bind
all six campaign legs; the preceding preparation corrections did not relax any
overhead, coverage, clock, cooldown or repeatability requirement.

## Normalization and evidence limits

All native aggregate, outcome, changed-gap, all-window-gap, receiver, clock,
writer and partial-write rows are retained. Unrelated process log lines are
omitted. Synthetic `127.1.*` addresses identify fixture peers. Publication
allocation addresses become stable integer aliases within each process; process,
process-group, session and boot identifiers become consistent campaign aliases.
Native monotonic times, real-time clock anchors, byte ranges, source exclusions,
peer/round identities, statuses and both maximum-gap definitions are preserved.
The filtered runner transcript retains native start/pass timestamps and the
300-second cooldown witness; its path-only completion destination is normalized.

The existing collector checks the declared compact source/binary/helper
bindings, native quiet samples, process relationships/order, and wall/monotonic
cooldown chronology. All six legs retain zero exit statuses for the recorded execution stages;
external cleanup receipts describe the observed completed run. Public
aliases cannot independently authenticate actual OS process identity or cleanup.
Hashes of omitted source snapshots, producer logs and raw ownership witnesses
cannot independently establish binary/source equality or prove extraction from
those raw bytes. Those assertions were checked against the retained full
archive; the public reader's claims stop at the available compact evidence.
`joined_rows_sha256` in the result binds the normalized 8,400-row join generated
by the reader, not the original allocation addresses.

All hot-path timestamps use a process monotonic origin. Publication timestamps
use `origin.elapsed() + 1 ns`; the reader removes that offset when mapping the
clock. Receiver/daemon offsets remain intervals derived from monotonic/real-time
brackets. Start/end agreement does not rule out every intermediate wall-clock
adjustment. Signed accepted-write-to-read-poll bounds remain signed. A successful
read poll identifies userspace execution, not kernel readiness or OS runnable
time. Both endpoints of all 8,400 frames arrived in the same read, so overlapping
first/last-byte measurements must not be added.

The diagnostic preserves every maximum-span tie and every observer at a worst-5%
cutoff, with the encoder separate from followers. Changed-gap windows end at
observer completion; all-window gaps include trailing round time. Only first
expected-generation frames are traced. The broad follower ranking changes
between processes; the narrower matched worst-5% gap-intersection ranking
repeats at process level but only in nine of twelve rounds. Failed overhead
prevents either diagnostic from establishing a production cause or gain.
