# History-recording settlement evidence (2026-10-06)

This compact bundle supports the [dated receipt](../../history-recording-settlement-2026-10-06.md).
It retains the complete six-process A/B in A–B / B–A / A–B order, with four
reloads per fresh process. The predeclared process-leg range criterion was
not met; both process-leg and raw-round ranges overlap. No row, first reload
or process leg was excluded.

| File | Contents |
| --- | --- |
| `rounds.csv` | All 24 paired SIGHUP operation IDs, trigger/complete/settled epoch nanoseconds, elapsed milliseconds, every numeric receiver field, settlement acknowledgement counts and withdrawal checks |
| `legs.json` | Six legs, each with medians for all 17 reported metrics, the 30-second control, memory, both quiet samples, full cooldown, health, actual exits, process identities and five V2 history scalar records |
| `provenance.json` | Fixed shape/order/criterion and result flags, exact measured sources/trees/default daemon binaries, reused helper producer provenance, build-log hashes/exits, dataset/script hashes, final cleanup facts and separate failed-attempt/diagnostic summaries |
| `SHA256SUMS` | Checksums for this README and the three data files |

## Units and joins

CSV `*_ns` fields are epoch nanoseconds. Elapsed daemon timings and stalls
use milliseconds; receiver completion fields use seconds; receiver RSS uses
MiB. Process `starttime` is the raw Linux `/proc` clock-tick value, not an
epoch timestamp. Each leg has its own operation IDs 1–4. Join CSV rows by
`arm`, `leg` and `reload`; history sequence `reload + 1` is the corresponding
append. Sequence 1 is startup, so its `reload_window_match` is null.

Each leg's `metric_medians` is the median across its four reloads. The receipt's
summary is the median across three process-leg medians per arm. Twelve reloads
per arm are correlated observations within three processes, not twelve
independent samples. Raw ranges and the process-leg ranges are separate.

Memory values named `*_kib` retain the Linux kB readouts as KiB; swap maximum
uses bytes. The memory window is `through_harness_completion;diagnostic_only`,
including daemon VmHWM/VmRSS and whole-cgroup peak/current/swap. It does not
cover the full daemon lifetime. Cgroup CPU is null and explicitly unavailable;
the unchanged cell did not capture `cpu.stat`. Quiet swap-in/out fields are
cumulative host counters; the two samples show no delta. Daemon cgroup swap
maximum and peak are zero.

The completed diagnostic's `successful_durability_union_ns` preserves the
analyzer's field name for the selected successful sync/rename interval union.
It is syscall overlap coverage, not proof that the gap is required durability.
Its residual remains unassigned, and none of its traced or control rows enters
the six-leg A/B pool.

## Provenance and privacy boundary

The measured runtime candidate is commit
`6bbc0a1e1b44df7a9b325f95762ed2da8a81c432`, tree
`0e8958dac582c6af8d6216de2a2a34ba228da4ab`, with a freshly built
default-feature daemon. Later documentation commits do not change that
identity. Both arms consume the same baseline-produced renderer and scale
harness. The candidate's per-component provenance retains their original
producer commit, tree, build commands, successful exits and log/receipt
digests. A copied harness is not a candidate scale build.

The scalar extraction read the completed report plus retained raw milestone,
receiver, history, quiet, cooldown, cleanup, process and build evidence. It
compared all 24 raw rows and all 17 metric summaries, and independently checked
each history filename/header identity, normalized-TOML digest, frozen envelope
digest and reload timestamp window. These checks do not claim to rerun every
native history reader validation.

Only history version, sequence, timestamp, byte counts, opaque digests and
those scalar validation results are included. `source_sha256` fingerprints
the source manifest; `normalized_toml_sha256` fingerprints the separate UTF-8
TOML string. Full V2 envelopes, normalized TOML, canonical manifests, daemon
logs, raw configurations, private paths and build-log text remain outside the
repository. Original raw reports and failed-attempt receipts remain unchanged.
The public bundle cannot rerun full private validation or independently repeat
the owned launcher/daemon campaign from these compact files.

## Inspect

Verify the bundle from this directory:

```sh
sha256sum -c SHA256SUMS
```

Recompute the primary process-leg medians and criterion from the public rows:

```sh
python3 - <<'PY'
import csv
import statistics
from collections import defaultdict

legs = defaultdict(list)
with open('rounds.csv', newline='') as stream:
    for row in csv.DictReader(stream):
        legs[row['arm'], row['leg']].append(float(row['settled_elapsed_ms']))
arms = {arm: [statistics.median(values) for (a, _), values in legs.items()
              if a == arm] for arm in ('A', 'B')}
print(arms)
print('criterion_met:', max(arms['B']) < min(arms['A']))
PY
```

This reproduces the primary aggregate from the scalar evidence. It does not
reconstruct omitted private inputs or the full raw validation.
