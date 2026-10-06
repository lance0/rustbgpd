# First survivor UPDATE phase extracts

Compact evidence for the [October 2026 phase attribution](../../first-update-phase-attribution-2026-10.md).
All six process legs, 18 flap rounds, and 5,850 instrumented survivor-rounds are
retained. No endpoint sample was excluded.

- `rounds.csv`: all original six-decimal endpoint quantiles, extracted phase
  offsets, registration observations, and the exact marker/writer byte bracket.
  Control rows intentionally have empty diagnostic fields. `t0_wall_us` is the
  adjacent wall stamp for the harness's re-announcement trigger. Other phase
  offsets are signed microseconds relative to it; arrival fields use the existing
  harness event clock. Registration p50s are per-round medians over 50 members.
- `arrivals.csv`: published-first, affected-first and marker arrival elapsed
  microseconds for each of 650 survivors in each of nine probe rounds. Peers are
  logical harness indices; sample 350 is the correlated session/writer trace.
- `legs.json`: actual exits, native HTTP checks, accepted quiet samples, full
  cooldown timing, canonical workload inputs, binary hashes and freeze equality.
  Compact assertions preserve the audited result; auditing the underlying
  operations requires the raw logs.
- `provenance.json`: measured source, build commands, binary/helper/patch hashes,
  methods, archive identity, cleanup observations and limitations. The control
  daemon is unmodified; both harnesses share reporting-only precision changes.
  The probe and runner changes were local and are not committed runtime code.
- `archived-raw-sha256.json`: identities of 218 retained original files, using
  paths relative to the private archive root. The archive includes all raw logs,
  scenario copies, source patches, frozen binaries, build logs and validation
  receipts, including superseded preparation under `pre-review/`. Only the
  binaries selected by each leg's freeze were measured. The archive and original
  contents are not published; hashes alone do not audit their contents.
- `recompute.py` and `comparison.json`: endpoint medians, matched process-pair
  changes, per-round signed spans, phase observations and exact arrival
  correlations. The script validates round/observer coverage, quantiles, compact
  leg receipts, canonical workload, arm-specific binary/harness identities,
  clock agreement and marker byte brackets before computing.
- `test_recompute.py`: standard-library checks that the valid receipt passes and
  plausible missing/duplicate coverage, invalid writer brackets, nonfinite
  endpoints, shortened cooldowns, missing native checks, changed workloads and
  mismatched binary/harness hashes fail.
- `SHA256SUMS`: hashes of all other files in this artifact directory.

From the repository root:

```bash
(cd docs/perf/artifacts/first-update-phase-attribution-2026-10 && sha256sum -c SHA256SUMS)
python3 docs/perf/artifacts/first-update-phase-attribution-2026-10/recompute.py > /tmp/first-update-comparison.json
diff -u docs/perf/artifacts/first-update-phase-attribution-2026-10/comparison.json /tmp/first-update-comparison.json
python3 docs/perf/artifacts/first-update-phase-attribution-2026-10/test_recompute.py
```

Endpoint medians pool nine correlated round p50s per arm; the independent sample
count is three processes per arm. Pair order is AB / BA / AB. The harness uses
the upper middle value for a 650-observer p50; differences across those observers
use the ordinary statistical median. All interval medians are computed from
per-round differences, not by subtracting aggregate medians.

`matching_marker_signed_spans_us` covers the six rounds where the sampled marker
equals the first affected arrival. In those same six rounds equality holds at
all 650 survivors. The other three rounds remain in all-arm endpoint and all-nine
phase summaries. Published-first equals affected-first in every instrumented
survivor-round, but marker arrival does not always equal either.

The first encoder slice is from the survivor delta envelope containing the
marker; the slice itself need not contain it. Its producer can differ from the
sampled member. Admission and completion stamps may overlap other tasks, and
cross-process clocks have the documented alignment limits. No interval is
clamped and no additive serial-path claim is made. These extracts recompute the
reported arithmetic, not the instrumentation build or full raw extraction.
Observer arrival stamps follow complete-frame reading, decode, UPDATE parsing
and base-prefix classification; they are not kernel or packet-capture timestamps.
