# Prestaged transition inventory A/B — 2026-10-04

Building the clean export-policy transition inventory before the RIB fence
(#2930) cut fenced BuildInventory time from a 173.2 ms to a 28.1 ms median and
changed-observer stall p50 from 364.9 ms to 208.3 ms on the 700-peer S2 reload
matrix leg, in instrumented builds measured on 2026-10-04.

This receipt was published retroactively on 2026-10-10 from the retained raw
data of that run. It is the measurement behind the v0.75.0 CHANGELOG entry for
#2930 (merged as `aceacb435677291fdb20c2e792f58cb9e4575b74`).

## What was measured

**Shape.** S2 reload-stall matrix leg: 700 peers, all 700 changed, 400,400
prefixes, a 30-second control window and four SIGHUP policy reloads per process
alternating between two generated export policies. Native loopback, no added
delay or reader pacing. Every reload kept 700 sessions up with zero parse
errors, and every transition committed for 700 members.

**Arms.** Both arms start from main at
`65aa92cc017e0905584563d9041f17f7ecdbb06c` (tree
`41593a9ad40bb982c752ba3d219aead2df71fe18`):

| Arm | Source | Daemon sha256 |
| --- | --- | --- |
| main | base + `instrumentation.diff` | `ab8a5902eb2c6c908cbd66b1dd90d7df1fc3ea580627dab2674ac5b47a365ea1` |
| fix | base + `fix.diff` + `instrumentation.diff` | `ef83eae041e4301ced7a11046a12f61445399304ec89a3db68a500f7bf43b833` |

**Both are instrumented builds.** `instrumentation.diff` adds an info-level
log line for every poll of the RIB transition (phase, poll duration, terminal
flag, primary backlog) and a per-observer `scout_gap` line to the `reloadstall`
harness. It is not part of #2930 or of main, and its overhead was not measured
against an uninstrumented build. Both arms used the same harness binary
(`7651f049971e3c0ccb909457db1465e87305b043de6302e1cf4b80c2a80d0884`), built
once in the main-arm tree.

`fix.diff` is byte-identical to the `crates/` changes of
`18b6c81fe577842b16eb3c2590eefd42a08e9a6d`, the first commit of #2930. The two
later PR commits, which retire a prestaged inventory on more discard paths,
and the squash merge onto a newer main were not measured. Rebuilding the main
arm from the committed diffs reproduces the recorded fingerprint of that
worktree's uncommitted diff. The fix-arm reconstruction does not reproduce its
recorded fingerprint, so the exact fix-arm source bytes are not independently
verified from retained material; the daemon digest above identifies the
binary that ran. Details are in
[provenance.json](artifacts/prestaged-transition-inventory-2026-10/provenance.json).

**Method.** Each arm was built in its own Cargo target with
`cargo build --release --locked -p rustbgpd --bin rustbgpd` (Rust 1.99.0,
default features). Six process legs ran in **ABBAAB** order (main, fix, fix,
main, main, fix) from 20:34:54 to 21:08:01 UTC, each through
`bench/scale/matrix/run-matrix.sh rustbgpd` with the native S2 inputs. Each leg
held the shared host lock and passed two host-quiet samples (load 1.09–1.87,
all 64 governors in performance mode, no competitors, unchanged swap
counters); the daemon cgroup ran with `memory.swap.max=0`. The wrapper cut the
runner's 300-second post-cell cool-down; the next leg instead waited for the
host lock, which took between zero and about five minutes. The host was a
64-thread x86_64 workstation on Linux 7.0.0-30-generic.

## Results

Median [range] over 12 reloads per arm (VmHWM: over three legs per arm).

| Metric | main | fix |
| --- | ---: | ---: |
| Destination prestage round trip, unfenced (ms) | 316 [290–335] | 448 [391–482] |
| Fence span: classify start to commit end (ms) | 335.4 [318.5–373.2] | 185.6 [183.6–210.4] |
| RIB export-policy transition `elapsed_ms` | 335 [318–372] | 185 [183–210] |
| BuildInventory busy under the fence (ms) | 173.2 [163.7–220.1] | 28.1 [25.9–53.1] |
| BuildInventory polls per reload | 7 [7–9] | 1 [1–1] |
| Changed-observer stall p50 (ms) | 364.9 [343.2–401.6] | 208.3 [198.9–231.8] |
| Changed-observer stall p95 (ms) | 448.8 [389.3–543.9] | 288.6 [240.8–382.1] |
| Worst observer stall (ms) | 528.3 [432.3–561.9] | 370.9 [285.7–405.3] |
| Completion p50 (ms) | 857 [828–903] | 846 [776–892] |
| First-generation UPDATE p50 (ms) | 712 [686–768] | 700 [645–758] |
| Base-prefix UPDATEs per member, median observer | 893 [893–893] | 893 [893–893] |
| VmHWM per leg (MiB) | 567 [558–571] | 570 [559–571] |

Per-leg medians show the separation holds in every launch. Stall p50 was
359.1, 376.8 and 360.6 ms for the three main legs and 207.9, 211.2 and
208.7 ms for the three fix legs. BuildInventory time was 170.3, 171.1 and
176.5 ms against 27.3, 29.7 and 28.1 ms. In each main leg, the first reload
had the highest fence span and BuildInventory time.

Every fix-arm reload committed through the prestaged inventory, with a single
BuildInventory poll. The walk's cost moved into the unfenced destination
prestage, whose round trip grew by a median of 132 ms, while route churn
continued between its slices. Completion and first-generation UPDATE medians
moved by 11 and 12 ms with overlapping ranges, and every member received the
same number of base-prefix UPDATEs in both arms.

## Relation to public wording

The v0.75.0 CHANGELOG says that on this leg "the fenced inventory step fell
from about 173 ms to 28 ms and the per-observer stall p50 from about 365 ms to
208 ms", with completion time, UPDATEs per member and VmHWM unchanged
(3 × 4 reloads per arm). Those figures are the 12-reload medians above,
rounded. They come from instrumented builds of the first #2930 commit, and
the "fenced inventory step" is the instrumentation's summed BuildInventory
poll time. "Unchanged" summarizes overlapping ranges; this run does not test
equivalence.

The #2930 PR-body table used the harness's two-decimal summary lines. With
that rounding, `recompute.py` reproduces the PR's cells, including completion
p50 860 [830–900] and 845 [780–890] ms and a fix-arm worst-stall maximum of
405.4 ms. The table above uses the native CSV precision.

Later attribution work quoted the RIB transition `elapsed_ms` as main
318–377 ms against fix 183–210 ms. In this run, main's values span 318–372 ms
and the fence span from poll timestamps spans 318.5–373.2 ms; 377 ms does not
occur among these 24 reloads and comes from a different run. The fix-arm range
matches.

## Does not establish

- **Uninstrumented behaviour.** Both daemons logged every transition poll, and
  the instrumentation's own cost was not measured.
- **The merged code.** The fix arm is the first #2930 commit on its original
  base, not `aceacb435` with its follow-up commits on a newer main.
- **Other shapes.** Only the all-peer S2 leg on loopback was measured: not S3,
  partial changes, dual-stack, added RTT, reader pacing, other peer or prefix
  counts, or another host.
- **Statistical significance.** Three launches per arm; the four reloads in a
  launch are correlated. Every main reload had a longer fence span, more
  BuildInventory time and a higher stall p50 than every fix reload, but no
  confidence interval is claimed.
- **Completion, memory or CPU improvement.** Completion and VmHWM ranges
  overlap, the unfenced prestage grew, and CPU time was not recorded.
- **Where the remaining 28 ms goes.** `scan-microbench.txt` keeps the single
  local microbenchmark run that the PR body used for that attribution; its test
  is not in the repository, and this A/B does not measure it.

## Evidence

The [compact artifacts](artifacts/prestaged-transition-inventory-2026-10/README.md)
contain every reload row, every transition poll, per-leg identity and quiet
checks, both diffs, the driver scripts and logs as recorded (private paths
replaced). The raw directory with full daemon and harness logs is not
published. From the repository root:

```bash
python3 docs/perf/artifacts/prestaged-transition-inventory-2026-10/recompute.py
```
