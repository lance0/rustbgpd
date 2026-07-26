# Cross-stack bgperf2 campaign artifacts — 2026-07

Retained artifacts for
[`competitive-bgperf2-2026-07.md`](../../competitive-bgperf2-2026-07.md): a
four-way rustbgpd / BIRD / GoBGP / FRR comparison across five fleet shapes,
three runs each, on one host through one harness.

Every published median in the receipt is recomputed from `raw/`. Every
establishment-versus-flood progression is read from `logs/`.

## Contents

| Path | What it is |
|---|---|
| `INDEX.txt` | The campaign's own index, written during the run. It also describes material that is **not** retained here — see "What was dropped" below. |
| `openbgpd-defect.txt` | Root cause for the uncollected OpenBGPD cell, verified live on the stuck container. |
| `config/phase{A,B}-run{1,2,3}.yaml` | The exact bgperf2 batch configs. Phase A covers 10×1k, 2×10k, 2×100k; Phase B covers 10×1k, 30×1k, 100×1k. |
| `config/quiet-gate.sh` | The idle interlock every run passed before starting: no hold lock, no `cargo`/`rustc`, one-minute load below 1.0, confirmed twice 30 s apart. |
| `config/run-phase.sh` | The phase driver: gate, then container/network cleanup, then a bounded batch run. |
| `raw/A{1,2,3}_*.csv`, `raw/B{1,2,3}_*.csv` | Raw bgperf2 stats, one row per (run, shape, daemon). The source of every median. |
| `logs/phase{A,B}-run{1,2,3}.log.gz` | Full harness transcripts including the per-second `mon recved` / `neighbors_accepted` progressions. |
| `logs/phaseA-run1-ABORTED-openbgp-hang.log.gz` | The aborted five-way attempt, retained as the evidence behind the OpenBGPD exclusion. It ends mid-`Waiting 674 seconds for monitor`. |
| `logs/chain.log`, `logs/chain3.log` | Phase sequencing with the quiet-gate admission decisions and the load average at each one. |
| `logs/image-build.log.gz` | The `nocache` Docker build of the measured target image. Contains zero `Using cache` lines, which is what makes the no-cache claim checkable. |

## What was dropped, and why

`INDEX.txt` was written against the full 2.3 GB campaign directory. Three
parts of it are deliberately not retained:

- **`src/`** — a git-archive export of the measured commit (1,918 files) plus
  its `target/` build tree, roughly 2.3 GB and the bulk of the campaign
  directory. The commit is named in the receipt and recoverable from the repo,
  so shipping a second copy buys nothing.
- **159 saved Criterion baselines** under `src/target/criterion/`. These belong
  to microbenchmarks, not to this cross-stack comparison, and are regenerable.
- **Phase D** (`phaseD/`, `logs/phaseD*.log`, `meta/run-phaseD.sh`) — an MRT
  snapshot-allocation measurement that shared the campaign window but is a
  different question with its own receipt,
  [`mrt-snapshot-allocation-2026-07.md`](../../mrt-snapshot-allocation-2026-07.md).

Nothing behind a published number was dropped. The retained set is 148 KiB
against a 2.3 GB source.

## Sanitization

Local checkout paths were rewritten before retention: the harness checkout to
`<bgperf2>`, the campaign scratch directory to `<scratch>`, and any remaining
home directory to `<home>`. The plain files and the gzipped contents were both
swept for the host name, home paths, and user names; the host name never
appeared.

CPU model, core count, RAM, kernel version, and the daemon version strings are
retained verbatim — they are part of the measurement, not identifiers.

One deliberate exception: `openbgpd-defect.txt` retains `/root/config/bgpd.conf`
and `/root/config/openbgp.log`. Those are paths *inside* the third-party
OpenBGPD container image, not host paths, and they are the substance of the
root cause.

`SHA256SUMS` covers the retained, sanitized bytes.
