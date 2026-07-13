# RIB rebaseline artifacts — 2026-07-13

This directory is the revision-pinned evidence for
[`rib-rebaseline-2026-07-13.md`](../../rib-rebaseline-2026-07-13.md). The
measured source is `4800061b178a84a7b62c74bf0b6a71c4e413b8f2`; the exact
environment, commands, load gates, image identity, and tool hashes are in
[`manifest.json`](manifest.json).

The eight raw pprof folded profiles are stored in the deterministic
`cpu-folded-profiles.tar.gz` archive. `folded-SHA256SUMS` authenticates each
member after extraction; the top-level `SHA256SUMS` authenticates the archive
and every other retained artifact. The corresponding `*.cpu.tsv` files are the
committed classifier output and `*.log` files are the harness result summaries.

The raw DHAT JSON and raw bgperf2 CSV are deliberately not committed because
they contain addresses, paths, and host-specific fields. The sanitized
`2p-100k.dhat-derivative.tsv` is sufficient to reproduce
`2p-100k.memory.tsv` with the committed classifier. `2p-100k.csv` is the
bounded same-process convergence/RSS view. The exact generated bgperf scenario,
daemon config, immutable image labels/digest, and builder/runtime package
inventories are retained alongside them. The two `bird-tester-*.log` files were
copied before the profiling SIGTERM; `bird-tester-scan.tsv` applies the pinned
adapter's `RMT`-excluding-`NEXT_HOP` error rule to those exact logs. bgperf2's
BIRD timeout field is structurally zero and is retained only as raw schema, not
claimed as independent timeout evidence.

Reviewer verification from the repository root:

```text
(cd docs/perf/artifacts/rib-rebaseline-2026-07-13 && sha256sum -c SHA256SUMS)
mkdir /tmp/rib-rebaseline-cpu
tar -xzf docs/perf/artifacts/rib-rebaseline-2026-07-13/cpu-folded-profiles.tar.gz \
  -C /tmp/rib-rebaseline-cpu
(cd /tmp/rib-rebaseline-cpu && sha256sum -c folded-SHA256SUMS)
for profile in /tmp/rib-rebaseline-cpu/*.folded; do
  stem=$(basename "$profile" .folded)
  python3 bench/scale/rebaseline/classify_cpu.py "$profile" \
    --check "docs/perf/artifacts/rib-rebaseline-2026-07-13/$stem.cpu.tsv"
done
python3 bench/scale/rebaseline/classify_dhat.py \
  --from-derivative docs/perf/artifacts/rib-rebaseline-2026-07-13/2p-100k.dhat-derivative.tsv \
  --check docs/perf/artifacts/rib-rebaseline-2026-07-13/2p-100k.memory.tsv
python3 bench/scale/rebaseline/sanitize_bgperf_csv.py \
  --from-sanitized docs/perf/artifacts/rib-rebaseline-2026-07-13/2p-100k.csv \
  --check docs/perf/artifacts/rib-rebaseline-2026-07-13/2p-100k.csv
```
