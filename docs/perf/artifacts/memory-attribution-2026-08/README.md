# Single-commit memory attribution 2026-08 — campaign evidence extract

Bounded evidence extract behind
[`../../memory-attribution-2026-08.md`](../../memory-attribution-2026-08.md).
Seven sealed campaign directories chained coarse → single commit; this
directory carries each one's **preregistered manifest**, its per-run
result table and verdict, its own seal roster, and the shared protocol
kit. The full roots (134 per-run bench logs, 1 Hz sample streams,
per-run `smaps`/`smaps_rollup` dumps, nocache build transcripts,
preflight boot transcripts, lane telemetry, rendered runtime manifests)
are retained read-only off-repo in the campaign artifact archive — tens
of MB of raw capture with no reviewable prose.

## Allocator-attribution erratum

Every measured phase image used jemalloc. The exact arm revisions
enabled jemalloc by default, the campaign Dockerfile explicitly built
`rustbgpd/jemalloc`, and the retained `build_A.log` records compilation
of the `tikv-jemalloc-*` crates. References in the frozen captures to a
"glibc allocator-arena" cause are therefore incorrect. The corrected
reading is a measured ±30–50 MiB anonymous/`Private_Dirty` residency
distribution whose allocator-internal cause was not established. The
low-mode observations, preregistered thresholds, and ownership findings
remain valid.

The affected frozen files are:

- `phase1-tip-tranche/results.txt`
- `phase2-coarse-bisect/MANIFEST.txt` and `results.txt`
- `phase3-refinement-bisect/MANIFEST.txt` and `results.txt`
- `phase4-quartile-split/MANIFEST.txt` and `results.txt`
- `phase5-micro-bisect/MANIFEST.txt` and `results.txt`
- `phase6-single-commit-split/MANIFEST.txt`

Those captures retain their original wording because their checksums
are evidence. This README and the live campaign receipt provide the
corrected interpretation without rewriting the sealed record.

The manifests are the load-bearing evidence: each was written **before
any build or measurement**, and each states its outcome bands, its
ownership thresholds, its anomaly tripwire, and its sum check up front.
The sealed image-digest and era-config sections are appended after
builds and preflights complete, before the first measured run; nothing
above those appended sections was ever edited.

## Phases

| Directory | Campaign | Window it narrowed |
|---|---|---|
| `phase0-endpoint-ab/` | pinned exact-SHA endpoint A/B, 5 interleaved pairs + a 5-pair bridge series | established the endpoint delta over 509 first-parent commits |
| `phase1-tip-tranche/` | tip tranche A/B, 7 interleaved pairs | the 12-merge structural-reclaim tranche at the tip |
| `phase2-coarse-bisect/` | 5 arms × 5 runs, round robin | 509 → 271 commits |
| `phase3-refinement-bisect/` | 4 arms × 5 runs | 271 → 86 commits |
| `phase4-quartile-split/` | 4 arms × 5 runs | 86 → 21 commits |
| `phase5-micro-bisect/` | 4 arms × 5 runs, candidate-targeted placement | 21 → 6 commits |
| `phase6-single-commit-split/` | 3 arms × 5 runs, every arm re-measured in-campaign | 6 → 1 commit |

## Files

| File | Contents |
|---|---|
| `<phase>/MANIFEST.txt` | the preregistration: frozen arms and SHAs, outcome bands, attribution rule, build discipline, harness pins, era-compat plan, run plan, quiet-lane policy — plus the appended sealed image digests, binary SHA-256s, and per-arm era-config record |
| `<phase>/results.txt` | every measured run (one row per run, all surfaces), per-arm distributions, growth curve, interval/step verdicts against the preregistered rule, sum check, anchor offset, anomalies, contamination status |
| `<phase>/original-SHA256SUMS.txt` | the campaign's own seal roster over its **unredacted** originals, written at campaign end. Use it to recognize the off-repo originals; it does not describe the redacted copies here (see below) |
| `phase0-endpoint-ab/run_one.sh` | per-run driver: cleanup, pinned-image bench, concurrent 1 Hz cgroup + `/proc` process-tree sampling, lane telemetry, rendered-config preservation. Reused with documented per-phase deltas by every later campaign |
| `phase0-endpoint-ab/preflight.sh` | per-arm boot + behavioral event-history proof (rendered config **and** the daemon's own disabled log line), db-file sweep, outbox metric count |
| `phase0-endpoint-ab/analyze.py` | post-processing: per-run table, per-surface distributions, paired t-CI against the preregistered bands |
| `phase0-endpoint-ab/config_base.toml` | the pre-v0.63.0 era rendered target config (`sha256 3316fed0…`) — `config_head.toml` plus the era-correct `[security.grpc] enforcement = "legacy"` block |
| `phase0-endpoint-ab/config_head.toml` | the post-authz-arc rendered target config (`sha256 64fb4f7b…`), byte-identical to the surface the preceding rebaseline measured. The bridge arm's config was byte-identical to this file and is not duplicated here |
| `phase0-endpoint-ab/adapter_shim.diff` | the env-gated harness shim that renders the legacy authz block for pre-v0.63.0 arms only. Applied after every build sealed, reverted at each campaign's end |
| `SHA256SUMS` | digests of every file in this directory, as published |

## Redaction

The captures are verbatim except for two mechanical substitutions
applied uniformly to every file:

- **Absolute host paths** → `<repo>`, `<bgperf2>`, `<runs>`, `<home>`.
- **Private tracker IDs and host workload/process names** → the phase
  names used above, `the prior rebaseline`, and `otherload`. The
  campaigns are identified here by phase and by the commit SHAs,
  digests, and PR numbers they measured, all of which are public.

Because those substitutions change bytes, the digests in each
`original-SHA256SUMS.txt` describe the off-repo originals, not the
copies in this directory. Verify what is published here with
`sha256sum -c SHA256SUMS`.
