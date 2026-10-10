# Policy-stats release follow-up evidence

This bundle analyzes the retained Q1 campaign and a new, valid short ABBA
confirmation. Original Q1–Q4 logs and verdicts are unchanged. Two earlier
confirmation attempts remain separately INVALID.

| File | Contents |
|---|---|
| `j2-reloads.json` | All 48 original reloads, selected clocks, concurrent neighbor probes, cell verdicts and four process exits |
| `j2-timeline.jsonl` | Original SIGHUP, last hot-apply, commit, phase, completion, settlement and post-commit-query records, with run/reload identity |
| `j2-correlation.csv` | Derived boundaries for every reload, including all six short post-#2952 cases |
| `j2-summary.json` | Per-run and pooled median/mean/range summaries |
| `source-sha256.json` | Digests of full original daemon/probe/environment/summary files and exits; labels identify sources without local paths |
| `pre2952-actor-reloads.csv`, `pre2952-provenance.json`, `pre2952-summary.json` | 72 actor values from the early S2 interval and prefix-snapshot scout, with all arm identities, original-file hashes and recomputed medians/ranges |
| `acceptance.md`, `invalid-four-reload-attempt.json` | Original four-reload declaration and FAIL/INVALID attempt; it could not meet the unchanged six-pair minimum |
| `confirmation-acceptance.md`, `invalid-six-reload-attempt.json` | Six-reload declaration and INVALID ABBA: the final parent had only five complete in-band pairs |
| `confirmation-eight-acceptance.md` | Final eight-reload confirmation declared before it ran |
| `confirmation-reloads.json`, `confirmation-timeline.jsonl` | All 32 reloads and selected original records from the valid eight-reload ABBA |
| `confirmation-correlation.csv`, `confirmation-summary.json` | Derived per-reload components and per-process/pooled median/mean/range summaries |
| `confirmation-provenance.json` | Four PASS cells, exits, quiet samples, pinned instruments, window timing and original-file hashes |
| `recompute.py`, `test_recompute.py` | Reproduction and negative controls |
| `quiet-preparation.json`, `quiet-preparation.md`, `quiet-irr-build-adapter.patch` | Explicitly unexecuted corrected S2/IRR recipe |

The reload JSON is a field extraction, not a byte-for-byte copy of the original
summary: it omits unrelated policy-stats reply payloads. The timeline contains
selected original JSON records with two added identity fields. Non-JSON daemon
lines are omitted from that selection. Full originals are identified by digest.

From this directory:

```bash
python3 recompute.py
python3 test_recompute.py
```

The first command requires and verifies both campaigns' stored summaries and
boundary tables, then reproduces the earlier actor evidence. Medians use
`statistics.median` on the per-reload values, including the midpoint of the
two middle values for even counts. The tests cover all reloads, the original
18 long cases and the confirmation's 13 long cases, reproduce the prior-step
actor values, and reject missing reloads, failed exits, fallback outcomes,
wrong member counts, inconsistent selected boundary/phase logs, failed or
missing probes, calls over two seconds and fewer than six complete in-band
pairs in a process. The original cell's full audit, reply-shape, flatness,
CPU and settlement checks are retained as its native verdict and hashes;
this extraction does not reimplement those omitted records. The checks do
not turn an inference about task scheduling into a measured profile.

The trace-arm estimate subtracts its monotonic wait duration from the wall
timestamp of its log event. The actor arms that trace after terminal input
retirement, before synchronous outer readiness cleanup and the oneshot send
without awaiting. It supplies an approximate terminal reply boundary; the
remaining cleanup and any scheduling pause are not independently timed. No
dedicated per-task admission/response timestamp was recorded; the full neighbor RPC includes
peer-manager fan-out followed by a RIB summary query.

All times are milliseconds unless the selected source field ends in `_us`.
Phase medians must not be added. Values from 12 reloads in one process are
correlated; the original has two launches per arm and the short confirmation
also has two, with eight reloads each.
