# IRR-scale streamed transactional config apply — 2026-08

Can the streamed transactional config path — streamed Plan, token-bound
streamed Apply, disk-backed commit-confirm journal, confirm / explicit
abort / timeout auto-revert — carry a realistic IRR route-server refresh?
The candidate here is a ~295.6 MB full config: 320 members whose IRR
filter lists total 3,218,965 prefix entries, applied to a live daemon
holding 320 established sessions, four times per run, then aborted and
auto-reverted with byte-exact restoration proofs. Two fresh sealed
artifact roots, both green, cross-checked by the campaign's independent
four-way verifier.

## Headline

| Metric (320 members × 183,040 routes, ~295.6 MB streamed candidate) | Root A | Root B |
|---|---|---|
| Measured transactional reload cycles, all confirmed | **4 / 4** | **4 / 4** |
| Sessions up at every reload validation / parse errors | 320/320 / 0 | 320/320 / 0 |
| Completion (full re-advertisement under the new generation marker), median of per-cycle p50s | **142.6 s** | **137.8 s** |
| Worst per-observer UPDATE gap during a reload (p50 range over cycles) | 289–487 ms | 288–334 ms |
| Explicit abort: terminal state, disk+runtime restoration | `aborted`, exact | `aborted`, exact |
| Timeout auto-revert: post-commit deadline → terminal (ceiling 600 s) | **69.5 s** | **69.0 s** |
| Final streamed Plan of the restored generation | tokenless `NOOP` | tokenless `NOOP` |
| Daemon `VmHWM` peak (abort fence 100 GiB) | 36.5 GiB | 36.7 GiB |
| Independent verifier (`verify-receipt.py transactions`) over the pair | **pass** (8 rows) | — |

Every measured cycle streamed a committable Plan, streamed the Apply
bound to that Plan's single-use token, held a pending commit-confirm
with the full v3 disk journal in place, and was explicitly confirmed;
the lifecycle legs then proved abort and timeout auto-revert restore the
prior generation exactly, on disk and in the effective runtime config.

## Commit and provenance

- **Commit measured:** `02c752408b2336061da050d3396c3f7a538d3389` — both
  roots, working tree clean, exactly `origin/main` at run time. This
  receipt is published from the successor release-prep commit; the whole
  delta between the measured commit and this document's base is v0.63.0
  release preparation (workspace version bumps and lockfiles, CHANGELOG
  roll, README/ROADMAP text, and a frozen v1-stable config fixture with
  its test) — no daemon, harness, or script code changed.
- **Campaign fingerprint:** root A
  `2e00514bbe5603bfb79a199ba7810d8088f9f287fb21dfb5c289c3b2926e41c6`,
  root B
  `b2d0ce4346397ec06cd1a33b3623e9176078328e755dee5845a2129ed89c192e`.
  The fingerprint hashes the entire provenance document, which binds the
  root's own start timestamp, so the two values legitimately differ; the
  two provenance files differ in **no other field** (same commit, dirty
  state, scripts, binaries, environment, and inputs — see the committed
  extracts), and the verifier independently requires that match.
- **Dataset digest** (identical in both roots):
  `fad37b701fcd3f7f51884906f66052325f3f1e57a02528a039535ed08907c56b`;
  scenario roster digest (identical):
  `5053629f223858c2d72a976226f3b4cfe99014619468209ed88cfd0919aa804d`.
- **Binaries** (SHA-256, identical in both roots): `rustbgpd`
  `bd240438a84cad38d0ee1fd02acec67b76ed7dff20fb4faa75be8c87cff79b7d`,
  `rbgp`
  `24b6cba7572713e25dc35a7a2e6eea2ea194d73ff496a872e90d3e534476740b`,
  `reloadstall` harness
  `f0b463e00f5619bca966000d0e36b8d6a23742ba360af7624b5bb64c0259778b`,
  `rs-config-render`
  `572caaad09d082b32b2524fbf4094a1eb732115169b91d9b5004d888722a7bfc`.
- **Scripts** (SHA-256, identical in both roots): runner
  `d3e0b4eaae3b3410dfd9c7f95c9d013edb0104b2e66b4542d0093826bc6ddd7d`,
  generator
  `319f070c936c6deb681635f2c06f1c9c5bf16f64ebf31ff3d6d56ec0eedb0267`,
  RSS sampler
  `cf00e09511d782bd40f60548ea60077b702e1bfe98c57eb391b94ce6aa202540`,
  `txn-apply.sh`
  `3ce26316023bbd4ae6d062e3c71ea4de354164b1dc4b6ed693f53d88de5dc249`,
  `txn-lifecycle.sh`
  `1a251908ad71f9747c6b1d7570688ec12673f03279d4e29c6b4d4acf477b6139`,
  verifier
  `5405698c238073b222e6df00e6b331ab609ab5a4f920ff72bf46f2357c0443d7`
  (byte-identical to `bench/scale/irrreload/verify-receipt.py` as
  committed alongside this receipt).

## Shape

The canonical full transaction shape of
[`bench/scale/irrreload/`](../../bench/scale/irrreload/README.md), cell
`rustbgpd-txn`: 320 members, 183,040 announced /24s (572 per member),
per-member IRR filter lists log-uniform 1,000–40,000 entries
(3,218,965 total), seed 61, changed fraction 0.1 (36 of 320 filter
lists change between generations), 16-prefix / 125 ms churn, four
measured reloads per root in B/A/B/A generation order. The dataset is
carried as inline chain-engine policy in a full candidate config TOML:
generation A 295,624,985 bytes, generation B 295,624,973 bytes. Each
reload is a streamed gRPC Plan, a streamed Apply presenting the Plan's
UUID-v4 single-use token, a pending commit-confirm (600 s window on the
measured cycles), and an explicit confirm. The export marker community
(`65400:1000` ⇄ `65400:2000`) changes output for all 320 observers, so
completion percentiles cover the full fleet.

## Method

- **Two fresh sealed roots** in strict A/B order
  (`irrreload-txn-20260804T131946Z-A`, `irrreload-txn-20260804T135502Z-B`),
  each a fresh daemon PID/start identity, each sealed with `COMPLETED`
  plus an exact `SHA256SUMS` roster and made read-only.
- **Quiet-host gates**: clean `HEAD` exactly at `origin/main`, passing
  preflight, exclusive host lock, two retained 1-minute-load samples
  below 2.0 at least 30 s apart with no swap movement between them,
  free ports, ≥ 40 GiB artifact headroom.
- **Independent verification**:
  `bench/scale/irrreload/verify-receipt.py transactions` over the pair
  returned `status: "pass"` with 8 transaction rows, re-deriving every
  row, re-computing both provenance fingerprints, re-checking seals,
  quiet evidence, lifecycle restoration, the history-warning sequence,
  the exact file roster, and the absence of retained token contents.
  Its `verification.json` and re-derived `transactions.csv` are
  committed in the artifact directory.

## Measured cycles

Completion is receiver-side: an observer completes when it holds every
expected unique non-self base prefix re-advertised with the new
generation marker; duplicates never advance it. First-generation output
includes the streamed Plan and Apply round-trips — that path's reload
cost by design. All cycles: 320/320 sessions up, 0 parse errors, 0
stable-marker leaks.

Root A (`irrreload-txn-20260804T131946Z-A`):

| Cycle | Completion p50 / p95 / max (s) | Worst observer gap p50 (ms) | RSS before → after (MiB) |
|---|---|---|---|
| 1 | 142.41 / 189.08 / 196.76 | 487.0 | 19,848 → 23,807 |
| 2 | 154.43 / 202.31 / 208.55 | 386.1 | 21,336 → 22,803 |
| 3 | 142.78 / 189.22 / 194.30 | 292.4 | 21,391 → 23,098 |
| 4 | 139.98 / 186.07 / 191.34 | 289.1 | 21,488 → 23,263 |

Root B (`irrreload-txn-20260804T135502Z-B`):

| Cycle | Completion p50 / p95 / max (s) | Worst observer gap p50 (ms) | RSS before → after (MiB) |
|---|---|---|---|
| 1 | 142.14 / 188.95 / 194.08 | 334.0 | 19,772 → 24,347 |
| 2 | 137.04 / 183.31 / 188.46 | 309.0 | 21,948 → 22,966 |
| 3 | 138.27 / 186.48 / 191.91 | 303.2 | 21,374 → 23,877 |
| 4 | 137.23 / 183.23 / 188.41 | 288.2 | 21,546 → 23,728 |

Median of the per-cycle p50s: **142.6 s (A) / 137.8 s (B)**, trigger to
full 320-observer re-advertisement — plan + streamed apply + recompute
of the 3.2M-entry policy + wire output. UPDATEs never stall beyond
~0.5 s at the worst observer in any cycle.

## Commit-confirm v3 journal

Every pending window left the complete disk-backed v3 authority beside
the config, all owner-only (`0600`), with full locator → metadata → raw
path/digest/device/inode linkage verified and the legacy journal absent:

| Object | Size |
|---|---|
| `config.toml.commit-confirm-locator.json` | 502–507 B |
| `commit-confirm-v3-metadata.json` | 567–572 B |
| `commit-confirm-v3-prior.toml` (raw prior config) | 298,877,893 B |

The authority's advertised pre-apply deadline correctly predates the
post-commit Apply/Status deadline in every window (schema-2 two-clock
separation; e.g. root A timeout leg: 13:46:35Z advertised vs 13:47:54Z
post-commit). After every terminal — confirmed, aborted, or
auto-reverted — the v3 authority is completely removed.

## Lifecycle proofs (after the measured cycles, per root)

- **Explicit abort**: the opposite generation applied pending (600 s
  window), then aborted by RPC. Terminal `aborted`, runtime snapshot
  token rotated, all v3 authority files removed, disk and
  effective-runtime hashes restored exactly, bounded history unchanged.
- **Confirmation-timeout auto-revert** (10 s window): root A post-commit
  deadline 13:47:54Z, terminal auto-revert logged 13:49:03.47Z —
  rollback of the ~295.6 MB generation completed **69.5 s** after the
  deadline; root B deadline 14:20:33Z, terminal 14:21:41.98Z —
  **69.0 s**. Both are far inside the 600 s rollback ceiling, with
  terminal `auto_reverted`, no rollback error, and exact restoration.
- **Final streamed Plan** of the restored generation: tokenless `NOOP`
  in both roots; the final state is byte-identical to the pre-lifecycle
  baseline.

## Persistence hashes (stable across cycles and across roots)

| Object | SHA-256 |
|---|---|
| Generation B candidate (`65400:2000`, cycles 1+3, both roots) | `6264b9a6aa636d8d6f9c661310451a18688db8ac9d5836c61978296ea2205f7f` |
| Generation A candidate (`65400:1000`, cycles 2+4, both roots) | `1c2cbced545d561283e68ae62beee4de739c60c450d50e52904db9656c0f6fd5` |
| Restored on-disk config (baseline == final, both roots) | `ef5cc53501622dd2b2ec40c0b28378875ed8cdd083e8fad9b955062b0b85f9e5` |
| Effective-runtime config (baseline == final, both roots) | `fad94efe1e0c47b0e18767c86779744329f27edac239d5f17cc53020500cfc28` |

Because the public config history skips entries above 10 MiB, the
receipt binds the empty history plus the daemon's exact oversize warning
(with a byte count above 10 MiB) at every persist: nine warnings per
root — boot, four measured applies, abort apply + restore, timeout
apply + restore — all present, and the bounded history and its on-disk
roster stayed empty throughout.

## Memory

`VmHWM` peaked at 38,315,048 KiB (**36.5 GiB**, root A) and
38,489,276 KiB (**36.7 GiB**, root B) — both far below the campaign's
100 GiB abort fence. The independent process-tree sampler (5 s cadence)
peaked at 35.7 GiB (A) and 36.0 GiB (B). Holding two ~299 MB config
representations plus the 3.2M-entry compiled policy across an apply is
the expected shape of this cost; the receipt reports it without a
memory-optimization claim.

## Campaign history: one defect, one false-red

The two green roots were preceded by two red runs, both retained as
immutable roots off-repo:

1. **Production defect (real).** The first full run failed its lifecycle
   proof: the commit-confirm public deadline was minted *before* the
   apply, so a slow (~2-minute) IRR-scale apply could consume the
   confirmation window before the caller ever saw the pending state.
   Fixed before the green runs (`f5eaca54`): the Apply/Status deadline
   now starts after commit, the advertised pre-apply deadline is
   recorded separately as informational, and boot recovery is
   unconditional. The green evidence schema records and checks both
   clocks.
2. **Harness false-red.** The second run failed only its
   timeout-auto-revert wait: the harness allowed 60 s for the terminal
   state, but the legitimate reverse apply of the ~295.6 MB generation
   takes ~70 s (69.0–69.5 s measured above). The daemon's rollback was
   correct; the instrument's ceiling was wrong. The harness now carries
   a separate 600 s terminal-rollback ceiling measured from the deadline
   (`28eec7ac`), and the green runs measured the real rollback time
   under it.

## Red proof (the verifier rejects tampering)

On copies of both green roots, `verify-receipt.py transactions` passes
(exit 0). Changing a single digit of one completion value in the copied
root A's sealed `rows.csv` (`142.408741` → `143.408741`, root then
restored to read-only) makes the same invocation fail closed — exit 1,
`checksum mismatch for rows.csv` — because the row no longer matches the
root's sealed `SHA256SUMS` roster. The mutated copy was scratch-only and
is not retained.

## Honesty notes

- Root A cycle 2 ran ~8–10% slower than the other seven cycles
  (completion p50 154.4 s vs 137–143 s elsewhere) with identical
  session/parse outcomes — ordinary host variance for this instrument,
  published unfiltered.
- The pre-cell quiet gate restarted its sampling once per root after
  observing swap-counter movement, then passed; the sealed roots retain
  the final accepted sample pair (`quiet-*.tsv`), and the restart lines
  are in the uncommitted runner logs.
- Loopback TCP on one host; single shape, two repeats in fixed order —
  not statistically independent trials.
- This cell never enters the cross-daemon comparison: it carries the
  dataset as inline chain-engine policy (the transactional seam rejects
  out-of-band `.rpol` changes by design), so it answers "what does the
  streamed transactional seam cost for the same semantic change", not
  engine-vs-engine or daemon-vs-daemon.
- First-generation-output and completion clocks include the Plan/Apply
  round-trips — the transactional path's real reload cost.
- Plan and runtime token contents are never retained in evidence; the
  verifier checks their absence.

## Environment

| Field | Value |
|---|---|
| Hardware | AMD Ryzen Threadripper 7970X (32 cores), 125 GiB RAM |
| Kernel | Linux 6.17.0-35-generic x86_64 |
| Toolchain | rustc 1.97.0, cargo 1.97.0, Python 3.12.3, jq 1.7 |
| Build | `--release`; quiet-host gates as above |

## Artifacts and reproduction

Compact evidence — verifier output, per-root provenance, complete
lifecycle/cycle transaction evidence, quiet samples, checksums — is
committed under
[`artifacts/irr-transactional-apply-2026-08/`](artifacts/irr-transactional-apply-2026-08/README.md)
with the digests that identify the sealed full roots. The campaign
runner, protocol, and verifier are
[`bench/scale/irrreload/`](../../bench/scale/irrreload/README.md); the
transaction receipt reproduces with the two `rustbgpd-txn` invocations
and the `verify-receipt.py transactions` step documented there.
