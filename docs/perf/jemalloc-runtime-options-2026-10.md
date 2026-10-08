# jemalloc run-time options: background_thread A/B — 2026-10-08

A same-session A/B of jemalloc's defaults against
`_RJEM_MALLOC_CONF=background_thread:true` on the S2 matrix, IRR 0% reload and
`GetPolicyStats` operator-read cells. The predeclared analyzer returned
**INVALID** because the operator-read cell produced no in-band calls in
either arm. The headline cells were valid. They show
`background_thread:true` is not an improvement on these shapes: the daemon's
cgroup memory peak rose by 177 MiB (S2) and 93 MiB (IRR) at the median with
separate ranges, while the IRR reload clocks fell by 17–30 ms.
`metadata_thp:auto` was not run. Nothing ships: the daemon keeps jemalloc's
defaults.

## Question and arms

Both arms ran the same daemon source, origin/main
`f15804bc408273095c963a64f92e500b93af7d5c`, each built in its own campaign
directory.

| Arm | Daemon environment | jemalloc read-back |
|---|---|---|
| `main` | no `_RJEM_MALLOC_CONF` | `opt.background_thread: false` |
| `bgth` | `_RJEM_MALLOC_CONF=background_thread:true` | `opt.background_thread: true` |

- **Daemon-only setting.** The `bgth` arm is a local, unpublished commit
  ([`arm.diff`](artifacts/jemalloc-runtime-options-2026-10/arm.diff)). It adds
  `env _RJEM_MALLOC_CONF=…` to the daemon launch line, in the runners'
  swap-fenced scope launcher and in the policy-stats cell. Harness processes,
  which also link the prefixed jemalloc, never saw the variable.
- **Prefixed variable.** The release build uses `_rjem_`-prefixed jemalloc, so
  plain `MALLOC_CONF` is ignored. `stats_print` showed `opt.background_thread:
  true` only with the prefixed name
  ([`opt-readback.txt`](artifacts/jemalloc-runtime-options-2026-10/opt-readback.txt)).
- **Checked on every leg.** A 1 Hz `/proc` watcher recorded each daemon's
  environment and its count of `jemalloc_bg_thd` threads; jemalloc creates
  those threads only when `opt.background_thread` is on. Every `bgth` daemon
  ran with the variable and 4 background threads. Every `main` daemon had
  neither (all 15 daemons, the terminated run included; `allocator-watch.tsv`).
- **Binary equivalence, as checked.** Both arms built the same source
  commit with the same commands and flags, in two different directories. Each
  build embeds its directory in generated-source paths, so the raw daemon
  hashes differ. The run's check (in `analyze.py`) substituted the directory
  name and found:
  - every allocated section the same size;
  - `.eh_frame` and `.gcc_except_table` byte-identical;
  - `.rodata` differing only by a permutation of its bytes.

  It compared neither `.text` contents nor relocations, so on its own it does
  not prove the binaries are equivalent. The `reloadstall` harness passed the
  same check.
- **Added after the run: `.text` disassembly.** This check was not
  predeclared ([`posthoc-text-diff.py`](artifacts/jemalloc-runtime-options-2026-10/posthoc-text-diff.py),
  [output](artifacts/jemalloc-runtime-options-2026-10/posthoc-text-diff.txt)).
  It compared the two daemons' `objdump -d` listings of `.text` line by line:
  - 6,959,404 of 6,963,967 instructions are identical, at identical addresses;
  - the other 4,563 differ only in a RIP-relative operand whose target lies
    inside `.rodata` in both builds, which is the constant reordering above;
  - no other instruction differs.

  The `reloadstall` `.text` listings match on all 552,851 instructions. A
  negative control (one changed instruction) fails the check. Relocation
  entries and `.data` contents were not compared beyond the section sizes.

## Predeclared bars and verdict

The bars were written before the first measured leg
([`acceptance.md`](artifacts/jemalloc-runtime-options-2026-10/acceptance.md))
and applied by
[`analyze.py`](artifacts/jemalloc-runtime-options-2026-10/analyze.py):

- **Clocks and reads:** better or worse only if the per-leg ranges are separate.
- **Memory:** separate ranges and a median difference of at least 50 MiB, the
  top of the 30–50 MiB noise floor.
- **Verdict:** a WIN needs at least one primary metric better and none worse.
  A missing primary value makes the stage INVALID.

**Verdict: INVALID.** The policy-stats cell fires its `GetPolicyStats` and
`neighbor` pair 0.50 s after the cohort hot-apply completes, intending to land
just before the RIB commit. On this main, the pairs started 445–454 ms
*after* the RIB commit in all 24 reloads of both runs, so no call was in band
and the in-band read metrics had no values. The cell itself exited 1 (FAIL:
0 complete in-band pairs, 6 required). After both arms' first runs showed
this, the remaining policy-stats runs were stopped deliberately: the third
run was terminated mid-run (exit 143) and the last three were not started.
Nothing was retried or excluded.

**Stage 2 not run.** The `background_thread:true,metadata_thp:auto` arm was
gated on a stage-1 WIN.

## Deviation from the predeclared bars

[`acceptance.md`](artifacts/jemalloc-runtime-options-2026-10/acceptance.md)
says the arms' daemon and `reloadstall` binaries "must hash identically". The
first smoke run showed that cannot hold. Each build embeds its own directory,
so identical sources built in two directories hash differently. Before the
measured run, the validity check was changed to the section-level comparison
described in its "Validity" section and implemented in `analyze.py`. The
stage used that comparison, not raw hashes. The "Arms and shape" sentence
requiring identical hashes was left unedited and is superseded by the
"Validity" section. Both predeclared files are kept as they were run.

## Headline results (secondary evidence)

All 12 headline legs passed their runners' acceptance with every runner
guard in place: two quiet samples per leg, 300 s cool-downs, swap counters
unchanged throughout. Arm order rotated per run. Values are per-leg medians
over each leg's four reloads; memory is per leg. n = 3 legs per arm.

| Metric | `main` | `bgth` | Median delta | Bar result |
|---|---|---|---:|---|
| IRR 0%: daemon SIGHUP → reload complete | 556–568 ms | 522–541 ms | −30 ms | better |
| IRR 0%: harness completion p50 | 0.574–0.582 s | 0.551–0.563 s | −17 ms | better |
| S2: daemon SIGHUP → reload complete | 663–748 ms | 678–756 ms | −39 ms | no difference |
| S2: harness completion p50 | 0.69–0.77 s | 0.71–0.78 s | −35 ms | no difference |
| S2: daemon cgroup `memory.peak` | 994–1,028 MiB | 1,045–1,222 MiB | +177 MiB | worse |
| IRR 0%: daemon cgroup `memory.peak` | 739–742 MiB | 827–861 MiB | +93 MiB | worse |
| S2: settled RSS (last 5 s sample) | 367–370 MiB | 371–376 MiB | +3.5 MiB | no difference |

Reported but not judged:

| Metric | `main` | `bgth` | Median delta |
|---|---|---|---:|
| S2: daemon VmHWM | 550–557 MiB | 601–608 MiB | +49 MiB |
| IRR 0%: daemon VmHWM | 741–745 MiB | 774–782 MiB | +34 MiB |
| S2: peak 5 s RSS sample | 477–531 MiB | 616–619 MiB | +96 MiB |
| IRR 0%: peak 5 s RSS sample | 627–642 MiB | 782–790 MiB | +151 MiB |
| S2: daemon RIB transition | 66–80 ms | 64–67 ms | −8 ms |
| IRR 0%: daemon RIB transition | 362–374 ms | 338–351 ms | −12 ms |
| Policy-stats cell (one run each): pair `GetPolicyStats` external p50 | 12.0 ms | 11.6 ms | — |
| Policy-stats cell (one run each): quiescent `GetPolicyStats` external p50 | 12.0 ms | 11.9 ms | — |

- **Memory moves the wrong way.** Purging moves to background threads, but
  the reload transient's cgroup peak is higher with them on. In the S2
  matrix, one `bgth` leg peaked at 1,045 MiB and two at 1,190–1,222 MiB.
  Settled RSS is unchanged, as in an earlier single-leg scout on the same S2
  shape.
- **IRR clocks improve.** The IRR 0% SIGHUP-to-complete interval and harness
  completion are lower in every `bgth` leg than in every `main` leg. The S2
  clocks overlap.
- **Not shipped.** Under the predeclared rule, a clock gain does not offset
  a memory regression beyond the noise floor. With the read cell invalid, the
  bars themselves can only return INVALID here; the headline data rule out a
  WIN either way. jemalloc's defaults stay. `_RJEM_MALLOC_CONF` remains
  available to operators who want to trade memory for the IRR-scale clock.

## Not claimed

- No operator-read latency result: the in-band read bar was not evaluated.
- Nothing about `metadata_thp`, unprefixed `malloc` for C dependencies (none
  of these cells enables `[event_history]`, so SQLite never runs), other
  shapes, or pinned placements.
- No statistical significance: three legs per arm.

## Provenance

- **Host and toolchain:** AMD Ryzen Threadripper 7970X (64 CPUs, all
  `performance` governors), Linux 7.0.0-30-generic, no swap device, cgroup v2
  with swap fenced by `memory.swap.max=0` on the daemon scope. Rust 1.99.0.
- **Builds:** the headline driver built each arm with
  `cargo build --release --locked -p rustbgpd -p rustbgpctl -p rs-config-render`
  and `cargo build --profile scale --locked -p reloadstall`.
- **Window:** 2026-10-08 09:17–11:34 local time. The shared host lock was held
  for the whole window; runners took a campaign-private lock file. The
  headline driver was
  [`run-campaign.sh`](../../bench/scale/headline/run-campaign.sh) with
  `CELLS=matrix,irr MATRIX_SCENARIOS=s2 RUNS=3 OVERLAPS=0
  IRR_CELLS=rustbgpd-sighup`.
- **Evidence:** the [artifact bundle](artifacts/jemalloc-runtime-options-2026-10/README.md).
