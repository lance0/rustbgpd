# Failover with alternates: announcing-owner churn cell (2026-09-27)

This is the first daemon-level receipt for announcing-owner churn with alternates. Route-server members that announce prefixes go down while part of each one's prefixes fail over to alternates announced by other members. One down pass therefore mixes displacing announcements, plain withdrawals, and new winning sources.

**Results, stated plainly:**

- **The RIB-side new-winner supplement candidate was declined** on its precommitted kill rule. At F=0.75, k=16, down-pass daemon CPU fell 11.5% (median of run means), but observer completion p50 stayed inside main's run spread. The rule declines if either condition fails. The candidate is not merged.
- **Session-side mixed-pass shared encode, already on main, is the first end-to-end number for that change.** At the same cell, down-pass daemon CPU is 59.6% lower than on its parent (median of run means 3.077 s → 1.243 s). Completion p50 did not move.

This is one fixed shape on one host: 700 members, 400,400 prefixes, 50 simultaneous flappers, three runs per arm. It does not establish a throughput limit, cross-host behavior, or a comparison with other daemons.

## Arms and source

Every arm is the listed commit plus `978b068c6dd9e3d4b6a4cb6ec89a71584c2ccae4`, which adds a `bench-internals`-only log line counting shared-payload and per-member-walk members in each mixed pass. That commit cherry-picks cleanly onto every arm, and default builds do not compile it.

| Arm | Commit | What it is |
|---|---|---|
| `main` | `82700ff0dfe1b37d4e5a32ec1557e19a10abedab` | main at measurement time, including the session-side mixed-pass shared encode |
| `pr2782` | `62b823dd48d33a374eb259a6c15faf9ee10977ba` | main plus the declined RIB-side new-winner supplement candidate |
| `pre2771` | `64c3ce4b360f3fa2de8aa71c639137b6b560abe0` | parent of the session-side mixed-pass shared encode |

Daemons were built with `cargo build --release --locked -p rustbgpd --features rustbgpd-rib/bench-internals` using rustc 1.98.1, and jemalloc as the default allocator. The harness is `reloadstall` and `failover_cell.sh` from `bench/scale` at the commit that adds this receipt.

## Workload

- **Fleet:** 700 eBGP route-server clients in one update group, 400,400 IPv4 /24s, 572 per member. This is the reloadstall scenario from `gen-scenario.py`, with 8 churners flapping 16-prefix blocks every 125 ms throughout.
- **Flapstorm:** `--flapstorm 50`. The first 50 members close at once, reconnect 10 s later and re-announce. There are three rounds per run.
- **Alternates** (`gen-failover-overlap.py 700 400400 50 F k`): for each flapped member, the first F% of its slice is also announced by one of k distinct surviving non-churning members, round-robin. Alternates carry the member's ASN twice, so they lose the initial best-path tie-break and win only after the flapped member closes.
  - F=0.75, k=16: 21,450 alternate prefixes from 642 sources.
  - F=0.75, k=1: 21,450 prefixes from 50 sources.
  - F=0.25, k=1: 7,150 prefixes from 50 sources.
- **Down-pass evidence per round:**
  - daemon user+system CPU-seconds from `/proc/<pid>/stat`, all threads, read just before the simultaneous close and again when the harness's 100 ms poll detects the last survivor's completion. The window therefore also contains the churners' steady background work; see [Measurement window](#measurement-window);
  - survivor completion p50/max, where each flapped prefix completes on the alternate's announcement, or on a withdrawal at the alternate itself and for prefixes without one;
  - `bgp_rib_actor_work_duration_seconds{work_unit="distribute_flush"}` sum and count between two metrics scrapes. In the campaign harness, the opening scrape ran before completion tracking was armed and before the opening CPU read, and the closing scrape ran after the closing CPU read. The flush interval therefore contains the CPU window plus the arming step and both scrapes, and is not the same interval. The current harness mirrors the two boundaries (scrape, then CPU read; CPU read, then scrape) and labels these columns `scrape_bracketed_flush_*`. Exact alignment is not possible, because a scrape costs daemon CPU and must stay outside the CPU window.

## Host discipline and commands

The host was an AMD Ryzen Threadripper 7970X (64 logical CPUs, about 125 GiB visible memory, Linux 7.0.0-30-generic). Daemon and harness shared logical CPUs 12-32 and 34-39. Each cell ran under a host benchmark lock, so timed cells never overlapped each other or another worker's timing. Unrelated build and test work ran on CPUs 40-63 during the campaign, so this is not an isolated-host measurement.

Arms alternated within each run index, in the order A,B,C then C,B,A then A,B,C. Every one of the 21 runs had harness exit 0 and daemon exit 0.

```bash
cd bench/scale && cargo build --release --locked -p reloadstall && cd ../..
flock <bench lock> env CORES=12-32,34-39 \
    bench/scale/reloadstall/failover_cell.sh <arm daemon> <out dir> 75 16
# secondary cells: ... 75 1   and   ... 25 1
```

`failover_cell.sh` generates the scenario and allocation, starts the pinned daemon, and runs `reloadstall 700 400400 1790 <pid> <policies> 0 30 --flapstorm 50` with `RELOADSTALL_OVERLAP_FILE` and `RELOADSTALL_FAILOVER_METRICS_ADDR=127.0.0.1:9179`. It then totals the daemon's mixed-pass path lines.

## Kill cell: F=0.75, k=16

The table gives daemon CPU-seconds per round, then completion p50 per round in seconds.

| Arm | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| main | 1.01 / 1.32 / 1.26; .358 / .475 / .376 | 1.41 / 1.61 / **2.92**; .332 / .431 / **.874** | 1.18 / 1.40 / 1.15; .416 / .459 / .444 |
| pr2782 | 0.98 / 1.19 / 1.13; .377 / .557 / .416 | 1.00 / 1.09 / 1.25; .316 / .471 / .461 | 1.00 / 1.03 / 1.25; .389 / .412 / .585 |
| pre2771 | 2.75 / 3.33 / 3.07; .324 / .461 / .391 | 2.58 / 3.24 / 3.41; .354 / .446 / .407 | 2.81 / 3.46 / 3.59; .326 / .487 / .530 |

Main's run 2, round 3 (2.92 s CPU, .874 s p50) is an outlier against every other main round, so run medians are given beside run means:

| Arm | CPU run means (s) | Median of means | CPU run medians (s) | Median of medians | p50 run means (s) | p50 run medians (s) |
|---|---|---:|---|---:|---|---|
| main | 1.197 / 1.980 / 1.243 | 1.243 | 1.26 / 1.61 / 1.18 | 1.26 | .403 / .546 / .440 | .376 / .431 / .444 |
| pr2782 | 1.100 / 1.113 / 1.093 | 1.100 | 1.13 / 1.09 / 1.03 | 1.09 | .450 / .416 / .462 | .416 / .461 / .412 |
| pre2771 | 3.050 / 3.077 / 3.287 | 3.077 | 3.07 / 3.24 / 3.46 | 3.24 | .392 / .402 / .448 | .391 / .407 / .487 |

**Kill rule.** The rule was precommitted on the tracking issue: decline if the candidate reduces down-pass daemon CPU-seconds by less than 10% at F=0.75, k=16, or if observer completion p50 does not move outside the run spread.

- **CPU:** pr2782 against main is −11.5% on the median of run means and −13.5% on the median of run medians. This clears 10%.
- **p50:** pr2782's run means (.416–.462 s) and run medians (.412–.461 s) sit inside or overlap main's (.403–.546 s and .376–.444 s). They did not move outside the spread.
- **Verdict: declined.** The initial report of this cell gave −11.3%, computed from means rounded to two places. The three-decimal figure above is the recorded value; the verdict is the same.

**Mechanism count, not a benefit claim.** The daemon's mixed-pass lines count 2,400 per-member walks per run on main and pre2771 (3 rounds × 50 flapped members × 16 new winners), and 0 on pr2782. They confirm that the candidate moved new winners onto the shared payload in the real daemon. They do not show a completion-latency benefit.

**Session-side mixed-pass shared encode (pre2771 → main).** Down-pass daemon CPU fell 59.6% on the median of run means (3.077 s → 1.243 s) and 61.1% on the median of run medians (3.24 s → 1.26 s). Completion p50 did not move outside the run spread: .392–.448 s against .403–.546 s. This is observed daemon CPU for one shape, not an encode-count model.

Scrape-bracketed `distribute_flush` actor-work sums (old bracketing, above) were 0.06–0.23 s in every arm. The per-round values are in the artifacts. Most window CPU is therefore outside the coalesced RIB distribution pass, consistent with session-side encode dominating. This is an observation from these runs, not an attribution profile. These flush figures are supporting data, not inputs to any decision in this receipt.

## Secondary cells, main vs pr2782

| Cell | Arm | CPU run means (s) | Median | CPU run medians (s) | p50 run means (s) | p50 run medians (s) | Walks per run |
|---|---|---|---:|---|---|---|---:|
| F=0.75, k=1 | main | 1.187 / 1.340 / 1.083 | 1.187 | 1.19 / 1.24 / 1.11 | .237 / .277 / .222 | .224 / .286 / .225 | 150 |
| F=0.75, k=1 | pr2782 | 1.077 / 1.220 / 1.193 | 1.193 | 1.08 / 1.20 / 1.22 | .252 / .272 / .272 | .253 / .241 / .274 | 0 |
| F=0.25, k=1 | main | 1.753 / 1.467 / 1.400 | 1.467 | 1.73 / 1.37 / 1.38 | .335 / .306 / .284 | .284 / .286 / .299 | 150 |
| F=0.25, k=1 | pr2782 | 1.433 / 1.610 / 1.303 | 1.433 | 1.55 / 1.62 / 1.26 | .310 / .334 / .261 | .335 / .348 / .215 | 0 |

With one alternate source per flapped member, the two arms are indistinguishable within run spread in both CPU and completion. Every round is in [`rounds.csv`](artifacts/failover-alternates-2026-09/rounds.csv).

## Modeled versus observed

The tracking issue's model predicted the RIB-side walk cost, k members cloning and probing about F·D routes each on the RIB actor, and the session-side per-member re-encode. It did not predict a speedup. Observed here:

- The session-side change cut daemon CPU by about 60% at the kill cell.
- The RIB-side change's 2,400 removed walks per run bought about 11–13% CPU and no completion movement.

No figure in this receipt is extrapolated to other fleet sizes, prefix counts, or flap cohorts.

## Measurement window

Post-campaign review found that the campaign's CPU window is not down-pass-only. This is how it was bracketed:

- **Start:** the harness read `/proc/<pid>/stat` after arming completion tracking and immediately before aborting the 50 flapped sessions.
- **End:** it read again once `wait_flap_completion`, which polls every 100 ms, saw the last survivor complete.

The window therefore also contains:

- the 8 churners' steady fanout for its whole length;
- up to one poll interval after the actual completion.

It misses only daemon work that continues after that poll, such as late teardown of the closed sessions. The window's length follows each round's completion time, so the background part is not a fixed offset between arms.

**Direction of the bias.** Background work adds a positive amount to every arm's window CPU, and the arm with the longer window carries more of it. Completion max bounds each window's length, less the up-to-100 ms poll slack. Across the campaign's rounds it averaged:

| Arm | Mean completion max (s) | Range (s) |
|---|---:|---|
| main | .509 | .357–.911 |
| pr2782 | .568 | .453–.713 |
| pre2771 | .446 | .354–.565 |

- **The candidate against main:** the candidate's windows were not shorter on average, so background inclusion understates its measured CPU reduction rather than overstating it.
- **Main against the session-side change's parent:** main's windows were longer on average, so the −59.6% likewise understates the reduction in window-attributable work rather than overstating it.

These are directional statements from the recorded window lengths, not corrected values.

**Size of the background.** After this review, one supplementary run per arm at the kill cell recorded each window's wall length and a churn-only daemon CPU rate sampled over 2 s just before each close. It used the same alternation and host discipline, and it re-derives no campaign figure.

| Arm | Window CPU per round (s) | Window length (s) | Pre-close background rate (CPU-s/s) |
|---|---|---|---|
| main | 1.360 / 1.600 / 1.670 | .651 / .714 / .611 | .870 / 1.590 / 1.709 |
| pr2782 | 0.950 / 1.110 / 1.340 | .305 / .409 / .608 | .820 / 1.619 / 1.729 |
| pre2771 | 2.580 / 2.970 / 3.450 | .405 / .505 / .505 | .685 / 1.670 / 1.654 |

The window CPU values fall within the campaign's ranges. At the sampled rates, background work could account for a large part of every main and pr2782 window. The rate during a down pass is not measured: while the RIB actor is busy, churn is likely delayed rather than running at its pre-close rate. This receipt therefore reports no background-corrected figure.

**Scope of the affected claims.**

- **The candidate's −11.5% and the session-side change's −59.6%** are reductions in daemon CPU over the window defined above, not in CPU attributable to the down pass alone. They are reported only in that sense.
- **The candidate's decline does not depend on this window.** It follows from the completion-p50 condition of the kill rule, which is measured from survivor timestamps. By the direction argument above, background inclusion is not what lets the CPU condition pass.
- **Future runs** record the window length and background rate per round (`flapstorm_failover_csv` columns `window_s` and `background_cpu_s_per_s`).

The same review added two fail-closed checks; neither changes a campaign number.

- **Allocation check before the first close.** Every alternate must cover a prefix of the flapped cohort and must not be a churner. Each alternate member must currently hold its owner's path, which proves it lost the initial tie-break. The campaign ran before this check existed, but its failover completion arm required every non-alternate survivor to receive each alternate's announcement during the down pass. That cannot happen if an alternate was already best, so any such round would have stalled and failed, and all 63 campaign rounds completed. The per-member walk counts, 2,400 = 3 rounds × 50 flapped members × 16 new winners per run, match the allocation.
- **Cell status covers every step.** It now fails on a nonzero daemon shutdown or a failed summary, not only a harness failure. Every campaign run recorded harness, daemon and summary success (`runs.csv`).

## Artifacts

The [artifact guide](artifacts/failover-alternates-2026-09/README.md) lists:

- per-round and per-run CSVs, plus the supplementary window run;
- every run's harness output, daemon mixed-pass lines and daemon warnings;
- host metadata.

The warnings are the expected categories. A single `marking dirty for resync` in one main run falls at teardown, after its last round.
