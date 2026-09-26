# Headline performance refresh: v0.72.0 and current main — 2026-09-26

This same-day, same-host campaign re-measured the headline route-server and
route-reflector cells on two builds: the v0.72.0 release tree and current main at
`33f8e7142c4a984812de0ba927b65a842a4db62c`. Runs alternated between the two
builds, with at least three runs per cell per build. Main shows no regression in
convergence, reload, flap, IRR, or RR1000 wire timing against v0.72.0. Those
differences sit within run-to-run spread, with three exceptions:

- **Session establishment is consistently slower on main.** The harness
  reported 0.8 s on every main leg and 0.7 s on every control leg; it logs at
  0.1 s resolution, so that reading alone places the delta between just over 0
  and just under 0.2 s. The daemon's own log narrows it: the span from the first
  to the 700th "session established" record is 0.758–0.779 s (median 0.775) on
  main and 0.665–0.686 s (median 0.668) on v0.72.0, about +0.1 s. This is
  unattributed. Several changes to the startup and session-establishment path
  landed between the two builds and are candidate causes: the single-command
  startup roster registration (#2723), holding a collision candidate's
  KEEPALIVE until the collision verdict (#2701; the harness stubs connect
  inbound and are promoted as collision candidates), and bounded nested
  notification drains (#2718). No measurement here isolates any of them.
- **RR1000 staged convergence** is +4.7% at the median.
- **RR1000 wire-point RSS** is about +3% at the median.

Both RR1000 shifts are small and unattributed.

Both builds are slower on this host than the 2026-08-30 v0.68.0 rows in the
[IXP matrix](ixp-matrix-2026-07.md), the [IRR reload receipt](irr-reload-v0680-2026-08.md),
and the [scale receipt](scale-receipt-2026-07.md). Those rows were measured on a
different date. This campaign did not measure v0.68.0, so it cannot say whether
the gap is a regression between the releases or a change on the host. A
same-day v0.68.0 and v0.72.0 comparison is pending.

## Results

S1 comes from the convergence phase of all six S2 and S3 legs per build. The S2
reload values are per-reload p50s over three runs of four reloads. The S3 flap
values are per-round p50s over three runs of three rounds. IRR values are
per-reload p50s over three runs of four reloads. RR1000 values are six runs
(two three-attempt campaigns) per build.

| Cell | v0.72.0 | main `33f8e7142` | Reading |
|---|---:|---:|---|
| S1 sessions established (700), harness reading | 0.7 s (all legs) | 0.8 s (all legs) | Consistent +0.1 s on every leg, at the harness's 0.1 s resolution |
| S1 first-to-700th established, daemon log | 0.665–0.686 s (median 0.668) | 0.758–0.779 s (median 0.775) | +0.107 s median; consistent, unattributed |
| S1 cold convergence, 700 × 400,400 | 3.6–4.0 s (median 3.6) | 3.7–3.9 s (median 3.9) | Within spread |
| S2 policy-reload completion p50 | 1.37–1.63 s (median 1.50) | 1.42–1.75 s (median 1.52) | Within spread |
| S2 changed-observer reload stall p50 | 457–646 ms (median 499) | 463–598 ms (median 527) | Within spread |
| S3 withdraw p50 | 0.26–0.48 s (median 0.37) | 0.25–0.52 s (median 0.39) | Within spread |
| S3 re-announce p50 | 0.48–0.55 s (median 0.50) | 0.50–0.53 s (median 0.52) | Within spread |
| S3 first re-announcement p50 | 0.31–0.34 s | 0.31–0.33 s | Within spread |
| IRR reload, 0% overlap, completion p50 | 1.223–1.438 s (median 1.282) | 1.210–1.316 s (median 1.267) | Within spread |
| IRR reload, 0% overlap, changed-observer gap p50 | 501–592 ms (median 534) | 494–559 ms (median 510) | Within spread |
| RR1000 injection | 33–35 ms | 32–39 ms | Within spread |
| RR1000 staged convergence | 296–317 ms (median 298) | 302–315 ms (median 312) | Median +4.7%; small, unattributed |
| RR1000 first exact wire convergence | 332–351 ms (median 339) | 343–349 ms (median 346) | Within spread (+2.1% median) |

Every cell passed its runner's acceptance:

- **IXP matrix:** 12 of 12 cells passed, with 700/700 sessions in every reload and flap round.
- **IRR reload:** 6 of 6 roots completed. Every row has 320/320 sessions and zero parse errors.
- **RR1000:** all 12 attempts passed the semantic verifier, with 1,000/1,000 sessions.

The RR1000 staged shift is on the RIB side. Neither of the two performance
changes merged on the day touches that path, and the instrument injects routes
directly, so its cause is not identified.

### Memory

| Cell | Measure | v0.72.0 | main `33f8e7142` |
|---|---|---:|---:|
| S2 | Settled process-tree RSS (last 5 s sample) | 384 / 385 / 384 MiB | 388 / 413 / 387 MiB |
| S2 | Peak process-tree RSS sample | 488–567 MiB | 524–583 MiB |
| S2 | Daemon VmHWM | 605–616 MiB | 608–629 MiB |
| S3 | Settled process-tree RSS (last 5 s sample, noisy) | 521 / 593 / 607 MiB | 519 / 576 / 635 MiB |
| S3 | Harness post-flap RSS (after each round) | 401–426 MiB (median 410) | 388–416 MiB (median 408) |
| S3 | Daemon VmHWM | 648–656 MiB | 649–671 MiB |
| IRR 0% | Peak process-tree RSS sample | 651–685 MiB | 658–664 MiB |
| RR1000 | Direct-process VmRSS at wire completion | 372,912–411,892 KiB (median 394,878) | 388,516–420,564 KiB (median 407,208) |

- **S3 settled RSS is noisy.** Its last sample lands at an arbitrary point in the
  reconnect cycle, and within a single run the 5-second samples swing between
  about 376 and 635 MiB. The harness's post-flap readings are the steadier
  S3 measure.
- **RR1000 wire-point RSS** is about +3% at the median: small and unattributed.
- **No cgroup peak.** The matrix runner does not capture a cgroup memory peak
  for the native daemon, so none is reported here.
- **Swap was untouched.** The kernel's swap-in and swap-out counters did not
  change across any run, so VmHWM is not under-reported by swapped pages.

## What these cells cannot show

Two performance changes merged just before this campaign. They target shapes
these headline cells do not exercise:

- **Import-attribute sharing.** It helps when an import policy modifies
  attributes. The matrix scenario's import chain only rejects one out-of-table
  prefix and otherwise accepts without modification.
- **Outbound packing by attribute value.** It helps when routes carry equal
  attributes behind separate allocations; its extra cost falls on tables with
  many distinct attribute sets. Every matrix and IRR stub announces one uniform
  attribute set per member, so neither the benefit nor the cost appears.

The session-level microbenchmarks for both changes are recorded in their pull
requests. These headline cells show that neither change regressed the
established shapes.

## Coverage

- **IRR reload at 10% and 50% overlap was not re-measured.** The IRR runner
  measures a received-view overlap above 0% only as a full cross-daemon root
  (rustbgpd, BIRD, and OpenBGPD). A rustbgpd-only campaign is refused at
  startup, so the 10% and 50% rows remain the dated v0.68.0 observations.
- **BIRD and OpenBGPD** were not run. Their matrix and IRR rows remain dated to
  their own receipts.

## Method

### Builds

- **Candidate:** main at `33f8e7142c4a984812de0ba927b65a842a4db62c`, with main CI
  complete and green on that commit before the first timed run.
- **Control:** the v0.72.0 release tree, `4ff22f7e882d5ade6057eacbe1e7da5613955838`,
  of release commit `dcbac54420dc92d5b0218916b3568598cd154cd0`.
  The IRR runner accepts a measured source only if it is current `origin/main`
  or a descendant of it, and the v0.72.0 tag is an ancestor. So the control ran
  from a local, never-published commit made with `git commit-tree
  v0.72.0^{tree} -p 33f8e7142`. Its tree is byte-identical to the tag, and the
  daemon it produced has the same SHA-256 as a tag build
  (`149f07de098be3f76c818496af227693f7dbb78dc9095a4a03b64773f7379982`).
  Matrix provenance files name that local commit; its tree hash above is the
  verifiable identity.
- **Build command.** Both builds used the IRR runner's command,
  `cargo build --release -p rustbgpd -p rustbgpctl -p rs-config-render`, for
  every cell. Building the three packages together changes the daemon's
  unified feature set. A build of the daemon binary alone produces a different
  hash, so the build command is part of the identity.
- **Other recorded binaries.** Each IRR root's `provenance.json` also records
  hashes for `rbgp`, `rs-config-render`, and `reloadstall`. They are not part of
  the measured daemon identity:
  - `rbgp` differs between the arms because the CLI source differs between
    them (for example #2722). The IRR runner uses `rbgp` only in its
    transaction cells, which this `rustbgpd-sighup` campaign did not run, so it
    is not on any timed path.
  - `rs-config-render` is identical in both arms, so both arms rendered the
    same scenario configuration.
  - `reloadstall` is covered in the next item.
- **Harnesses.** Each build ran its own tree's harnesses. The harness sources
  are identical between the trees. The only difference in the harness binaries
  is that `reloadstall` links `crates/wire`, which carries a small
  OPEN-capability change on main (`crates/wire/src/capability.rs`).

### Host and order

- One AMD Ryzen Threadripper 7970X host, 125 GiB RAM, Linux 7.0, rustc 1.98.1.
  All CPU governors were set to `performance`.
- Background load: a shared local inference service kept one core busy
  throughout. Another development lane ran three `bench/scale` `cargo check`
  builds from about 06:04 to 06:09 on cores 40–63, detailed below. Otherwise no
  builds, test gates, or pushes to main ran during the window. The runners' own quiet gates (one-minute
  load below 2.0 before every matrix and IRR cell, two accepted samples) passed
  each time.
- **Overlap at the start of the window.** From about 06:04 to 06:09 local time,
  another development lane ran three `cargo check` builds of the `bench/scale`
  workspace on cores 40–63, before it saw the window marker; one of them
  failed early. The benchmark cores were 16–23 for the daemon and 24–39 for
  the harness, so the builds used separate cores.
  - **Which run.** The builds overlapped the first matrix run, v0.72.0 run 1
    S2, whose runner was active 06:04:19–06:17:03.
  - **Load at the time.** The campaign logged a one-minute/five-minute/
    fifteen-minute load average of 2.64/3.54/3.24 when that run began.
  - **The quiet gate.** The runner's gate rejected its samples until 06:09:19
    and 06:09:50 (one-minute load 1.84 and 1.59). The daemon started at
    06:09:50 and the first reload came at 06:10:30. The builds therefore
    overlapped the gate wait and ended around the cell start; an overlap with
    the first seconds of that run's cold convergence cannot be ruled out.
  - **Effect of excluding that run** (the other v0.72.0 runs are unchanged):
    - S1: sessions established stays at 0.7 s; cold convergence stays at
      3.6–4.0 s with a median of 3.6 s.
    - S2 completion p50: the range stays 1.37–1.63 s; the median moves from
      1.50 to 1.52 s.
    - S2 changed-observer stall p50: the range stays 457–646 ms; the median
      moves from 499 to 485 ms.
    - S2 peak process-tree RSS: the range narrows from 488–567 MiB to
      488–497 MiB.
    - No main-against-v0.72.0 reading in the results changes.
- Order: strictly sequential, alternating the two builds within every cell type,
  with the runners' 300-second cool-downs. The sequence was matrix S2 then S3
  for each run, then IRR at 0%, then RR1000.

### Shapes and extraction

- **Shapes.** The shapes are the current receipts' canonical shapes:
  - IXP matrix: 700 members × 400,400 routes, four reloads, a 30-second control
    window; S3 with 50 flapping members.
  - IRR: 320 members × 183,040 prefixes, seed 61, four reloads.
  - RR1000: the fixed shape of `rrtransport rr1000`.
- **Matrix extraction.** Matrix values are read from the labeled lines in each
  `reloadstall.log` (`established`, `converged`, `reload N completion_s`,
  `reload N maxgap_ms`, `flap N withdraw_s/reannounce_s/first_reann_s`), not
  from the CSV rows.

## Artifacts

The compact bundle is
[`artifacts/headline-refresh-v0720-2026-09`](artifacts/headline-refresh-v0720-2026-09/README.md):
logs, per-run status and provenance, RSS samples, IRR rows, RR1000 phase
records, the campaign progress log, and a machine-readable `summary.csv` of
every value above. `establishment-span.csv` is derived from the daemon logs,
which stay outside the repository.
