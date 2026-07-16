# reloadstall

Route-server-scale policy-reload UPDATE-stall driver.

## What it measures

`N` real BGP stub clients dial a running rustbgpd route server over loopback
TCP (real OPEN/KEEPALIVE/UPDATE wire exchange), announce a full table, run
steady churn from a subset of members, then the driver copies successive
`.rpol` generations over the daemon's live policy file and SIGHUPs it. It
records every observer's inter-UPDATE gaps and post-SIGHUP re-advertisement
completion, so it can answer: how long do UPDATEs stall while the route server
reloads policy under churn, at the receiver. It supports both the historical
all-peer import+export change and a mixed export-only change where only a prefix
of the peer fleet should receive a new export generation.

Stubs bind distinct `127.1.x.y` source addresses with router-ids `240.1.x.y`
(higher than the daemon's, so the inbound connection wins RFC 6286 collision
resolution), use a non-loopback synthetic NEXT_HOP (a `127/8` NEXT_HOP is
rejected with UPDATE error subcode 8; route-server mode passes it through), and
answer ROUTE_REFRESH by re-sending their base slice. It reports per-observer
max-gap / completion percentiles, samples delivered communities to verify which
policy generation is live, and reads daemon RSS from `/proc/<pid>`. In mixed
mode, completion is measured only for changed observers, while max-gap and
session-health checks still cover the full fleet. After every changed observer
has completed the new generation, the harness resets its evidence threshold;
every stable observer must then receive a fresh announced UPDATE carrying the
`stable-out` community marker. Steady churn supplies that independent proof. A
reload is rejected before its CSV row if any session is down, post-completion
stable-marker evidence is missing, or a daemon UPDATE fails to decode. Each
valid reload emits a `reloadstall_csv` record for durable raw receipts.

Depends only on `crates/wire` (wire encode/decode for the stub sessions).

## Backs

- `docs/perf/reload-stall-2026-07.md` (LAN-333). The full daemon-side scenario
  (700 `[[neighbors]]` route-server-client blocks, `member-in` / `member-out`
  rpol chains, gRPC UDS, and the two policy generations) is pinned there.

## Build and run

Standalone crate (not a workspace member — build it explicitly):

```text
cd bench/scale/reloadstall
cargo build --release
./target/release/reloadstall <n_peers> <total_prefixes> <daemon_port> \
    <daemon_pid> <policy_live> <policy_a> <policy_b> <reloads> <control_secs> \
    [changed_peers]
```

The daemon must already be running (load-gated `--release` start) with
`n_peers` route-server-client neighbors and its live policy file at
`<policy_live>`; `<policy_a>` / `<policy_b>` are the two generations copied over
it on alternating reloads.

## Arg contract

From `src/main.rs` (fewer than 9 positional args prints the usage string and
exits 2):

```text
reloadstall <n_peers> <total_prefixes> <daemon_port> <daemon_pid> \
    <policy_live> <policy_a> <policy_b> <reloads> <control_secs> \
    [changed_peers] [reload_cmd] [--flapstorm K]
```

- `n_peers` — stub sessions to establish (`total_prefixes` must divide evenly).
- `total_prefixes` — base-table size; each stub owns `total/n_peers` /24s.
- `daemon_port` / `daemon_pid` — the running daemon's listen port and PID (PID
  is used for SIGHUP and RSS sampling).
- `policy_live` — the daemon's live `.rpol` file (copied over each reload).
- `policy_a` / `policy_b` — the two policy generations (alternated per reload).
- `reloads` — number of SIGHUP reload cycles.
- `control_secs` — quiet control-window length (baseline inter-UPDATE gap).
- `changed_peers` — optional number of leading observers whose effective export
  chain changes. Completion waits only for these observers; all-observer gap and
  session checks still include every peer. Omit it for the historical all-peer
  import+export scenario.
- `reload_cmd` — optional (IXP matrix, LAN-334): each reload runs
  `sh -c <reload_cmd>` (e.g. `docker exec <c> birdc configure`) instead of
  SIGHUP-ing `daemon_pid`; a nonzero exit fails the run like a failed SIGHUP.
  The policy-file copy still happens first, so for BIRD/OpenBGPD the "policy"
  files are the generation include/rule files.
- `--flapstorm K` — optional flag (anywhere in argv): alternative mode
  replacing the reload loop. After convergence + the control window, the first
  `K` stubs (never the churners) are closed simultaneously; every survivor
  timestamps receipt of all `K` slices' withdrawals, the `K` reconnect after
  10 s and re-announce, and survivors timestamp re-announce completion.
  3 rounds, per-round percentiles plus `flapstorm_csv` records.

`daemon_pid` may be `0` when an outer sampler owns RSS measurement (RSS
columns report 0); that requires `reload_cmd` or `--flapstorm`. The
9/10-positional-arg SIGHUP invocation above is a frozen contract and behaves
exactly as before.

Cross-daemon cells (BIRD 3.3.1 / OpenBGPD 9.1) generate their route-server
configs with `gen-bird-scenario.py` / `gen-obgpd-scenario.py` (same
addressing contract) and are sequenced by `bench/scale/matrix/run-matrix.sh`.

Generate matching daemon configuration and policy generations with:

```text
python3 gen-scenario.py <n_peers> <out_dir> [listen_port] [changed_peers]
```

When `changed_peers` is supplied, the generator keeps
`member-in` byte-for-byte stable, changes `member-out` between generations for
the leading observers, and assigns the remaining observers a content-stable
`stable-out` chain.

Receipt run shape (heavy — 700 real sessions × 400k routes; do not run casually):

```text
python3 gen-scenario.py 700 <scenario-dir> 1790 600
reloadstall 700 400400 <port> <daemon_pid> <live.rpol> <gen-a.rpol> <gen-b.rpol> 4 30 600
```
