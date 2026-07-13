# reloadstall

Route-server-scale policy-reload UPDATE-stall driver.

## What it measures

`N` real BGP stub clients dial a running rustbgpd route server over loopback
TCP (real OPEN/KEEPALIVE/UPDATE wire exchange), announce a full table, run
steady churn from a subset of members, then the driver copies successive
`.rpol` generations over the daemon's live policy file and SIGHUPs it. It
records every observer's inter-UPDATE gaps and post-SIGHUP re-advertisement
completion, so it can answer: how long do UPDATEs stall while the route server
reloads a changed import+export policy, under churn, at the receiver.

Stubs bind distinct `127.1.x.y` source addresses with router-ids `240.1.x.y`
(higher than the daemon's, so the inbound connection wins RFC 6286 collision
resolution), use a non-loopback synthetic NEXT_HOP (a `127/8` NEXT_HOP is
rejected with UPDATE error subcode 8; route-server mode passes it through), and
answer ROUTE_REFRESH by re-sending their base slice. It reports per-observer
max-gap / completion percentiles, samples delivered communities to verify which
policy generation is live, and reads daemon RSS from `/proc/<pid>`.

Depends only on `crates/wire` (wire encode/decode for the stub sessions).

## Backs

- `docs/perf/reload-stall-2026-07.md` (LAN-333/LAN-350). The full daemon-side
  scenario (700 `[[neighbors]]` route-server-client blocks, `member-in` /
  `member-out` rpol chains, gRPC UDS, and the two policy generations) is pinned
  here. The corrected historical run remains non-acceptance evidence until the
  durable wrapper below produces a complete validated bundle.

## Retained acceptance run

Run only from the exact clean commit under test, with an output path that does
not exist yet:

```text
bench/scale/reloadstall/run-receipt.sh \
  --source-sha <full-40-hex-clean-HEAD> \
  --output-dir target/reloadstall-receipt/<unique-run-id>
```

`run-receipt.sh` owns the shared host lock, exact-source release builds, short
UDS-safe runtime directory, daemon and health-probe lifecycle, and a timestamped
final load/process/all-governor snapshot immediately before daemon start. It
retains a `git archive` carrying the requested commit marker, extracts that
archive into a read-only source tree, and sends every Cargo build, scenario
generation, process-fence scan, and final validation through that exact tree;
Cargo output lives in a separate scratch target directory. The validator
reconstructs the Git tree object from the archive and requires its SHA-1 to
equal the retained source tree before accepting the bundle. Every
retained public text surface (build and daemon output, generated config,
invocation, and provenance included) normalizes host paths, hostname, and
the daemon PID to stable placeholders while preserving the exact source
commit/tree/archive and binary hashes. Unexpected extra artifacts fail
validation rather than escaping that publication-safety contract. The final
host fence inspects process argv, cwd, and descendants, including interpreted
benchmarks and Cargo target binaries; the shared lock remains the first line of
coordination. The exact-source validator accepts only the fixed 700 ×
400,400 shape with four complete alternating-marker cycles, where each cycle
proves unique prefix coverage for its active A or B policy marker, 700/700
observers, 399,828 expected non-self prefixes per observer, daemon-side
continuity, zero health failures, and a worst-observer UPDATE gap below 1,000 ms.
The validator's
adversarial fixtures run with:

```text
cd bench/scale/reloadstall
python3 -m unittest -v test_validate_receipt.py
python3 -m unittest -v test_process_fence.py
```

`SHA256SUMS` covers every retained input, full source archive, selected source
copy, log, preflight sample, invocation, manifest, and provenance file; only
`SHA256SUMS` itself is excluded. There is deliberately no unsummed
`validation.json`: acceptance is the exact validator's successful exit and JSON
printed by the wrapper after the complete checksum inventory passes. A later
audit should run `validate_receipt.py` from the named source commit (or from a
separately verified extraction of `sources/source.tar`) against the bundle.

## Build and run

Standalone crate (not a workspace member — build it explicitly):

```text
cd bench/scale/reloadstall
cargo build --release
./target/release/reloadstall <n_peers> <total_prefixes> <daemon_port> \
    <daemon_pid> <policy_live> <policy_a> <policy_b> <reloads> <control_secs>
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
    <policy_live> <policy_a> <policy_b> <reloads> <control_secs>
```

- `n_peers` — stub sessions to establish (`total_prefixes` must divide evenly).
- `total_prefixes` — base-table size; each stub owns `total/n_peers` /24s.
- `daemon_port` / `daemon_pid` — the running daemon's listen port and PID (PID
  is used for SIGHUP and RSS sampling).
- `policy_live` — the daemon's live `.rpol` file (copied over each reload).
- `policy_a` / `policy_b` — the two policy generations (alternated per reload).
- `reloads` — number of SIGHUP reload cycles.
- `control_secs` — quiet control-window length (baseline inter-UPDATE gap).

Underlying harness shape (heavy; manual invocation is mechanics-only and does
not create an acceptance receipt):

```text
reloadstall 700 400400 <port> <daemon_pid> <live.rpol> <gen-a.rpol> <gen-b.rpol> 4 30
```
