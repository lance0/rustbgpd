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
retains the requested Git commit object plus a `git archive`, proves the
commit object's tree header matches the archive tree, extracts that archive
into a read-only source tree, and sends every Cargo build, scenario
generation, process-fence scan, and final validation through that exact tree;
Cargo output lives in a separate scratch target directory. The validator
reconstructs the Git tree object from the archive and requires its SHA-1 to
equal the retained commit's tree before accepting the bundle. The runner makes
files and directories non-writable and rechecks the complete extracted tree
before and after the build, at the measurement boundary, and after the run. Every
build is capped at 1,800 seconds, scenario generation at 60 seconds, and the
whole harness at 4,200 seconds; the harness additionally caps each stub
connect/OPEN at 15 seconds, all establishment and initial convergence at 120
seconds each, and each reload at 900 seconds. INT/TERM reaches terminal cleanup
that tracks and bounds the harness, health probe, and daemon before escalating
to KILL. The build fence rejects compiler/linker/profile/target overrides and
external Cargo configuration, allowing only the archived regular
`.cargo/config.toml`. Builds use `env -i`, fresh empty home and Cargo-home
directories, the literal
`/usr/bin:/bin` search path, and exact Rust
`1.95.0-x86_64-unknown-linux-gnu`; provenance records the
resolved Cargo/rustc/rustdoc paths and hashes, rustup, toolchain, sysroot, and
host platform. This is a
controlled and provenance-bound host build, not a hermetic container build.
Daemon, harness, and health probes run
under `env -i` with only `LC_ALL=C`, `TZ=UTC`, and daemon-only `RUST_LOG=info`.
Every
retained public text surface (build and daemon output, generated config,
invocation, and provenance included) normalizes host paths, hostname, and
the daemon PID to stable placeholders while preserving the exact source
commit/tree/archive and binary hashes. Unexpected extra artifacts fail
validation rather than escaping that publication-safety contract. The final
host fence inspects process argv, cwd, and descendants, including interpreted
benchmarks and Cargo target binaries; the shared lock remains the first line of
coordination. The exact-source validator accepts only the fixed 700 ×
400,400 shape with four complete alternating-marker cycles, where each cycle
proves exact current receiver-state coverage for its active A or B policy
marker both at completion and after the 20-second quiesce, 700/700
observers, 399,828 expected non-self prefixes per observer, daemon-side
continuity, zero health failures, zero base withdrawals, zero active/inactive
marker conflicts, zero duplicate/malformed/out-of-range/self prefix identities,
and a worst-observer UPDATE gap below 1,000 ms. The generated
global, security, policy, gRPC, and neighbor mappings are exact: extra keys or
policy text invalidate the receipt.
The validator's
adversarial fixtures run with:

```text
cd bench/scale/reloadstall
python3 -m unittest -v test_validate_receipt.py
python3 -m unittest -v test_process_fence.py
python3 -m unittest -v test_build_fence.py
python3 -m unittest -v test_runner_contract.py
```

`SHA256SUMS` covers every retained input, commit object, full source archive, selected source
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
