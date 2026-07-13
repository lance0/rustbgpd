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

- `docs/perf/reload-stall-2026-07.md`. The full daemon-side
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
first fetches the declared baseline and requested source SHA directly from the
hard-coded `https://github.com/lance0/rustbgpd.git` remote into a fresh bare
repository. Mutable branch tips are recorded only as context, never used as
source authority. A failed exact-SHA fetch, including a network failure, fails
the run closed. From those canonical objects it retains the requested commit
object, a `git archive`, the exact fetch command and object IDs, and a
self-contained Git bundle advertising only `refs/receipt/baseline` and
`refs/receipt/source`. Before building, the runner imports that bundle into a
second fresh bare repository, requires the imported commit bytes and tree to
match the retained evidence, and runs a strict Git object check. It then
extracts the archive into a
read-only source tree and sends every Cargo build, scenario
generation, process-fence scan, and final validation through that exact tree;
Cargo output lives in a separate scratch target directory. The validator
repeats the fresh-repository bundle import, then reconstructs the Git tree
object from the archive and requires its SHA-1 to equal the imported commit's
tree before accepting the receipt. The runner makes
files and directories non-writable and rechecks the complete extracted tree
before and after the build, at the measurement boundary, and after the run. Every
build is capped at 1,800 seconds, scenario generation at 60 seconds, and the
whole harness at 4,200 seconds; the harness additionally caps each stub
connect/OPEN at 15 seconds, all establishment and initial convergence at 120
seconds each, and each reload at 900 seconds. INT/TERM reaches terminal cleanup
that tracks and bounds the harness, health probe, and daemon before escalating
to KILL. The build fence rejects compiler/linker/profile/target overrides and
external Cargo configuration, allowing only the archived regular
`.cargo/config.toml`. The runner must be executed directly through its
privileged-mode Bash shebang; sourced or unprivileged-interpreter invocation,
inherited aliases or shell functions, shell startup hooks, ambient Rust
selection variables, and a non-literal `PATH` fail closed. Rustup
is the invoking account's regular, non-symlinked, owner-safe
`~/.cargo/bin/rustup`; every selection query runs by absolute path under
`env -i`, and Cargo/rustc/rustdoc must resolve to owner-safe absolute binaries
inside the exact `1.95.0-x86_64-unknown-linux-gnu` toolchain. Builds use fresh
empty home and Cargo-home directories plus the literal `/usr/bin:/bin` search
path. Every receipt-authority Python path uses `/usr/bin/python3 -I -S` under
an exact `env -i` whitelist, so ambient `PYTHONPATH`, `PYTHONSTARTUP`, user-site
packages, and `sitecustomize` cannot alter build/process fences, scenario
generation, receipt construction, or validation. Provenance records that
interpreter contract plus the resolved Rust tool paths and hashes, rustup,
toolchain, sysroot, and host platform. This is a
controlled and provenance-bound host build, not a hermetic container build.
Daemon, harness, and health probes run
under `env -i` with only `LC_ALL=C`, `TZ=UTC`, and daemon-only `RUST_LOG=info`.
Every
retained public text surface (build and daemon output, generated config,
invocation, and provenance included) normalizes host paths, hostname, and
the daemon PID to stable placeholders while preserving the exact source
commit/tree/archive and binary hashes. Unexpected extra artifacts fail
validation rather than escaping that publication-safety contract. The final
host fence inspects process argv, cwd, executable, state, and descendants,
including interpreted benchmarks and Cargo target binaries. Missing cwd/exe
links are accepted only for a `/proc/<pid>/stat`-proven zombie or kernel thread;
an incomplete ordinary live record fails closed. The shared lock remains the
first line of coordination. The exact-source validator accepts only the fixed 700 ×
400,400 shape with four complete alternating-marker cycles, where each cycle
proves exact current receiver-state coverage for its active A or B policy
marker after the full 20-second quiesce, 700/700
observers, 399,828 expected non-self prefixes per observer, daemon-side
continuity, zero health failures, zero base withdrawals, zero active/inactive
marker conflicts, zero duplicate/malformed/out-of-range/self prefix identities,
and a worst-observer UPDATE gap below 1,000 ms. Completion and maximum-gap
metrics are computed only after quiesce from the final authoritative completion
timestamp, so a late revoke/reassert sequence extends both measurement windows.
The generated
global, security, policy, gRPC, and neighbor mappings are exact: extra keys or
policy text invalidate the receipt.
The validator's
adversarial fixtures run with:

```text
cd bench/scale/reloadstall
receipt_python=(
  /usr/bin/env -i LC_ALL=C TZ=UTC HOME=/nonexistent PATH=/usr/bin:/bin
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S
)
"${receipt_python[@]}" "$PWD/test_validate_receipt.py" -v
"${receipt_python[@]}" "$PWD/test_process_fence.py" -v
"${receipt_python[@]}" "$PWD/test_build_fence.py" -v
"${receipt_python[@]}" "$PWD/test_runner_contract.py" -v
```

`SHA256SUMS` covers every retained input, commit object, self-contained Git
bundle, full source archive, selected source copy, log, preflight sample,
invocation, manifest, and provenance file; only
`SHA256SUMS` itself is excluded. There is deliberately no unsummed
`validation.json`: acceptance is the exact validator's successful exit and JSON
printed by the wrapper after the complete checksum inventory passes. Validation
always repeats the exact-SHA fetch from the hard-coded canonical remote in a
fresh repository; it does not accept a retained bundle as proof of canonical
membership. The retained bundle, commit, archive, and fetch record support
offline integrity and source reconstruction, but an offline-only check is not
an acceptance result. A later acceptance audit should run
`validate_receipt.py` from the named source commit with canonical network access
through the same absolute, isolated Python command shown above;
the validator also independently imports `sources/source.bundle` into a fresh
repository before trusting the retained commit/archive relationship.

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
