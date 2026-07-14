# Reproduce the mixed export-policy reload campaign

Run the variants serially on an otherwise idle host. The recorded campaign used
Linux 6.17.0-35-generic, `rustc 1.97.0 (2d8144b78 2026-07-07)`, and an AMD Ryzen
Threadripper 7970X 32-Core CPU. Do not run the two 700-session daemons or
harnesses concurrently. Use short scenario paths because the generated gRPC
Unix socket must fit `sun_path`.

Prepare isolated worktrees and target directories:

```console
git clone https://github.com/lance0/rustbgpd.git rustbgpd-policy-reload-receipt
cd rustbgpd-policy-reload-receipt

BASE_SHA=a170ab0f38fd97cc294d56ba5f283c7221c2c166
CANDIDATE_SHA=fa2759e9b19ecbc00f245c6d07e520e8f28e0882
BASE_WORKTREE=/tmp/rbgp-reload-base
CANDIDATE_WORKTREE=/tmp/rbgp-reload-candidate
BASE_TARGET=/tmp/rbgp-reload-base-target
CANDIDATE_TARGET=/tmp/rbgp-reload-candidate-target

git worktree add --detach "$BASE_WORKTREE" "$BASE_SHA"
git worktree add --detach "$CANDIDATE_WORKTREE" "$CANDIDATE_SHA"

(cd "$BASE_WORKTREE" &&
  CARGO_TARGET_DIR="$BASE_TARGET" cargo build --release --bin rustbgpd)
(cd "$CANDIDATE_WORKTREE" &&
  CARGO_TARGET_DIR="$CANDIDATE_TARGET" cargo build --release --bin rustbgpd)
(cd "$CANDIDATE_WORKTREE/bench/scale/reloadstall" &&
  CARGO_TARGET_DIR="$CANDIDATE_TARGET/reloadstall" cargo build --release)
```

Generate two fresh copies of the exact 600-changed / 100-stable fixture:

```console
python3 "$CANDIDATE_WORKTREE/bench/scale/reloadstall/gen-scenario.py" \
  700 /tmp/rbgp-reload-base-run 1911 600
python3 "$CANDIDATE_WORKTREE/bench/scale/reloadstall/gen-scenario.py" \
  700 /tmp/rbgp-reload-candidate-run 1912 600
```

Wait until the one-minute load average is below 2.0 before each daemon start.
Start the base daemon, record its PID, then run the frozen harness:

```console
"$BASE_TARGET/release/rustbgpd" \
  /tmp/rbgp-reload-base-run/config.toml \
  > /tmp/rbgp-reload-base-run/daemon.log 2>&1 &
BASE_PID=$!

"$CANDIDATE_TARGET/reloadstall/release/reloadstall" \
  700 400400 1911 "$BASE_PID" \
  /tmp/rbgp-reload-base-run/member.rpol \
  /tmp/rbgp-reload-base-run/gen-a.rpol \
  /tmp/rbgp-reload-base-run/gen-b.rpol \
  4 30 600 | tee /tmp/rbgp-reload-base-run/harness.log
```

Stop the base daemon and verify that its PID, port, and children are gone before
starting the candidate. Generate a fresh candidate scenario if any file was
modified. Then run the candidate identically on its isolated port:

```console
"$CANDIDATE_TARGET/release/rustbgpd" \
  /tmp/rbgp-reload-candidate-run/config.toml \
  > /tmp/rbgp-reload-candidate-run/daemon.log 2>&1 &
CANDIDATE_PID=$!

"$CANDIDATE_TARGET/reloadstall/release/reloadstall" \
  700 400400 1912 "$CANDIDATE_PID" \
  /tmp/rbgp-reload-candidate-run/member.rpol \
  /tmp/rbgp-reload-candidate-run/gen-a.rpol \
  /tmp/rbgp-reload-candidate-run/gen-b.rpol \
  4 30 600 | tee /tmp/rbgp-reload-candidate-run/harness.log
```

The live file starts at generation A; four reloads alternate B, A, B, A. A
valid run emits four `reloadstall_csv` rows. Preserve the preceding
`reloadstall_csv_header`, the control-window row, the source and binary hashes,
and the daemon's `config reload complete`, `partitioned resolved policy
snapshot`, `RIB export-policy transition completed`, and `committed partitioned
resolved policy snapshot` events. Prefix each raw row with its variant and exact
source SHA when assembling
`mixed-policy-reload-600-changed-100-unchanged.csv`. Reject a run if any row
reports fewer than 700 sessions, fewer than 100 stable-marker peers, or a
nonzero parse-error count.

The recorded campaign exposed a post-measurement shutdown wedge. Send SIGINT
only after the fourth valid row, retain the teardown log, and do not mistake
forced cleanup after the recorded wedge for part of reload timing.
