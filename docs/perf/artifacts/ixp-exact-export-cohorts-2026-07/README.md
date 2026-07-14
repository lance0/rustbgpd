# IXP exact-export cohort artifacts

This directory retains normalized aggregate Criterion summaries and
deterministic production-state-machine counters for the IXP exact-export cohort
campaign. The CSVs do not contain raw samples. All durations are nanoseconds.
The measured fixture-only baseline is commit
`a47c618ebb7cdf9c99a48e6bd7ed753f42cac664`. The measured wire-equivalence
optimization is commit `828e7a7f7be2a27d2556341320fe2dfc036d7e1a`.

Environment: Linux 6.17.0-35-generic x86_64, AMD Ryzen Threadripper 7970X,
`rustc 1.97.0 (2d8144b78 2026-07-07)`, Criterion 0.8, workspace release
profile, CPU 7 pinned with the `performance` governor. Immediately before the
definitive serial campaign, the process audit found no `cargo`, `rustc`,
`fanout`, or `rustbgpd` process, and the load averages were 0.56, 1.26, and
1.69. An earlier run that overlapped another test process was stopped and its
results were discarded.

The first-advertise matrix used 64 IPv4 unicast routes and 8, 64, or 256
eBGP route-server clients. The transition matrix used 4,096 routes and 64 or
700 clients. `homogeneous_remote_asn` assigns AS 65001 to every client;
`distinct_remote_asns` assigns consecutive ASNs beginning at 65001. Manager
and transport fixtures agree on eBGP mode, route-server-client mode, local
address, and capabilities. The fixtures are groupable plain single-best peers;
per-client-best and Add-Path peers remain ungrouped and are outside this
shared-cohort receipt.

Criterion's `iter_batched_ref` setup closure registers peers, seeds the Loc-RIB,
and drains initial output outside the timed routine. The first-advertise cells
time only distribution, and the transition cells time only the production
policy-transition routine. Counter CSV rows record the first measured
production-state-machine invocation, not setup work.

The two pinned worktrees compiled into separate clean target directories. This
prevents Cargo from treating a binary produced by the other worktree as fresh.
After every baseline cell completed, the baseline target's `criterion/`
directory was copied byte-for-byte into the optimized target. The optimized
binary was then compiled from its pinned commit and invoked with the matching
Criterion baseline name. Criterion's paired change therefore compares the
exact retained baseline samples without sharing build outputs across revisions.

Bootstrap both PR-only source commits and isolated worktrees from a fresh
clone before running the commands below:

```console
git clone https://github.com/lance0/rustbgpd.git rustbgpd-ixp-receipt
cd rustbgpd-ixp-receipt
git fetch origin refs/pull/885/head:refs/remotes/origin/pr-885

BASE_WORKTREE=/tmp/rustbgpd-ixp-baseline
HEAD_WORKTREE=/tmp/rustbgpd-ixp-optimized
BASE_TARGET=/tmp/rustbgpd-ixp-baseline-target
HEAD_TARGET=/tmp/rustbgpd-ixp-optimized-target

git worktree add --detach "$BASE_WORKTREE" a47c618ebb7cdf9c99a48e6bd7ed753f42cac664
git worktree add --detach "$HEAD_WORKTREE" 828e7a7f7be2a27d2556341320fe2dfc036d7e1a
```

Reproduce the first-advertise comparison from the two pinned worktrees:

```console
(cd "$BASE_WORKTREE" &&
taskset -c 7 env CARGO_TARGET_DIR="$BASE_TARGET" \
  cargo bench -p rustbgpd-transport --features bench-internals \
  --bench fanout -- 'ixp_exact_export_fanout' \
  --warm-up-time 1 --measurement-time 2 --sample-size 20 \
  --save-baseline terminal-clean-raw-peer-asn --noplot)

mkdir -p "$HEAD_TARGET/criterion"
cp -a "$BASE_TARGET/criterion/." "$HEAD_TARGET/criterion/"

(cd "$HEAD_WORKTREE" &&
taskset -c 7 env CARGO_TARGET_DIR="$HEAD_TARGET" \
  cargo bench -p rustbgpd-transport --features bench-internals \
  --bench fanout -- 'ixp_exact_export_fanout' \
  --warm-up-time 1 --measurement-time 2 --sample-size 20 \
  --baseline terminal-clean-raw-peer-asn --noplot)
```

Reproduce one transition cell and its counter receipt. The baseline run used a
cell-specific `--save-baseline` name; after copying `criterion/` as above, the
optimized run used the same name with `--baseline`. Set
`RUSTBGPD_IXP_LARGE_RECEIPT=1` for 700 peers.

```console
(cd "$BASE_WORKTREE" &&
taskset -c 7 env CARGO_TARGET_DIR="$BASE_TARGET" \
  RUSTBGPD_POLICY_TRANSITION_RECEIPT=1 \
  cargo bench -p rustbgpd-transport --features bench-internals \
  --bench fanout -- \
  'ixp_policy_regroup_resync/shared_plan/distinct_remote_asns/4096/64' \
  --warm-up-time 1 --measurement-time 2 --sample-size 10 \
  --save-baseline terminal-clean-distinct-64 --noplot)

mkdir -p "$HEAD_TARGET/criterion"
cp -a "$BASE_TARGET/criterion/." "$HEAD_TARGET/criterion/"

(cd "$HEAD_WORKTREE" &&
taskset -c 7 env CARGO_TARGET_DIR="$HEAD_TARGET" \
  RUSTBGPD_POLICY_TRANSITION_RECEIPT=1 \
  cargo bench -p rustbgpd-transport --features bench-internals \
  --bench fanout -- \
  'ixp_policy_regroup_resync/shared_plan/distinct_remote_asns/4096/64' \
  --warm-up-time 1 --measurement-time 2 --sample-size 10 \
  --baseline terminal-clean-distinct-64 --noplot)
```

Criterion's aggregate `median.point_estimate` and median confidence bounds are
retained verbatim in the CSV summaries. The optimized CSV also retains
Criterion's paired mean change estimate and confidence bounds. Counter receipts
are the first measured production state-machine invocation emitted by the
benchmark process.
