# LAN-409 IXP exact-export cohort artifacts

This directory retains the raw, normalized Criterion medians and deterministic
production-state-machine counters for the IXP exact-export cohort campaign.
All durations are nanoseconds. The fixture-only baseline is commit
`5ba459833190b72cc1f1c348155557ed0d090ff1`, stacked on
`89208314c018e43af55233ccefb26eaf32eb330a`.

Environment: Linux 6.17.0-35-generic x86_64, AMD Ryzen Threadripper 7970X,
`rustc 1.97.0 (2d8144b78 2026-07-07)`, Criterion 0.8, workspace release
profile, CPU 7 pinned with the `performance` governor. The initial one-minute
load average was 2.21 on a 64-logical-CPU host.

The first-advertise matrix used 64 IPv4 unicast routes and 8, 64, or 256
eBGP route-server clients. The transition matrix used 4,096 routes and 64 or
700 clients. `homogeneous_remote_asn` assigns AS 65001 to every client;
`distinct_remote_asns` assigns consecutive ASNs beginning at 65001. Manager
and transport fixtures agree on eBGP mode, route-server-client mode, local
address, and capabilities.

Reproduce a first-advertise revision with a private target directory shared
between the baseline and optimized worktrees:

```console
taskset -c 7 env CARGO_TARGET_DIR="$TARGET" \
  cargo bench -p rustbgpd-transport --features bench-internals \
  --bench fanout -- 'ixp_exact_export_fanout' \
  --warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot
```

Reproduce one transition cell and its counter receipt (set
`RUSTBGPD_IXP_LARGE_RECEIPT=1` for 700 peers):

```console
taskset -c 7 env CARGO_TARGET_DIR="$TARGET" \
  RUSTBGPD_POLICY_TRANSITION_RECEIPT=1 \
  cargo bench -p rustbgpd-transport --features bench-internals \
  --bench fanout -- \
  'ixp_policy_regroup_resync/shared_plan/distinct_remote_asns/4096/64' \
  --warm-up-time 1 --measurement-time 2 --sample-size 10 --noplot
```

Criterion's `median.point_estimate` and median confidence bounds are retained
verbatim in the CSV. Counter receipts are the first measured production state
machine invocation emitted by the benchmark process.
