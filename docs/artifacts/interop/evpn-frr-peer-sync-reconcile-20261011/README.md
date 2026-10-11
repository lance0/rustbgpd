# FRR peer-sync reconciliation and restart receipt

This bounded local proof exercises all-active peer-sync forwarding, two daemon
restart cases and real-kernel reconciliation of incomplete legacy-bridge FDB
pairs. It ran on 2026-10-11 against clean runtime commit
`53b5cb1a1f2dfe7b56306b285211f013b1ae23f6`, FRR 10.7.1 and Linux
`7.0.0-30-generic`.

The [result](result.json) records exact source, executable hashes, image
identities, assertions and exits. Both FRR runs use the same immutable daemon
and CLI, with an empty runtime source delta at execution. The kernel test
binary comes from the same clean source commit. Later receipt-only changes
do not change that provenance.

## Fresh all-active forwarding

The [permanent harness](../../../../tests/interop/peer-sync-frr/README.md)
uses FRR A and rustbgpd B on one bound all-active ES, traditional bridge and
VNI 100, with a real two-port CE 802.3ad bond. Only FRR A learns the target
CE MAC. The remote FRR VTEP builds its own two-member L2 nexthop group.
B remains non-DF with unknown-unicast flooding disabled, accepts the peer's
Type 2 and does not originate a local Type 2 for that MAC.

The fresh run selects the same 34 B-bound flow seeds as the
[pre-fix baseline](../evpn-frr-peer-sync-20261011/README.md). Ten frames per
seed deliver **340/340** through B to the CE bond; the 30-flow FRR A control
delivers **300/300**. Each flow's exact count is checked at VXLAN ingress,
both CE members and the CE bond. The historical baseline delivered 0/340
through B. It was not rerun; its distinct source and executable identities
remain recorded separately.

## Daemon restart cases

The private derivative included in the archive starts with another successful
340/340 B replay and 300/300 A control, then exercises these two cases. Before
each post-restart replay, it waits for the remote FRR nexthop group to contain
both exact PE addresses and rechecks B's non-DF role, flood suppression,
accepted peer route and absence of local Type 2 origination.

| Runtime case | Required transition | Post-convergence replay |
| --- | --- | ---: |
| Retained local peer pair | Exact pair survives kill/restart and observed post-grace reconciliation | 340/340 |
| Marked overlay to peer forwarding | Daemon-created overlay converts to the exact pair before orphan grace expires | 340/340 |

For retained-pair restart, the daemon installs exactly two `extern_learn`
master rows for the target MAC on `es0`/`br100`: untagged and default PVID 1,
with no overlay destination or nexthop ID. The exact pair remains in the
stopped kernel after `SIGKILL`. A separate synthetic marked overlay orphan,
MAC `02:aa:bb:cc:dd:fe`, serves only as a grace-expiry control. The restarted
daemon uses the existing `RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS=5`
override. The exact actor reap message and control row's absence are observed
6.76 seconds after restart. The target pair remains exact in every retained
sample; the live FDB monitor observes the control deletion and no target-MAC
deletion through the post-grace traffic replay.

For overlay conversion, operator drain first makes the real daemon remove
the peer rows and install the target's marked VXLAN row toward FRR A.
`SIGKILL` leaves that row in the kernel. Restart clears the in-memory operator
drain and uses the same documented override set to 120 seconds. Timestamped
observations show the exact local peer pair 0.51 seconds after restart,
before that orphan grace expires. Settled-state checks and the subsequent
340-frame replay pass.

These durations establish the tested ordering; they are not performance
measurements. The production adoption deferral remains 500 seconds. Neither
case forces the target to remain `NotReady` through the orphan deadline or
exercises a foreign VLAN sibling across restart.

## Real-kernel incomplete-pair and takeover controls

A separate network-namespace test runs the actual `ReconcileActor` and
`LinuxDataplane` from the same runtime commit. This is distinct from the
full-daemon FRR topology. The exact test,
`linux_dataplane_peer_sync_local_fdb_forwards_with_flood_off`, passes once,
with zero failures and four other tests filtered out. The archive retains
the complete test source, build log, wrapper, command, binary hash, container
image digest, raw output, exit status and six raw FDB snapshots.

On `eslegacy`/`brlegacy`, VNI 300, the test constructs each incomplete marked
set explicitly: default-PVID 1 only, then untagged only. For each shape,
startup adoption and reconciliation restore both marked rows on the correct
port. Actor shutdown drains the target rows. An unscoped Linux FDB delete
removes the complete pair, so the PVID-only input is explicitly seeded rather
than inferred from that delete.

The PVID-only case also tests takeover after planning. After the reconciler
plans an explicit PVID-row remove followed by the unscoped peer add, the test
replaces that row with an unmarked dynamic row, then repeats with an unmarked
static row. Applying the stale plan preserves each foreign row: remove
returns success without deleting it, add returns an error, and the complete
local-FDB snapshot remains unchanged. These controls exercise fresh backend
guards; they do not establish atomicity between a guard and a kernel write.

## Historical evidence and limits

Both earlier receipt directories remain byte-for-byte unchanged. The
[previous restart receipt](../evpn-frr-peer-sync-restart-20261011/README.md)
contains a separate M67 single-active run with 94 checks passed and zero
failed on `8668288150c1c4c687f0a61a27c09c97a80b4f6c`. That result is
**historical evidence only**: M67 was not rerun as part of this receipt, and
this receipt does not claim M67 passes on the new runtime commit.

The FRR results cover one-way known unicast for one peer-only MAC on one
bound all-active ES. They do not qualify uninterrupted traffic during
restart, all-active carrier failover, return traffic, BUM uniqueness,
VLAN-aware services, scale or performance. The default-PVID sibling is not
VLAN-aware service evidence. Later same-port local-learning promotion is
outside these runtime results.

## Evidence and cleanup

The [archive](evidence.tar.gz) separates `forwarding/`, `restart/` and
`kernel-partial-set/` evidence. It retains raw pcaps, per-flow ledgers, state
snapshots, configs, commands, daemon logs, harness source, timestamped restart
events and cleanup results. `offline-validation.json` records a fresh replay
of all six traffic oracles, nine exact-pair state snapshots, sixteen
restart-pair samples and six kernel snapshots. All 40 pcaps retain their
original bytes.

All six FRR-lab containers and the separate kernel-test container were
removed. Final checks found no proof daemon, named network namespace or
owned live container remaining. Shared resources were preserved.

Absolute workspace/artifact paths in text evidence are replaced with
placeholders, and archive owner names are removed. Set those placeholders
to local paths before reproducing a derivative. Protocol bytes and measured
counts are unchanged. [Checksums](SHA256SUMS) cover the archive and result.
