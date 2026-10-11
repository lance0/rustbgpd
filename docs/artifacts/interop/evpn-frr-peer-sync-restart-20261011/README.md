# FRR peer-sync restart and single-active regression receipt

This bounded local proof qualifies peer-sync forwarding and two restart cases
on an all-active FRR topology, plus the separate M67 single-active recovery
regression. It ran on 2026-10-11 against clean runtime commit
`8668288150c1c4c687f0a61a27c09c97a80b4f6c`, FRR 10.7.1 and Linux
`7.0.0-30-generic`.

Every new run uses the same immutable daemon and CLI pair. The [result](result.json)
records their hashes, exact source, image identities, assertions and exits.
The runtime source delta was empty when the FRR runs started. Subsequent
receipt-only commits do not change that runtime provenance.

## Fresh all-active forwarding

The [permanent harness](../../../../tests/interop/peer-sync-frr/README.md)
uses FRR A and rustbgpd B on one bound all-active ES, traditional bridge and
VNI 100, with a real two-port CE 802.3ad bond. Only FRR A learns the target
CE MAC. The remote FRR VTEP builds its own two-member L2 nexthop group.
B remains non-DF with unknown-unicast flooding disabled, accepts the peer's
Type 2 and does not originate a local Type 2 for that MAC.

The fresh run selects exactly the same 34 B-bound flow seeds as the
[historical pre-fix baseline](../evpn-frr-peer-sync-20261011/README.md).
Replaying ten frames per seed delivers 340/340 through B to the CE bond;
the 30-flow FRR A control delivers 300/300. Each flow's exact count is
checked at VXLAN ingress, both CE members and the CE bond. The historical
baseline delivered 0/340 through B. It was not rerun: its source and CLI
identities are recorded separately, and all four historical receipt files
remain byte-for-byte unchanged.

## Restart cases

The private derivative retained in the archive executes these two cases
against the real daemon. Its post-restart traffic checks wait for the remote
FRR nexthop group to contain both exact PE addresses, and recheck B's
non-DF role, flood suppression, accepted peer route and absence of local
Type 2 origination.

| Runtime case | Required state transition | Post-convergence replay |
| --- | --- | ---: |
| Retained local peer pair | Exact pair survives kill/restart and an observed post-grace reconciliation | 340/340 |
| Marked overlay to peer forwarding | Daemon-created overlay converts to the exact peer pair before orphan grace expires | 340/340 |

For the retained-pair case, the daemon first installs exactly two
`extern_learn` master rows for the target MAC on `es0`/`br100`: untagged and
default PVID 1, with no overlay destination or nexthop ID. After `SIGKILL`,
the stopped kernel still contains that pair. A separate synthetic marked
overlay orphan, MAC `02:aa:bb:cc:dd:fe`, is inserted solely as a grace-expiry
control. The restarted daemon uses the existing
`RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS=5` override. The exact actor reap
message and the control row's absence are observed 6.75 seconds after
restart. The target pair remains exact in the samples; the live FDB monitor
observes the control deletion and no target-MAC deletion through the
post-grace traffic replay.

For overlay conversion, an operator drain first makes the real daemon
remove its peer rows and install the target's marked VXLAN row toward
FRR A. The daemon is killed with that overlay row still present. Restart
clears the in-memory operator drain and uses the same documented override
set to 120 seconds. Timestamped observations show the exact local peer
pair 0.51 seconds after restart, before that orphan grace expires. The
subsequent settled-state checks and 340-frame replay pass.

These durations establish the tested ordering; they are not performance
measurements. The production adoption deferral remains 500 seconds.
Neither case exercises a foreign VLAN sibling across restart. The
historical active foreign-drain experiment does not supply that coverage.

## Separate M67 single-active recovery

The unchanged full M67 driver passes **94 checks, zero failures**, with
`M67_RERUN=0`. Its original checks cover carrier-driven withdrawal,
held-off recovery, local Type 2 return after the CE broadcast, ping
recovery, flap damping, operator/link drain composition and foreign-state
preservation. This is a single-active regression result; it does not
qualify all-active carrier failover.

The standard topology's links, configs, setup commands and pre-link stages
are preserved. A private wrapper selects an isolated Ubuntu 24.04 tooling
image and management network, retains the original bind files, and mounts
the immutable daemon/CLI read-only. It verifies both executable hashes in
all five nodes. The carrier is identified separately from the runtime
source. Read-only FDB, port, nexthop, route and segment samples accompany
the unchanged driver; the observer adds no traffic stimulus.

Two earlier local qualification attempts failed: copied startup files
initially lost their executable modes, and an older carrier subsequently
emitted a CLI loader warning that invalidated the combined-output JSON
checks. Neither attempt counts as a pass. Both executables' version/help
probes on the final carrier exit successfully with empty stderr before
the final complete M67 run.

## Evidence and limits

The [archive](evidence.tar.gz) contains separate `forwarding/`, `restart/`
and `m67/` runs, the final carrier recipe/probes, and the offline pcap replay
checks. It retains raw pcaps, per-flow ledgers, state snapshots, configs,
commands, daemon logs, harness source, timestamped restart events and
cleanup results. All eleven containers from the qualified lab runs and
the four carrier-probe containers were removed. Owned networks and image
tags were removed; no proof daemon or named network namespace remained.

Absolute workspace/artifact paths in derivative sources and metadata are
replaced with placeholders, and archive owner names are removed. Set those
placeholders to local paths before reproducing a derivative. Protocol bytes
and measured counts are unchanged. [Checksums](SHA256SUMS) cover the archive
and result.

The FRR claims cover one-way known unicast for one peer-only MAC on one
bound all-active ES. They do not qualify uninterrupted traffic during
restart, return traffic, BUM uniqueness, VLAN-aware services, scale or
performance. The default-PVID sibling is not VLAN-aware service evidence.
Ownership atomicity and later same-port local-learning promotion remain
outside these passing results; the M67 scope restriction does not establish
all-active local-learning convergence.
