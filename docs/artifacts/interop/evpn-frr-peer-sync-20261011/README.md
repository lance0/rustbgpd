# FRR all-active peer-only MAC forwarding receipt

This bounded local proof records zero loss through a non-DF rustbgpd ES member
for a CE MAC learned only by its FRR peer, against a pre-fix loss reproduction.
It ran on 2026-10-11 with FRR 10.7.1 and Linux `7.0.0-30-generic`.

FRR A and rustbgpd B share a bound all-active ES, traditional bridge, VNI 100
and a real two-port CE 802.3ad bond. Their LACP system ID is shared;
`highest-preference` elects FRR A at preference 200 over B at 100. The CE
source frame is sent explicitly on its FRR-facing bond member, while both
members remain active. FRR A dynamically learns the MAC and advertises its
ESI-tagged Type 2. The remote FRR VTEP constructs its own two-member L2
nexthop group; the harness does not insert or replace that group.

A 64-flow discovery identifies 34 distinct hashes selecting rustbgpd B and
30 selecting FRR A. The same seeds select the same members in both runs.
Each selected flow is then repeated ten times. Captures match every flow's
exact count on the PE VXLAN ingress, each CE member, and the CE bond itself.

| Source | Path | Flows | Decapsulated | Accepted by CE bond | Loss |
| --- | --- | ---: | ---: | ---: | ---: |
| Pre-fix `0a73ba716ac0` | Non-DF rustbgpd B | 34 | 340 | 0 | 100% |
| Fixed `7c694dbf38ce` | Non-DF rustbgpd B | 34 | 340 | 340 | 0% |
| Pre-fix control | FRR A | 30 | 300 | 300 | 0% |
| Fixed control | FRR A | 30 | 300 | 300 | 0% |

The baseline has no CE-MAC FDB row on B. The fixed daemon installs its
`extern_learn` master rows on B's `es0`. Linux creates the exact untagged
and default-PVID-1 pair for this unscoped legacy-bridge add. Both rows must
carry the marker, name the same port and bridge, and contain no overlay
next hop. B remains non-DF with unknown-unicast flooding disabled, accepts
the peer's Type 2, and does not originate a local CE-MAC Type 2 before or
after the traffic test.

The first fixed run stopped before traffic because the original oracle
expected one row. Its failure, raw two-row snapshot and successful cleanup
are retained in `fixed-initial-row-shape/`. The corrected oracle requires
exactly the observed pair and rejects a foreign sibling, a wrong port,
a missing sibling, an extra or wrong VLAN, and an overlay destination.
Thirteen offline tests also reject missing decapsulation, wrong-link or
bond delivery, and equal packet totals that hide a missing flow.

The [result](result.json) records the complete source revisions, executable
hashes, FRR image identity, seeds, counts and exits. The baseline executable
and CLI hashes match the earlier exact-source reproduction at
`0a73ba716ac0a83e5bb9977e0fab4f88f6b54cc9`. The fixed daemon was built from
clean commit `7c694dbf38cef1ed19e463a1c74dbf8257cae9ff`; the retained baseline
CLI was used for both runs. The fixed runtime source delta was empty at
execution. The later oracle correction affects only the harness.

The [evidence archive](evidence.tar.gz) contains `baseline/`, `fixed/`, the
initial row-shape failure, `active-foreign-drain/`, and `ownership/`. It retains raw pcaps, decoded
per-flow ledgers, FDB/NHG/EVPN snapshots, LACP state, counters, commands,
generated configs, daemon logs and each run's harness source. All twelve
containers from the archived runs were confirmed absent afterward; the
fixed runs also record each removal's successful exit. Host-specific paths
in the ownership source excerpt and derivative runner were replaced with `<repo>` and
`<cargo-registry>`, and archive owner names were removed. Protocol bytes
and captured counts are unchanged. [Checksums](SHA256SUMS) cover the archive
and summary.

An additional actual-daemon transition in `active-foreign-drain/` first
establishes the owned row pair, replaces only PVID 1 with an unmarked
static row on `es0`, then operator-drains the segment. Three peer-row
removal conflicts (the first attempt plus two retries) and five deferred
remote-FDB additions are recorded in the actor log. All five FDB samples
retain the foreign PVID row and contain no overlay row. This qualifies
the active peer-to-remote drain guard for that controlled state. It does
not exercise a restart, adoption, or an arbitrary concurrent writer.
The derivative runner's `<repo>` path must be set to a checkout before
reproduction; the permanent forwarding harness remains unchanged by this
extra experiment.

The ownership controls record remaining limits. Ordinary raw-netlink
`CREATE|EXCL` returns `EEXIST` and preserves foreign dynamic/static rows,
but adding `NTF_EXT_LEARNED` updates those rows despite `EXCL`. Inserting a
foreign row after a vacant final dump reproduces that check/write race.
The probe's modeled final-dump marker guard skips deletion when it sees
a foreign replacement; it does not execute the daemon's delete path or
establish atomic compare-and-delete. A separate source-frame probe confirms
that learning on the same port leaves the `extern_learn` marker in place.
These controls do not qualify ownership atomicity or later local-learning
convergence.

Use the [permanent harness instructions](../../../../tests/interop/peer-sync-frr/README.md)
to rerun with explicitly selected binaries. To check the offline oracle:

```sh
python3 tests/interop/scripts/test_evpn_frr_peer_sync.py
```

This receipt covers one-way known unicast for a peer-only MAC on one bound
all-active ES. It does not qualify return traffic, BUM uniqueness, carrier
failover, algorithm disagreement, VLAN-aware services, scale or performance.
The kernel's default-PVID sibling is not evidence of VLAN-aware service
support. The ownership and later-local-learning limitations above remain
outside the passing forwarding result.
