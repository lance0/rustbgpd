# All-active peer-only MAC forwarding against FRR

This privileged local proof checks delivery when FRR learns a CE MAC and a
remote FRR VTEP aliases its traffic to a non-DF rustbgpd peer that has never
learned the MAC locally.

The runner creates three owned Docker containers. Two run FRR 10.7.1; a
third contains isolated rustbgpd and CE network namespaces and the underlay
bridge. Every test network device lives inside those containers. The runner
installs packet tools in the disposable Ubuntu container, disconnects its
Docker bridge before the test, and removes all three containers on exit.
Docker access, Linux VXLAN/FDB-nexthop support and bonding support are required.
No build is performed. Supply Linux binaries compatible with Ubuntu 24.04.

```text
                  all-active ES, VNI 100
 FRR A (DF) -------- es0 -- cea --+
 10.211.0.1                     CE bond0 (802.3ad)
                                +-- ceb -- es0 -------- rustbgpd B (non-DF)
                                                       10.211.0.2
            \                 /
             FRR remote R, 10.211.0.3
             real two-member L2 nexthop group
                         |
                    remote injector
```

The PE bonds share LACP system ID `aa:bb:cc:dd:ee:ff`; both CE members must
join one active aggregator. The ES uses `highest-preference`, with FRR at
200 and rustbgpd at 100. One raw CE source frame is explicitly sent on
`cea`, pinning its source learning to FRR without taking the other member
down. IPv6 is disabled to prevent unrelated learning. The CE does not reply.

FRR's own EAD/Type-2 processing must produce the remote two-member FDB
nexthop group. The harness neither inserts nor overrides this group. It
sends 64 distinct marked UDP flows, records which real PE each hash selects,
then repeats every flow ten times. Captures verify the exact per-flow frame
counts at PE VXLAN ingress, each CE member and CE `bond0`. A separate FRR
DF delivery control must pass. Snapshots retain EVPN routes, DF state,
FDB entries, NHGs, LACP state and interface counters.

Run a pre-fix binary and fixed binary in separate fresh output directories:

```sh
python3 tests/interop/scripts/run-evpn-frr-peer-sync-proof.py \
  --daemon /path/to/baseline/rustbgpd --cli /path/to/rbgp \
  --output /tmp/peer-sync-baseline --expect baseline
python3 tests/interop/scripts/run-evpn-frr-peer-sync-proof.py \
  --daemon /path/to/fixed/rustbgpd --cli /path/to/rbgp \
  --output /tmp/peer-sync-fixed --expect fixed
python3 tests/interop/scripts/test_evpn_frr_peer_sync.py
```

`baseline` requires the peer-only MAC to be absent from rustbgpd's FDB and
all frames selected for rustbgpd to be lost. `fixed` requires the owned
`extern_learn` FDB rows on its bound `es0` (the exact untagged/default-PVID-1
pair produced by an unscoped legacy-bridge add) and zero loss, including exact
acceptance on the CE bond. Both require the accepted Type 2 to carry the
shared ESI, no locally originated CE MAC on rustbgpd, and suppression of
unknown-unicast flooding on rustbgpd's non-DF interface. `--keep` retains
only this run's named containers for diagnosis; remove them after inspection.

This is one-way known-unicast correctness evidence for a traditional
bridge and one bound all-active ES. It does not qualify return traffic,
BUM uniqueness, carrier-driven failover, algorithm disagreement, VLAN-aware
bundles, scale or performance.
