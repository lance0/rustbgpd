# Partial mixed FRR all-active forwarding receipt

This local M121 run passed the FRR-DF cell and failed BUM uniqueness in the
rustbgpd-DF cell; the full mixed all-active matrix remains unqualified.
The default-modulo cell was not reached. The strict oracle remains unchanged.

The run used source `69bc267813f73500294d9d2dc9d1cb8cdc288a7b`, FRR
`10.7.1_git`, and Linux `7.0.0-30-generic` on 2026-10-12. It used an equivalent
three-node Docker deployment with debug binaries copied into an owned
Ubuntu 24.04 controller image, then ran the unchanged tracked driver. This is local
correctness evidence, not an Actions checkout or a performance measurement.
[Provenance](provenance.json) records source, input, executable and image hashes.

FRR A and rustbgpd B share an all-active Ethernet Segment, a traditional bridge
and a two-member CE LACP bond. Remote FRR R constructs its own aliasing
nexthop group. Fresh cells elect A on VNI 100 or B on VNI 101 using
highest-preference. They run
sequentially; this does not demonstrate simultaneous per-VNI DF carving.

| Check | FRR A is DF | rustbgpd B is DF |
| --- | --- | --- |
| Peer-only known unicast | 300 frames through A, 340 through B | 300 through A, 340 through B |
| Rust original and FRR synchronized proxy | Passed route, local synchronization and raw wire checks | Passed the same checks |
| Bidirectional known unicast | 40 frames each direction, both members exercised | 40 frames each direction, both members exercised |
| BUM uniqueness | One ingress copy at each PE, one CE delivery through A | **Failed:** one delivery through each member, two at the CE bond |
| Carrier withdrawal and recovery | 340 frames through surviving A; 340 through recovered B | Not reached |
| Default-modulo disagreement | Not reached | Not reached |

The packet oracle checks individual `(flow seed, IPv4 identification)` pairs,
including absence from the other member. In the failed BUM check, identity
`(121, 1936)` appeared once at each PE VXLAN ingress, once on each CE member,
and twice on the CE bond. This is a duplicate of one transmitted frame.
FRR reported non-DF in that cell, but its bridge-port flood flags remained enabled.

FRR's pinned source queues the non-DF change through
[`dplane_br_port_update`](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/zebra_evpn_mh.c#L1880-L1908).
Its stock Linux netlink dispatcher returns success for
[`DPLANE_OP_BR_PORT_UPDATE`](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/kernel_netlink.c#L1473-L1478)
without sending a kernel update. This source behavior explains the observed
missing FRR non-DF enforcement. Full qualification needs a working comparator
dataplane; forcing FRR's flood flags from the harness would not establish that.

The passing carrier phase checks EAD withdrawal, the surviving FRR path,
a five-second recovery hold, restored readiness and aliasing, and delivery
through recovered B. The harness first confirms its owned daemon is stopped,
raises carrier and observes `LOWER_UP`, then resumes the daemon before sampling.
This proves controlled recovery ordering, not natural timer latency.
Later readiness observations include DF and dataplane convergence; those
diagnostic timestamps do not establish a latency result.

Both cell cleanups reported no errors or remaining namespace handles. Final
namespace and outer Docker cleanup receipts are empty. The overall run exited
1 on the BUM assertion. [Results](result.json) preserve the native successful
FRR-DF result and explicitly label the Rust-DF summary as derived partial evidence.

The [evidence archive](evidence.tar.gz) contains unchanged UDP pcaps, packet
and identity ledgers, DF/FDB/NHG snapshots, generated configs, the controlled
recovery samples, cleanup results and per-file derivation metadata.
Route JSON derivatives remove only `hostname` keys recursively. BGP OPEN
messages contain generated container hostnames, so the full BGP pcaps and TCP
payload tables are excluded. Instead, `bgp-updates.json` retains exact complete
UPDATE message bytes obtained with the existing strict TCP reassembly and BGP
framing helpers, lab endpoints and the original private capture hash. These
excerpts support attribute inspection; they are not complete public TCP captures.
No protocol field, packet identity or captured count was changed. Raw originals
remain separate and unchanged. Commands, process dumps, host paths, runtime
state and logs are excluded. Archive ownership and timestamps are normalized.
[Checksums](SHA256SUMS) cover the public files; the archive has its own file manifest.

The discovered 30/34 flow split matches the earlier same-host
[peer-only receipt](../evpn-frr-peer-sync-20261011/README.md), but this run had
`compare_historical=false`. The older pre-fix/fixed counter evidence and its
limitations remain unchanged; it does not acquire individual-frame proof from
this later run. This receipt makes no scale, performance, VLAN-aware service,
default-modulo, hosted, or full three-cell qualification claim.
