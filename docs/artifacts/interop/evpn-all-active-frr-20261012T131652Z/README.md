# Mixed FRR all-active forwarding receipt

This local M121 run passed all three cells: FRR as DF, rustbgpd as DF, and
rustbgpd left at `default-modulo`. Stock FRR 10.7.1 on Linux does not filter
BUM when it is non-DF, so the rustbgpd-DF cell delivers two copies of each
BUM frame to the CE. The leg pins that extra copy as a non-enforcement
witness instead of treating it as a pass or a rustbgpd failure.

The run used source `2d27cb49ce7e6ddb84354cb114f16f70b8d5a944` with clean
runtime and harness inputs, FRR `10.7.1_git` and Linux `7.0.0-30-generic` on
2026-10-12. Containerlab 0.74.3 deployed the tracked topology with a
controller image from `docker build --target dev`; its source id matched the
tree. This is local correctness evidence, not an Actions run or a performance
measurement. [Provenance](provenance.json) records source, input, executable
and image hashes.

FRR A and rustbgpd B share an all-active Ethernet Segment, a traditional bridge
and a two-member CE LACP bond. Remote FRR R builds its own aliasing nexthop
group. Each cell starts from fresh namespaces, daemons and state. Highest-
preference elects one DF across the segment, so the cells run sequentially;
this does not demonstrate per-VNI DF carving.

| Check | FRR A is DF (VNI 100) | rustbgpd B is DF (VNI 101) | default-modulo (VNI 100) |
| --- | --- | --- | --- |
| DF state | A `df`; B `nondf`, ES port flooding off | A `non-df`; B `df`, flooding on | A `non-df`; B modulo `nondf`, flooding off |
| Peer-only known unicast | 300 frames through A, 340 through B | 300 through A, 340 through B | Not run |
| Rust original and FRR synchronized proxy | Route, sync-state and raw wire checks passed | Same checks passed | Not run |
| Bidirectional known unicast | 40 frames each direction, both members | 40 frames each direction, both members | Not run |
| BUM copies on CE member A / B / bond | 1 / 0 / 1 | 1 / 1 / 2 | 1 / 0 / 1 |
| FRR non-enforcement witness | Not applicable | `non-df`, all three flood flags on | `non-df`, all three flood flags on |
| Carrier withdrawal and recovery | 340 frames through surviving A; 340 through recovered B | Not run | Not run |

The BUM oracle checks the individual `(flow seed, IPv4 identification)` pair
`(121, 1936)`. In every cell it entered each PE's VXLAN device once. rustbgpd's
member delivered it exactly once when rustbgpd was DF and never when it was
non-DF. FRR's member delivered it once in every cell.

**Non-enforcement witness.** In the rustbgpd-DF and modulo cells, FRR reports
`DF status: non-df` while its `es0` bridge port keeps `flood`, `mcast_flood`
and `bcast_flood` on. The leg checks this before and after the broadcast and
requires the copy on CE member A. If FRR starts filtering as non-DF on Linux,
the witness fails and the leg must be requalified. The cause is in FRR's
pinned source: the non-DF change queues
[`dplane_br_port_update`](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/zebra_evpn_mh.c#L1880-L1908),
and the stock Linux netlink dispatcher returns success for
[`DPLANE_OP_BR_PORT_UPDATE`](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/kernel_netlink.c#L1473-L1478)
without sending a kernel update.

**Default-modulo cell.** rustbgpd keeps its configured `default-modulo`
algorithm. FRR's Type 4 carries the DF Election extended community with the
preference algorithm (`06060200000000c8`), and rustbgpd's Type 4 carries none.
FRR lists rustbgpd's VTEP as `df_alg: service-carving` and reports `non-df`.
Modulo assigns VNI 100 to FRR (100 mod 2 selects the lower originator), so
rustbgpd is `nondf` with BUM action `suppress` and its port flooding off. The
CE received one copy, from FRR's still-flooding port. This matches the
prediction from source: BUM is not lost on a VNI that modulo assigns to FRR.
On a VNI that modulo assigns to rustbgpd, the rustbgpd-DF duplicate applies;
this run did not exercise such a VNI.

The carrier phase checks EAD withdrawal, the surviving FRR path, a five-second
recovery hold, restored readiness and aliasing, and delivery through recovered
B. The harness confirms its owned daemon is stopped, raises carrier and
observes `LOWER_UP`, then resumes the daemon before sampling. This proves
recovery ordering, not natural timer latency.

All three cell cleanups reported no errors or remaining namespace handles, the
final namespace list was empty, and the run exited 0.
[Results](result.json) are the native driver output plus the run exit code.

The [evidence archive](evidence.tar.gz) contains unchanged UDP pcaps, packet
and identity ledgers, DF/FDB/NHG snapshots, the witness and modulo state,
generated configs, recovery samples, cleanup results and per-file derivation
metadata. Snapshot JSON omits only `hostname` keys. BGP OPEN messages carry
generated container hostnames, so full BGP pcaps are excluded; each cell's
`bgp-updates.json` keeps exact complete UPDATE message bytes from the existing
TCP reassembly and BGP framing helpers, with the private capture hash.
Commands, process dumps, daemon logs and runtime state are excluded. Archive
ownership and timestamps are normalized. [Checksums](SHA256SUMS) cover the
public files; the archive carries its own file manifest.

This receipt replaces the earlier partial receipt from the same unmerged
change, which recorded the rustbgpd-DF duplicate as a failure before the
non-enforcement witness existed. It makes no scale, performance, VLAN-aware
service or hosted-run claim.
