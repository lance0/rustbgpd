# M110 — FRR 10.7.1 Type 5 next-hop startup race on an IPv6 underlay

Raw capture behind the peer-side caveat recorded on the M110 row in
[`docs/INTEROP.md`](../../../interop.md).

On an IPv6-only VXLAN underlay, FRR 10.7.1's per-VRF `advertise ipv6 unicast`
Type 5 origination can latch the BGP instance's IPv4 `bgp router-id` into the
16-octet IPv6 next-hop field, zero-padded, instead of the L3VNI's IPv6 tunnel
source. FRR's own `show bgp l2vpn evpn neighbors ... advertised-routes`
reports the wrong value, so the defect is on the originating side. rustbgpd
decodes and programs what it receives, which is correct receiver behavior.

| File | What it is |
|---|---|
| `observations.txt` | The commands and verbatim output that attribute the behavior, the bit-level decode of the bad next hop, what clears it, and the observed frequency. |
| `driver.log` | The one M110 run that hit the race, ANSI escapes stripped. Six assertions red, all downstream of the received next hop; the withdraw assertions still pass. |

Resetting the BGP session does not re-derive the next hop. A VXLAN link event
does. Three subsequent runs of the same driver on the same tree passed 19/19.
