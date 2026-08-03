# L3VPN route reflector (VPNv4/VPNv6 + RT-Constrain)

**When this is you:** you have a PE fleet exchanging VPNv4/VPNv6
routes (SAFI 128) and want the reflector out of the vendor-appliance
business — reflect with RD, MPLS label stack, next-hop, and Route
Targets preserved verbatim, and only send each PE the routes whose RTs
it actually imports (RFC 4684 RT-Constrain). Scope honesty up front:
this is the **route-reflector / controller-feed slice only**
([ADR-0077](../adr/0077-mpls-vpn-bgpls-address-family-boundary.md)).
rustbgpd does no VRF import, no MPLS label forwarding, no CE-facing
attachment circuits — the PEs keep their dataplane; the RR moves
routes.

**Proven by:** [M74](../RECEIPTS.md#interop-labs--pr-gated-interopyml)
(VPNv4 reflection, RD/label/RT/next-hop field-equal on the sink's
re-decoded NLRI, vs GoBGP), M75 (RT-Constrain filtering: strict
empty-membership, widen/narrow without session reset, and the
non-RTC-peer full-table rule), M77 (GR/LLGR stale preservation for the
VPN and RTC families — RTC membership survives a PE restart, so no
VPN blackout at re-establish), and the
[VPN scale receipt](../perf/scale-receipt-2026-07.md) (Scenario E):
100k VPNv4 to 1,000 clients in 12.6 s uniform / 3.9 s with
heterogeneous ~10 % RT memberships, and a single member's
RT-membership flip at 100k staged routes hitting the wire in ~15 ms
with zero policy evaluations. Config shape derived from
[`tests/interop/configs/rustbgpd-m75-rtc-rr.toml`](../../tests/interop/configs/rustbgpd-m75-rtc-rr.toml)
and [`rustbgpd-m77-gr-rr.toml`](../../tests/interop/configs/rustbgpd-m77-gr-rr.toml).

## Config

```toml
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179
cluster_id = "10.0.0.1"

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

# Owner-only local socket (default mode 0600): clients are authorized as the
# implicit "local-operator" principal — no [security.grpc] block needed.
[global.telemetry.grpc_uds]
path = "/var/lib/rustbgpd/grpc.sock"

# PE clients: VPN families plus "rtc" (RFC 4684, AFI 1 / SAFI 132).
# Each PE advertises its RT membership as RTC NLRIs; the RR filters
# its VPN reflection per peer accordingly. Semantics are strict: an
# RTC-negotiated peer with an empty advertised membership receives
# NO VPN routes (fail closed) until its first RTC announce arrives.
#
# GR/LLGR on the VPN + RTC families keeps both the VPN routes AND the
# peer's RTC membership across a PE restart — without membership
# retention, a restarting PE would blackhole its VPNs until it
# re-advertised every RT (M77 proves the retention).
[peer_groups.pe-clients]
hold_time = 90
families = ["l3vpn_ipv4_unicast", "l3vpn_ipv6_unicast", "rtc"]
route_reflector_client = true
graceful_restart = true
gr_stale_routes_time = 120
llgr_stale_time = 300

[[neighbors]]
address = "10.0.0.11"
remote_asn = 65000
description = "pe-1"
peer_group = "pe-clients"

[[neighbors]]
address = "10.0.0.12"
remote_asn = 65000
description = "pe-2"
peer_group = "pe-clients"

# A consumer WITHOUT "rtc" on purpose: a peer that has not negotiated
# SAFI 132 must receive the full unfiltered VPN table (RFC 4684 rule;
# M75 pins it). This is the controller/analytics-feed shape.
[[neighbors]]
address = "10.0.0.100"
remote_asn = 65000
description = "controller-feed"
hold_time = 90
route_reflector_client = true
families = ["l3vpn_ipv4_unicast", "l3vpn_ipv6_unicast"]
```

## Verify

```console
$ export RUSTBGPD_ADDR=unix:///var/lib/rustbgpd/grpc.sock
$ rbgp neighbor
```

All PEs `Established`. Note the update-group column: since
[ADR-0099](../adr/0099-update-groups-v2.md), RTC negotiation is part
of the group key, **not** a per-peer fallback — PEs with entirely
different RT memberships still share one group and one staging pass;
the RFC 4684 filter is applied per member at emit time.

The VPN table and the membership driving the filter:

```console
$ rbgp rib vpn                          # VPNv4/VPNv6: RD, prefix, label, RTs
$ rbgp rib vpn -a vpnv6                 # VPNv6 only
$ rbgp rib rtc                          # RT-Constrain NLRIs per peer
$ rbgp rib rtc --neighbor 10.0.0.11     # what pe-1 says it imports
$ rbgp rib advertised 10.0.0.12 -a l3vpn_ipv4_unicast   # what pe-2 gets
```

Expected shape: `rbgp rib advertised` toward an RTC peer shows only
routes whose RTs intersect that peer's membership;
toward `controller-feed` it shows every VPN route.

Refresh a PE's VPN view without touching the session (the stale
lifecycle is BoRR/EoRR-bounded per RFC 7313):

```console
$ rbgp neighbor 10.0.0.11 softreset --family l3vpn_ipv4_unicast
```

## Watch

Same dashboard rows as the
[unicast RR recipe](route-reflector.md#watch) — the update-group
gauges (`bgp_update_groups`, `bgp_update_group_members{group}`,
`bgp_update_group_fallback_peers`) cover the VPN groups too
(ADR-0099), and `bgp_session_state_transitions_total` catches PE
flaps. RIB scale panels in the [Grafana overview](../GRAFANA.md)
track table growth as VPNs are provisioned.

## Failure modes

**A PE gets no VPN routes although its session is Established.**
First suspect: empty RTC membership — strict fail-closed is the
designed behavior, not a bug. Check what the PE has advertised:

```console
$ rbgp rib rtc --neighbor 10.0.0.11
```

Empty output = the PE negotiated SAFI 132 but announced no RT
membership; fix the PE's VRF import config (or its RTC default-route
origination). Confirm with the VPN export ladder, which includes the
RT-membership gate:

```console
$ rbgp rib --prefix 10.1.0.0/24 advertised 10.0.0.11 --explain --rd 65000:1
```

A STOP at `rt_membership` names exactly this condition; the ladder
otherwise mirrors the unicast one
(`best_route → … → rt_membership → export_policy → adj_rib_out`).

**The controller feed receives "too much".** By design: no SAFI 132
negotiated → full table. If the consumer should be filtered, negotiate
`rtc` on that peer and advertise membership from its side.

**Stale VPN routes after a PE restart.** Bounded by the GR window then
`llgr_stale_time`, same as unicast — and deliberately so: the RTC
membership is preserved through the same mechanism, so reflection
resumes without a blackout when the PE returns (M77). If a PE never
returns, both the routes and its membership expire with LLGR.

**A VRF is torn down on a PE but its routes linger on other PEs.**
Check the withdraw actually arrived: `rbgp events --prefix <pfx>`
shows the per-prefix route-event history, and `rbgp rib vpn --neighbor
<pe>` shows what the RR still holds from that PE.
