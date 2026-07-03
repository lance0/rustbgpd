# EVPN fabric route reflector (control-plane only)

**When this is you:** a VXLAN-EVPN leaf/spine fabric where the VTEPs
(FRR, SR Linux, GoBGP, or rustbgpd leaves) do the dataplane and you
want a lean, API-first reflector distributing the RFC 7432 routes
between them. Scope, stated up front: **this recipe is the RR role.**
The RR holds no EVI state, learns no MACs, and forwards no packets —
it reflects all five EVPN route types verbatim between clients.
rustbgpd also has a bidirectional VTEP mode (alpha, Linux/VXLAN-only,
with IRB and multi-homing — see
[`evpn-enablement.md`](../evpn-enablement.md)); that is a different
deployment and not this document.

**Proven by:** [M29](../RECEIPTS.md#interop-labs--pr-gated-interopyml)
(EVPN RR capability + `ListEvpnRoutes` vs FRR), M30 (Type 2 MAC
reflection end-to-end between kernel VXLAN VTEPs), M31 (MAC mobility +
sticky preservation), M32 (multi-homing Type 1 EAD / Type 4 ES
reflection), M82 (VLAN-aware-bundle reflection with non-zero Ethernet
Tags — including rustbgpd's first vendor-NOS leg, Nokia SR Linux
25.10), and the M33 scale gate (50k reflected Type 2 routes + 60 s of
1,000-rps churn). The config below is
[`examples/rr-evpn-fabric/config.toml`](../../examples/rr-evpn-fabric/config.toml).

## Config

```toml
[global]
asn = 65000
router_id = "10.0.0.100"
listen_port = 179
cluster_id = "10.0.0.100"

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

[global.telemetry.grpc_uds]
path = "/var/lib/rustbgpd/grpc.sock"
principal = "operator"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
operator = "operator"

# All VTEPs are iBGP RR clients on the l2vpn_evpn family. Empty
# [[evpn_instances]] (none configured) selects pure RR mode: no local
# EVI state, no kernel programming, reflection only.
[[neighbors]]
address = "10.0.0.1"
remote_asn = 65000
description = "vtep-leaf-01"
hold_time = 180
families = ["l2vpn_evpn"]
route_reflector_client = true

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65000
description = "vtep-leaf-02"
hold_time = 180
families = ["l2vpn_evpn"]
route_reflector_client = true

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65000
description = "vtep-leaf-03"
hold_time = 180
families = ["l2vpn_evpn"]
route_reflector_client = true
```

For larger fabrics, template the leaves with a peer group and an
auto-accept range over the VTEP loopback subnet — the
[unicast RR recipe](route-reflector.md#config) shows the
`[peer_groups]` + `[[dynamic_neighbors]]` shape; swap the families for
`["l2vpn_evpn"]`.

## Verify

```console
$ export RUSTBGPD_ADDR=unix:///var/lib/rustbgpd/grpc.sock
$ rbgp neighbor                      # every leaf Established, l2vpn_evpn negotiated
$ rbgp evpn                          # all reflected EVPN routes
$ rbgp evpn --route-type 2           # MAC/IP advertisements only
$ rbgp evpn --route-type 3           # IMET (BUM flooding) entries
$ rbgp evpn --rd 65000:100           # one EVI's view
$ rbgp evpn --peer 10.0.0.1          # what leaf-01 contributed
```

Expected shape: one row per (RD, route-type, key) with the originating
peer; after two leaves come up with the same L2VNI you should see each
leaf's Type 3 IMET route reflected to the other, then Type 2 rows
appearing as MACs are learned.

Two things that look odd but are correct:

- **The same MAC under two Ethernet Tags is two routes.** In
  VLAN-aware-bundle service the non-zero Ethernet Tag is part of the
  route identity ([ADR-0092](../adr/0092-evpn-vlan-aware-bundle-service.md));
  the RR keys and reflects them separately, tag-verbatim, and a
  single-tag withdraw removes exactly that entry (M82).
- **Attributes pass through untouched.** RD, label/VNI, next-hop, RTs,
  MAC-mobility sequence numbers, ESI — the RR adds ORIGINATOR_ID and
  CLUSTER_LIST per RFC 4456 and changes nothing else. DF election,
  ARP/ND suppression, and mobility sequencing are the VTEPs' business.

## Watch

The [Grafana overview](../GRAFANA.md) session and RIB-scale rows apply
as-is (`bgp_session_state_transitions_total`,
`bgp_rib_outbound_registered_peers`, update-group gauges). Per-VNI
EVPN metric families (`evpn_*`) are VTEP-mode surface and stay empty
in the RR role — deliberately not on the overview dashboard.

Route churn is the fabric health signal on an EVPN RR: watch
`rbgp events watch --category route` (or the route-event history,
`rbgp events --limit 200`) during rollouts. MAC-mobility wars show up
as a tight add/withdraw loop on one MAC key with a climbing sequence
number.

## Failure modes

**A leaf's routes aren't reaching another leaf.** (The
`rbgp rib advertised --explain` gate ladder covers the unicast and
VPN families, not EVPN — for EVPN, walk the gates by hand; they fail
in this order.) First `rbgp evpn --peer 10.0.0.1` — did the RR accept
the routes from the source leaf at all? Then the two common
reflection stops: *family* — the quiet leaf didn't negotiate
`l2vpn_evpn` (check its row in `rbgp neighbor`; an FRR leaf missing
`neighbor X activate` under `address-family l2vpn evpn` establishes
happily and receives nothing — the M29 lesson) — and *RR rules* — the
leaf isn't marked `route_reflector_client`, so client→non-client
reflection rules apply.

**Vendor NOS quirks.** From the M82 SR Linux leg: SR Linux enforces
one EVI per mac-vrf (bundle identity = shared RT + Ethernet Tag,
per-BD RDs) and needs an explicit `transport local-address` on the BGP
group, or it sources the session from its system0 address and the RR's
neighbor stanza never matches. Recorded in
[`upstream-findings.md`](../upstream-findings.md) and the M82 lab
fixtures.

**Reflected state survives leaf restarts?** Add GR to the neighbor
stanzas (`graceful_restart = true` and friends, as in the
[unicast recipe](route-reflector.md#config)) if your leaves support
GR for EVPN; without it, a leaf bounce withdraws its routes
fabric-wide and they re-learn on re-establish.
