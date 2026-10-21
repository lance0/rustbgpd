# ADR-0142: Interface-only unnumbered neighbors

**Status:** Proposed
**Date:** 2026-10-21

## Context

[ADR-0069](0069-bgp-unnumbered.md) shipped BGP unnumbered as static,
interface-bound IPv6 link-local neighbors: the operator writes both the remote
link-local address and the interface. RFC 8950 next hops, the link-local next
hop (32-byte form and the opt-in capability 77), scoped Linux FIB install,
scoped single-hop BFD and the M53 FRR interop lab all exist.

Data-center fabrics configure unnumbered differently. FRR, Cumulus Linux and
SONiC operators write `neighbor swp1 interface remote-as external`: they name
only the port. The daemon learns the peer's link-local address from IPv6
Router Advertisements (RAs) on that link and follows it when it changes.
Configuration generators can then emit the same stanza for every fabric port
without knowing any remote address. ADR-0069 deferred this mode first.

Three facts shape the design:

- **The interface is the identity.** Many platforms reuse one router MAC on
  every port, so EUI-64 link-local addresses repeat across parallel links, and
  some operators configure `fe80::1` everywhere. A learned address is a
  property of the current session, not of the neighbor.
- **Linux never originates RAs.** Only radvd or a routing daemon does. FRR
  peers need them: FRR connects only to an interface peer's RA-learned address
  and accepts connections only from it.
- **The RIB keys peers by bare address today.** Same-address neighbors on
  different interfaces need the scoped RIB neighbor identity (a generational
  neighbor handle) that is being introduced separately. Until it lands,
  configuration rejects the same link-local address on two interfaces.

### Prior art

Read from source at the 2026-10-20 heads of each project.

- **FRR.** zebra receives RAs (`zebra/rtadv.c`, `rtadv_process_packet`: hop
  limit must be 255, and RAs are processed only on interfaces where zebra is
  sending them; `rtadv_process_advert` drops non-link-local sources). It keeps
  one learned neighbor per interface: `nbr_connected_add_ipv6`
  (`zebra/zapi_msg.c`) overwrites the list head, so the most recent RA source
  wins. Learned addresses never age out. They are cleared only when the
  interface goes down (`zebra/interface.c`, `if_down_del_nbr_connected`).
  bgpd reads the head in `bgp_peer_conf_if_to_su_update_v6`
  (`bgpd/bgpd.c`), scoped to the interface index, and `bgp_start`
  (`bgpd/bgp_fsm.c`) stays Idle until an address is known. Inbound
  `peer_lookup` matches the learned address plus scope (`sockunion_same`,
  `lib/sockunion.c`). bgpd asks zebra to send RAs automatically
  (`bgp_zebra_initiate_radv`, `bgpd/bgp_zebra.c`) at a 10 s interval
  (`BGP_UNNUM_DEFAULT_RA_INTERVAL`), with a non-zero router lifetime derived
  from the interval. `no bgp ipv6-auto-ra` turns that off. When the interface
  goes down, or the learned neighbor address is deleted, bgpd raises
  `BGP_Stop`, which does not enter Graceful Restart helper mode. FRR's
  documentation says only one neighbor comes up if this mode is used on a
  shared Ethernet segment. Without `v6only`, FRR first tries an IPv4 session
  derived from a /30 or /31 on the interface.
- **GoBGP.** `neighbor-interface` resolves the address once, when the peer is
  added, from the kernel neighbor table. It requires exactly one non-failed
  link-local neighbor on the interface, and does not follow later changes
  (`pkg/config/oc/default_linux.go`, `GetIPv6LinkLocalNeighborAddress`).
- **BIRD 2.19 and later.** The `radv` protocol with `router discovery yes`
  exports discovered routers, keyed by address and interface index, into a
  neighbor table. The entry expires with the RA's Router Lifetime, and **a
  Router Lifetime of 0 withdraws it** (`proto/radv/packets.c`). A dynamic BGP
  instance with a `neighbors` channel opens one session per discovered entry.

## Decision

Add **interface-only neighbors**: a `[[neighbors]]` entry with `interface` and
no `address`. The daemon discovers the peer's IPv6 link-local address on that
interface and keeps the interface as the neighbor's identity for the
neighbor's whole lifetime.

### Configuration

```toml
[global.unnumbered]            # optional section
router_advertisements = true   # default
ra_interval_secs = 10          # RFC 4861 MaxRtrAdvInterval, 4..=1800

[[neighbors]]
interface = "swp1"             # no address: interface-only
remote_asn = "external"        # an ASN, "external" or "internal"
peer_group = "fabric"
families = ["ipv4_unicast", "ipv6_unicast"]
```

- `remote_asn = "external"` accepts any ASN from OPEN except `global.asn`, and
  `"internal"` means `global.asn`. A number keeps its current meaning. The
  string forms are valid on every static neighbor, not only interface-only
  ones.
- The interface does not need to exist when configuration loads. The neighbor
  waits in `interface_missing` until it appears, and the interface index is
  resolved by name on every link event, never cached across a recreation.
- Each interface has at most one interface-only neighbor, and an interface
  that has one cannot also have a static link-local neighbor.
- Peer groups apply as they do to any neighbor. `link_local_next_hop` is
  allowed. Families follow ADR-0069: IPv4 unicast requires RFC 8950.
- Rejected on an interface-only neighbor: explicit `listen_addresses` (the
  same rule as static link-local neighbors), `ttl_security_hops` above 1,
  `bfd.multihop`, `local_address`, and TCP-AO or MD5 in the first release.
  Dynamic ranges still cannot match link-local sources.

### Discovery

- **Primary: Router Advertisements.** One raw ICMPv6 socket receives RAs on
  interfaces that have an interface-only neighbor. Packets are validated
  according to RFC 4861 §6.1.2: link-local source, IPv6 hop limit 255, ICMP
  code 0, a minimum length, and well-formed options. The kernel filter passes
  only RA and Router Solicitation (RS). Routers receiving other routers' RAs is
  standard behavior (RFC 4861 §6.2.7).
  - A candidate expires after the RA's Router Lifetime. When the lifetime is 0
    (common in radvd configurations), the candidate expires after a fixed 30 s
    hold. Carrier loss clears every candidate on the interface.
- **Secondary: an inbound connection on the interface.** A TCP SYN that
  arrives on an interface-only neighbor's interface is matched by its arrival
  scope (interface index, then interface, then neighbor), not by its address.
  It is accepted while the neighbor has no Established session. This covers
  peers that are configured statically toward us or that do not send RAs, and
  needs no extra privilege.
- **The kernel neighbor table is not a discovery source.** It is a cache: an
  entry exists only after traffic has resolved it, it ages and is
  garbage-collected, and it does not say which neighbor is a BGP speaker. A
  snapshot at add time, as in GoBGP, cannot follow an address change.
- **Sending.** By default the daemon sends RAs on every interface-only
  neighbor's interface, every `ra_interval_secs`, and answers Router
  Solicitations. The RA template is fixed:
  - Router Lifetime is three times the interval, RFC 4861's default ratio.
    It is non-zero, as FRR's is, because BIRD's discovery treats lifetime 0 as
    a withdrawal.
  - There are no Prefix Information, MTU or RDNSS options. The Source
    Link-Layer Address option is included.
  - Current hop limit, reachable time and retransmit timer are 0
    ("unspecified"), so peers' RFC 4861 consistency checks do not log
    mismatches.

  On interface up the daemon also sends one RS, so that a peer which answers
  RSs is discovered in one round trip. Sites where radvd already advertises
  on those interfaces set `router_advertisements = false`. This is
  deliberately not a general RA daemon.
- **Privilege.** The raw socket needs `CAP_NET_RAW`, which is required only
  when interface-only neighbors are configured. If the socket cannot be
  opened, the startup or reload that introduces the first such neighbor fails
  with an explicit error. It does not fall back silently to listen-only. The
  security reference and the example systemd units are updated to match.
- **Trust boundary.** The trust boundary is the link, as for any directly
  connected session. An RA or a SYN only proposes a TCP endpoint on that one
  interface. The session still has to pass OPEN validation, and GTSM (hop
  limit 255 on the TCP session) still applies.

### Binding and multiple sources

The neighbor binds one learned address at a time. The binding is sticky and
reselection is deterministic:

- While a session is not Established, the neighbor keeps its current binding
  as long as that candidate is live. Otherwise it binds the numerically lowest
  live candidate. FRR's last-RA-wins overwrite flaps between sources on a
  shared segment; lowest-live does not.
- A second live RA source is a conflict.
  - The daemon logs the conflict once per source, counts it, sets the neighbor
    warning `multiple_routers_on_link`, and reports it in `rbgp doctor`.
  - A new source never moves an Established session.
  - Refusing the neighbor outright whenever two sources exist was considered
    and rejected: it would turn a stray RA on a misconfigured segment into a
    fabric link outage.
- If a second connection's OPEN carries a different BGP Identifier from the
  session's, the connection is not a collision. It is a second router on a
  link that is defined to have one, and it is refused with
  `multiple_routers_on_link`.

### Sessions and collisions

Both ends connect actively, and both accept passively, as FRR does and as
static link-local neighbors do today. Connection collision follows RFC 4271
§6.8 and [ADR-0021](0021-tcp-collision-detection.md) unchanged: it compares
BGP Identifiers, so link-local addresses play no part. The connection that
wins fixes the session's endpoint.

### Lifecycle

States: `interface_missing`, `link_down`, `awaiting_discovery`, then the
ordinary FSM states once an address is bound.

- **Carrier loss or interface removal.** The session is torn down at once with
  a Cease NOTIFICATION, matching FRR's default fast external failover, and the
  binding and candidates are cleared. This is a local stop, not a transport
  failure: Graceful Restart and LLGR routes are not retained
  ([ADR-0024](0024-graceful-restart.md), [ADR-0042](0042-llgr.md)).
  Their next hop sits behind a down or deleted interface.
- **Address change.** A different learned address is a new TCP endpoint. It is
  modelled as session down, then up, under the same neighbor identity, with
  state reason `peer_address_changed`.
  - An Established session moves only when two conditions both hold: its bound
    source's RA has expired, and another candidate is live (or an inbound
    session from the new source wins after the old one failed).
  - An expired source with no replacement changes nothing. Session liveness
    belongs to the hold timer and BFD.
  - Routes retained from the old address are purged, not kept as stale,
    because their next hop is the old link-local address.
- **Ordinary transport loss.** When the address is unchanged and carrier is
  up, ordinary transport loss keeps the normal Graceful Restart helper
  behavior. Each session generation records its own endpoint, so retained
  routes keep the endpoint they were learned from.
- **BFD.** No BFD session exists before an address is bound
  ([ADR-0067](0067-bfd-single-hop.md)). Binding creates the single-hop session
  to `fe80::x%ifindex`, rebinding replaces it, and unbinding removes it. BFD
  down remains a session-down input. This requires BFD sessions that are
  registered at runtime, not only derived from configuration.
- **Neighbor handle.** Under the scoped RIB identity, an interface-only
  neighbor receives its handle when OPEN validates. The handle is stable
  across address changes and link flaps, and released only when configuration
  deletes the neighbor.

### Same-address neighbors before and after the scoped RIB identity

Before the scoped RIB identity lands, the existing duplicate-address rule is
enforced at admission. A learned address that equals another neighbor's
address is refused with `duplicate_link_local_address`. That still covers the
common Clos shape, where each fabric link goes to a different switch with its
own MAC. Parallel links to the same device, or `fe80::1` on every port, need
the scoped identity. Once the duplicate-address rule is lifted, two further
rules apply:

- **BMP admission.** A learned address that duplicates another monitored
  neighbor's address is refused before Established, with reason
  `bmp_identity_conflict`. A BMP station may instead opt in with
  `on_identity_conflict = "exclude"`: the session then establishes but is left
  out of that station's feed, and the exclusion is reported in neighbor state,
  `rbgp doctor` and metrics. Identities are never merged.
- **MRT.** The peer index allows duplicate-address entries.

### Operator surfaces

- **`rbgp neighbor`** shows the identity `swp1`, the learned address (or `-`)
  and the state reason. `rbgp neighbor swp1` selects the neighbor: an argument
  that does not parse as an IP address is an interface name.
- **API.** `NeighborConfig.address` is empty and `interface` is `swp1`.
  `NeighborState` gains `learned_peer_address`, which is empty until an
  address is bound, and a `discovery_state` enum.
  - Route rows and events keep the scoped identity contract: `peer_address`
    is the learned address recorded in the session's provenance, and
    `peer_interface` is `swp1`.
  - A selector with an empty address and interface `swp1` selects the
    neighbor. So does `fe80::x%swp1` for any `x`, because the interface owns at
    most one neighbor.
  - A bare link-local selector is still `INVALID_ARGUMENT`.
- **Metrics.** Every per-peer family uses `peer="interface:swp1"`, which stays
  stable across learned-address changes, and the identity gauges carry
  `interface="swp1"`. The learned address goes in separate metadata:
  - `bgp_unnumbered_peer_address_info{peer,interface,address}`, one series
    while an address is bound;
  - `bgp_unnumbered_address_changes_total{peer}`;
  - `bgp_unnumbered_ra_conflicts_total{peer}`.

  `bgp_peer_info` keeps its label set.
- **Events and logs.** Session down and up carry the reasons `link_down`,
  `interface_removed` and `peer_address_changed`. Structured log events record
  when an address is learned or changes, and when an RA conflict is detected.
- **`rbgp doctor`** reports:
  - a missing or down interface;
  - discovery still waiting after three RA intervals, with hints: the peer
    sends no RAs, FRR has `no bgp ipv6-auto-ra`, or FRR lacks `v6only` and is
    preferring an IPv4 /30 or /31 session;
  - multiple routers on a link;
  - an unavailable RA socket;
  - an interface without a link-local address;
  - BMP exclusions.

### Interop gate

- **M53 interface variant.** FRR is configured with
  `neighbor eth1 interface v6only remote-as external`, and the links carry
  only kernel-generated EUI-64 link-local addresses. The lab asserts that:
  - sessions establish from either side;
  - IPv4 is exchanged over RFC 8950, and the FIB installs ECMP via scoped
    devices;
  - changing FRR's link-local address produces exactly one session down/up,
    keeps the same `peer` series, and counts one address change;
  - carrier loss takes the session down within one second, removes its FIB
    routes, and recovers when the link returns;
  - with an FRR leg that runs `no bgp ipv6-auto-ra` and a static neighbor
    toward us, the session establishes through inbound learning;
  - a third RA source on a bridged segment is reported as a conflict and
    does not cause a flap.
- **Multi-link fabric topology.** Two links connect to one FRR node, and both
  of its interfaces share one MAC, so both have the same EUI-64 link-local
  address.
  - Before the scoped RIB identity, the second session is refused with
    `duplicate_link_local_address`.
  - After it, both sessions establish and hold two-way ECMP. Losing one link
    removes only that session's routes, and the tie-break by interface name is
    the same whatever the start order.
- **Optional leg.** BIRD 2.19 or later, with router discovery, confirms the
  non-zero Router Lifetime.

### Out of scope

- Dynamic unnumbered across many interfaces (an interface range spawning
  sessions). Configuration generators emit one neighbor per port.
- IPv4 link-local, and FRR's IPv4 /30 or /31 derivation. Interface-only
  neighbors are IPv6 link-local only, equivalent to FRR's `v6only`.
- More than one BGP speaker on one interface.
- RA prefix, MTU, RDNSS or per-interface RA tuning.
- Multihop, VRFs, and TCP-AO or MD5 in the first release.
- Carrier-loss teardown for existing static link-local neighbors. That would
  change behavior for current configurations, so it is a separate decision.

## Consequences

- Fabric configuration needs only port names: one stanza per port, no
  addresses, no ASN bookkeeping with `remote_asn = "external"`.
- The daemon gains a raw ICMPv6 socket and therefore `CAP_NET_RAW`, but only
  for configurations that use this mode. Control-plane-only route-server and
  route-reflector deployments keep their current privileges.
- Link loss now ends interface-only sessions immediately rather than at hold
  expiry or BFD detection, and those routes are not retained for Graceful
  Restart.
- Discovery is decided by rules that do not depend on timing, so a stray RA
  source produces a reported conflict, not session churn.
- Parallel links to one device need the scoped RIB neighbor identity. Until
  it lands, they are refused explicitly rather than aliased.
- ADR-0069's first Deferred item is addressed by this record once it is
  accepted. The static link-local mode stays unchanged.

## References

- RFC 4861, Neighbor Discovery for IPv6 (§6.1.2 RA validation, §6.2.1 router
  configuration variables, §6.2.7 RA consistency):
  <https://www.rfc-editor.org/rfc/rfc4861>
- RFC 4007, IPv6 scoped address architecture:
  <https://www.rfc-editor.org/rfc/rfc4007>
- RFC 8950, IPv4 NLRI with an IPv6 next hop:
  <https://www.rfc-editor.org/rfc/rfc8950>
- RFC 7404, using only link-local addressing inside an IPv6 network:
  <https://www.rfc-editor.org/rfc/rfc7404>
- RFC 4271 §6.8, connection collision detection:
  <https://www.rfc-editor.org/rfc/rfc4271#section-6.8>
- FRR source: <https://github.com/FRRouting/frr>
- GoBGP source: <https://github.com/osrg/gobgp>
- BIRD source and documentation: <https://gitlab.nic.cz/labs/bird>
