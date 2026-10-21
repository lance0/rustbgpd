# ADR-0142: Interface-only unnumbered neighbors

**Status:** Accepted. The design questions left open in the proposal were
decided on 2026-10-21 and are written into the sections below.
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
  ones. Both are checked against the ASN the peer actually sends in OPEN (the
  four-octet AS capability when present). `"external"` is its own check: it
  does not reuse the dynamic-neighbor `0` sentinel, which also accepts iBGP.
- The interface does not need to exist when configuration loads. The neighbor
  waits in `interface_missing` until it appears, and the interface index is
  resolved by name on every link event, never cached across a recreation.
- Each interface has at most one interface-only neighbor, and an interface
  that has one cannot also have a static link-local neighbor.
- Peer groups apply as they do to any neighbor. `link_local_next_hop` is
  allowed. Families follow ADR-0069: IPv4 unicast requires RFC 8950.
- Rejected on an interface-only neighbor: explicit `listen_addresses` (the
  same rule as static link-local neighbors), `ttl_security_hops` above 1,
  `bfd.multihop`, `local_address`, and TCP-AO or MD5. Dynamic ranges still
  cannot match link-local sources.
- **Authentication limitation.** TCP-AO and MD5 are rejected with an explicit
  configuration error, not ignored, and are deferred to a later release. Until
  then an interface-only session has no TCP-layer authentication. What
  protects it is the link itself, OPEN validation against `remote_asn`, and
  optional GTSM. Deployments that require TCP-layer authentication on every
  session cannot use this mode yet.

### Discovery

- **Primary: Router Advertisements.** One raw ICMPv6 socket receives RAs on
  interfaces that have an interface-only neighbor. Packets are validated
  according to RFC 4861 §6.1.2: link-local source, IPv6 hop limit 255, ICMP
  code 0, a minimum length, and well-formed options. The kernel filter passes
  only RA and Router Solicitation (RS). Routers receiving other routers' RAs is
  standard behavior (RFC 4861 §6.2.7).
  - **Own advertisements are never candidates.** Linux loops IPv6 multicast
    back to local sockets by default, so the daemon's own all-nodes RA would
    otherwise pass every check above. The socket that sends RAs sets
    `IPV6_MULTICAST_LOOP` to 0, and discovery discards any RA whose source
    address is assigned to the receiving interface. The second check also
    covers RAs from another local sender, such as radvd.
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
- **Sending.** By default the daemon sends RAs only on the interfaces of
  explicitly configured interface-only neighbors, never on other interfaces
  (including those with static link-local neighbors), and answers Router
  Solicitations there. `ra_interval_secs` is RFC 4861's MaxRtrAdvInterval:
  unsolicited RAs go out at a uniformly random interval between
  MinRtrAdvInterval and that value (§6.2.4), with MinRtrAdvInterval set to
  0.33 times the interval but at least 3 s. The RA template is fixed:
  - Router Lifetime is three times the interval, RFC 4861's default ratio, so
    30 s at the default 10 s interval. RFC 4861 §6.2.1 bounds
    MaxRtrAdvInterval to 4..=1800 s, MinRtrAdvInterval to 3 s..=0.75 times
    MaxRtrAdvInterval, and AdvDefaultLifetime to 0 or MaxRtrAdvInterval..=9000
    s. The accepted interval range keeps the derived lifetime (12..=5400 s)
    inside those bounds, and so inside RFC 8319's wider limits too.
  - The lifetime is non-zero, as FRR's is, because BIRD's discovery treats
    lifetime 0 as a withdrawal. **A non-zero Router Lifetime advertises this
    router as eligible to be an IPv6 default router (RFC 4861 §4.2, §6.2.1),
    even though the RA carries no prefix options.** A neighbor that accepts
    RAs may install a default route through it. That is acceptable on
    dedicated fabric links, which is the only place these RAs are sent;
    operators should know the effect before enabling this mode on a link
    that also serves hosts.
  - There are no Prefix Information, MTU or RDNSS options. The Source
    Link-Layer Address option is included.
  - Current hop limit, reachable time and retransmit timer are 0
    ("unspecified"), so peers' RFC 4861 consistency checks do not log
    mismatches.

  When the interface comes up, and when the neighbor is added, the daemon
  also sends one RS, so that a peer which answers RSs is discovered in one
  round trip instead of waiting for its next unsolicited RA. FRR answers RSs;
  the interop gate demonstrates it.
- **Opting out.** `router_advertisements = false` is a global opt-out for
  sites where radvd or another daemon already advertises on those interfaces.
  It disables sending only: the daemon sends no RAs and no RSs, including the
  link-up RS, so discovery waits for the peer's next unsolicited RA. RA
  reception stays on, because discovery depends on it; a host whose RAs come
  from another advertiser still has to discover its peers. This is
  deliberately not a general RA daemon.
- **Privilege.** The raw ICMPv6 socket needs `CAP_NET_RAW`. It receives RAs
  whenever at least one interface-only neighbor is configured, whether or not
  sending is enabled, so the capability is required exactly then and not
  otherwise. Static link-local neighbors need no raw socket. Without the
  capability, `rustbgpd --check`, startup, and the reload that introduces the
  first interface-only neighbor fail with an error that names `CAP_NET_RAW`.
  The daemon never degrades silently to inbound-only discovery. The security
  reference and the example systemd units are updated to match.
- **Trust boundary.** The trust boundary is the link, as for any directly
  connected session. An RA or a SYN only proposes a TCP endpoint on that one
  interface, and the session still has to pass OPEN validation. Two hop-limit
  checks are distinct here:
  - The Hop Limit 255 check on received RAs is mandatory (RFC 4861 §6.1.2).
    An RA that fails it is discarded.
  - TCP GTSM (RFC 5082) is unchanged and opt-in, enabled per neighbor or peer
    group with `ttl_security` as on any other neighbor. RFC 5082 §3 says GTSM
    SHOULD NOT be on by default, and peers using ordinary eBGP hop limits,
    such as FRR's default, must still connect.

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
- A second connection is a collision only when its OPEN carries the same
  effective remote ASN (the four-octet AS capability when present) and the
  same BGP Identifier as the other connection. RFC 6286 §2.1 makes the
  Identifier unique only within an AS, and with `remote_asn = "external"` two
  routers in different ASes can both pass OPEN validation with one
  Identifier. If either value differs, the connection is a second router on a
  link that is defined to have one, and it is refused with
  `multiple_routers_on_link` instead of entering collision resolution.

### Sessions and collisions

Both ends connect actively, and both accept passively, as FRR does and as
static link-local neighbors do today. Connection collision follows RFC 4271
§6.8 and [ADR-0021](0021-tcp-collision-detection.md) unchanged once two
connections are established to be the same router, by the remote ASN and
Identifier match above. Resolution compares BGP Identifiers, with ADR-0021's
RFC 6286 §2.3 ASN tie-break, so link-local addresses play no part. The
connection that wins fixes the session's endpoint.

### Lifecycle

States: `interface_missing`, `link_down`, `awaiting_discovery`, then the
ordinary FSM states once an address is bound.

- **Carrier loss or interface removal.** Confirmed carrier loss or removal of
  the interface tears the session down at once with a Cease NOTIFICATION,
  matching FRR's default fast external failover, and clears the binding and
  candidates. This is a local stop, not a transport failure: Graceful Restart
  and LLGR routes are purged, not retained
  ([ADR-0024](0024-graceful-restart.md), [ADR-0042](0042-llgr.md)).
  Their next hop sits behind a down or deleted interface. A monitor state
  that cannot be read is not confirmed carrier loss.
- **Address change.** A different learned address is a new TCP endpoint. It is
  modelled as session down, then up, under the same neighbor identity, with
  state reason `peer_address_changed`.
  - Discovery never ends a healthy Established session. Expiry of the bound
    source's RA, a new live candidate, or both together are not a session
    failure. The existing session has to fail first, through its hold timer,
    BFD, a NOTIFICATION or TCP close from the peer, or confirmed carrier
    loss. Only then does the next attempt bind by the reselection rule above,
    or accept an inbound session from the new source. This is the same
    guarantee as for a second RA source: discovery input alone never moves an
    Established session.
  - An expired source with no replacement changes nothing either. Session
    liveness belongs to the hold timer and BFD.
  - When the binding actually moves to a different address, routes retained
    from the old session are purged, not kept as stale, because their next
    hop is the old link-local address.
- **Ordinary transport loss.** When carrier is up and the endpoint is not
  replaced, ordinary transport loss keeps the existing Graceful Restart and
  LLGR helper behavior. Each session generation records its own endpoint, so
  retained routes keep the endpoint they were learned from. Retention ends,
  with a purge, only on confirmed carrier loss, interface removal or an
  actual endpoint replacement, or when the normal timers expire.
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

This mode ships before the scoped RIB identity. Until that lands, the
existing duplicate-address rule is enforced at admission. A learned address
that equals another neighbor's address is refused with
`duplicate_link_local_address`. The check and the binding are one atomic step
in the peer manager's single owner, so two links that discover the same
address at the same time cannot both be admitted, and a static neighbor added
by reload or RPC is checked against bound learned addresses the same way.

That covers the common Clos shape, where each fabric link goes to a different
switch with its own MAC. **Limitation:** parallel links to the same device
(one router MAC on every port, so one EUI-64 address), or `fe80::1` on every
port, do not work until the scoped identity lands. Only the first link
admitted establishes. Every other link stays down with
`duplicate_link_local_address`, and after a restart, which link is admitted
first depends on timing. Those links carry no traffic until then.

Once the duplicate-address rule is lifted, two further rules apply:

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
    sends no RAs, FRR has `no bgp ipv6-auto-ra`, FRR lacks `v6only` and is
    preferring an IPv4 /30 or /31 session, or `router_advertisements = false`
    is set with no other advertiser on the link, so the peer cannot discover
    this router;
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
  - after link-up, the daemon's RS is answered by FRR and the session's
    endpoint is learned from that solicited RA, before FRR's next
    unsolicited one;
  - our own RAs are never reported as a candidate or a conflict;
  - with an FRR leg that runs `no bgp ipv6-auto-ra` and a static neighbor
    toward us, the session establishes through inbound learning;
  - a third RA source on a bridged segment is reported as a conflict and
    does not cause a flap, and neither does letting the bound source's RA
    expire while the session stays healthy.
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
- Multihop and VRFs. TCP-AO and MD5 are deferred, as described under
  Configuration.
- Carrier-loss teardown for existing directly connected eBGP neighbors,
  static link-local and numbered. It has been decided separately, on by
  default with opt-outs, and is specified and delivered on its own; this
  record does not define it.

## Consequences

- Fabric configuration needs only port names: one stanza per port, no
  addresses, no ASN bookkeeping with `remote_asn = "external"`.
- The daemon gains a raw ICMPv6 socket and therefore `CAP_NET_RAW`, but only
  for configurations with at least one interface-only neighbor, whether or not
  RA sending is on. Static link-local neighbors and control-plane-only
  route-server and route-reflector deployments keep their current privileges.
- A non-zero Router Lifetime makes this router a default-router candidate on
  every interface-only link. That is intended for dedicated fabric links.
- Interface-only sessions have no TCP-layer authentication until TCP-AO or
  MD5 support is added.
- Link loss now ends interface-only sessions immediately rather than at hold
  expiry or BFD detection, and those routes are not retained for Graceful
  Restart.
- Discovery is decided by rules that do not depend on timing, so a stray RA
  source produces a reported conflict, not session churn.
- Parallel links to one device need the scoped RIB neighbor identity. Until
  it lands, they are refused explicitly rather than aliased.
- ADR-0069's first Deferred item is addressed by this record. The static
  link-local mode stays unchanged.

## References

- RFC 4861, Neighbor Discovery for IPv6 (§4.2 Router Lifetime, §6.1.2 RA
  validation, §6.2.1 router configuration variables, §6.2.4 unsolicited RA
  timing, §6.2.7 RA consistency):
  <https://www.rfc-editor.org/rfc/rfc4861>
- RFC 8319, adjustable maximum router lifetimes:
  <https://www.rfc-editor.org/rfc/rfc8319>
- RFC 5082, Generalized TTL Security Mechanism:
  <https://www.rfc-editor.org/rfc/rfc5082>
- RFC 6286, AS-wide unique BGP Identifier:
  <https://www.rfc-editor.org/rfc/rfc6286>
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
