### Added

- EVPN Type 6 Selective Multicast Ethernet Tag (SMET) relay: typed
  receive, reflection, withdrawal, route/event inspection, and exact
  `rbgp evpn explain smet` selection, with generic MRT, BMP, and warm-state
  preservation. Source/group wildcards are explicit; flags remain payload
  outside the key. Invalid announcement flag profiles use treat-as-withdraw
  with all decoded keys retained; withdrawals ignore announcement flags.
  This remains alpha RR support, with external Type 6 peer proof pending.
  SMET origination, IGMP/MLD proxy, multicast forwarding, and Types 7–11
  remain outside scope. See the
  [Type 6 boundary](../docs/reference/rfc-notes.md#type-6-smet-reflection).
- Prepare wire `0.23.0`, FSM `0.10.0`, and RPKI `0.5.0` for the changed
  Type 6 decoder behavior and shared public wire types. Published dependency
  examples remain on the last published versions until registry publication.
