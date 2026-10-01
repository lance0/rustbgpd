### Added

- EVPN Type 6 Selective Multicast Ethernet Tag (SMET) relay: typed
  receive, reflection, withdrawal, route/event inspection, and exact
  `rbgp evpn explain smet` selection, with generic MRT, BMP, and warm-state
  preservation. Source/group wildcards are explicit; flags remain payload
  outside the key. Invalid announcement flag profiles use treat-as-withdraw
  with all decoded keys retained; withdrawals ignore announcement flags.
  This remains alpha RR support. The [M113 controlled raw-peer proof](../docs/artifacts/interop/m113-smet-20261001T180815Z/README.md)
  checks reflected bytes and error recovery with an independent TShark decoder;
  vendor interoperability remains unproven.
  SMET origination, IGMP/MLD proxy, multicast forwarding, and Types 7–11
  remain outside scope. See the
  [Type 6 boundary](../docs/reference/rfc-notes.md#type-6-smet-reflection).
- Prepare wire `0.23.0`, FSM `0.10.0`, and RPKI `0.5.0` for the changed
  Type 6 decoder behavior and shared public wire types. Published dependency
  examples remain on the last published versions until registry publication.
