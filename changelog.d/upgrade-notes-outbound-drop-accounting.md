### Upgrade notes

- `bgp_outbound_route_drops_total{peer}` keeps its name and labels, but what it
  counts has changed. It now rises for writer-channel deferrals in every
  address family, so rates on EVPN, VPN, FlowSpec, labeled-unicast, BGP-LS or
  RT-Constrain peers can rise after the upgrade. It no longer counts RFC 4724
  selection-gate, missing-encoder or EVPN-recovery refusals. Those refusals are
  now counted in `bgp_outbound_commit_refusals_total{peer,reason}`.
  The shipped `BgpOutboundRouteDrops` alert changed from critical to warning. A
  local copy of the alert pack keeps the old critical rule until it is replaced,
  and routing keyed on its severity needs review. Alert on
  `BgpOutboundResyncStalled` for outbound recovery that is not converging.
