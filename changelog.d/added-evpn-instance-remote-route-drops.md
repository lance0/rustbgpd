### Added

- `rbgp evpn instances` and the `ListEvpnInstances` API now report, per
  L2VNI, the remote Type 1 EAD-per-EVI and Type 2 routes that the VTEP
  does not program, by reason (for example `ethernet_tag_mismatch`). The
  new `EvpnInstanceState.remote_route_drop_counts` field carries the same
  current values as the `evpn_l2_remote_route_drops{vni,reason}` gauge.
  The human output adds `remote-route-drops=[reason=N,...]` when a VNI has
  drops; JSON adds `remote_route_drop_counts`. See
  [the API reference](../docs/reference/api.md#list-local-evpn-instances).
