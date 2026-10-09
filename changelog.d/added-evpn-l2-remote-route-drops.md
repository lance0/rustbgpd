### Added

- The VTEP now counts remote Type 1 EAD-per-EVI and Type 2 routes that
  match a local L2VNI by VNI and route target but carry another Ethernet
  Tag. Before, it skipped them silently. The new
  `evpn_l2_remote_route_drops{vni,reason}` gauge reports them with reason
  `ethernet_tag_mismatch`. The routes stay in Adj-RIB-In and are still
  reflected. `[[evpn_instances]]` also gains `service_interface` and
  `ethernet_tag` for the VLAN-aware bundle service, validated against the
  bundle rules. See
  [the configuration reference](../docs/reference/configuration.md#validation).
