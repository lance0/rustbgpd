### Added

- The VTEP now serves single-homed VLAN-aware bundle members
  (RFC 8365 §5.1.2, ADR-0092). An `[[evpn_instances]]` row with
  `service_interface = "vlan_aware_bundle"` and an explicit `ethernet_tag`
  is accepted. It originates its IMET and its local MAC-only, MAC+IP and
  SVI-MAC Type 2 routes under that Ethernet Tag, and programs remote Type 2
  and Type 3 routes only when they carry its tag, its VNI and a bundle
  route target. The FDB rows land on the member's `bridge_vlan`, so the
  same MAC under two tags is kept in two VLANs. For a bundle member,
  `evpn_l2_remote_route_drops` now also counts `vni_mismatch` (route target
  and tag select the member but the VNI differs) and
  `multihoming_unsupported` (a multi-homed Type 2 or an EAD-per-EVI route).
  For every L2VNI it also counts received IMET routes under another
  Ethernet Tag as `ethernet_tag_mismatch`. `ListEvpnInstances` adds
  `service_interface` and `ethernet_tag`, and `rbgp evpn instances` shows
  `service=vlan-aware-bundle ethernet-tag=N` for bundle members. Members
  cannot join an Ethernet Segment or link an `ip_vrf`, and non-zero-tag
  Type 5 routes are still not imported. See
  [VLAN-aware bundle members](../docs/reference/configuration.md#vlan-aware-bundle-members).
