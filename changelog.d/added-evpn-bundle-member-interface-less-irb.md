### Added

- Allow single-homed VLAN-aware bundle members to bind an IP-VRF configured
  with `overlay_index_mode = "interface_less"`. Routed Type 5 prefixes retain
  Ethernet Tag `0` and the separate IP-VRF L3VNI, RD, route targets and Router
  MAC; member Type 2/3 routes retain their Ethernet Tags. Linux SVI/VRF
  attachments remain operator-provisioned. Bundle multi-homing, locally
  assigned VNIs, non-zero-tag Type 5, and GW-IP/ESI overlay-index resolution
  through bundle members remain unsupported. A
  [local SR Linux 25.10.1 receipt](../docs/artifacts/interop/m120-evpn-bundle-irb-20261011T045852Z/README.md)
  qualifies routed forwarding, Type 5 withdrawal and binding reloads; EVPN
  remains alpha. See the
  [bundle configuration](../docs/reference/configuration.md#vlan-aware-bundle-members).
