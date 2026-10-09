### Fixed

- A remote EVPN Type 5 route with a non-zero Ethernet Tag is no longer
  imported into a matching IP-VRF. It is counted as `non_zero_ethernet_tag`
  in `evpn_ip_vrf_remote_prefix_drops`, as
  [ADR-0092](../docs/adr/0092-evpn-vlan-aware-bundle-service.md) requires.
  The route is still reflected, and no NOTIFICATION is sent.
