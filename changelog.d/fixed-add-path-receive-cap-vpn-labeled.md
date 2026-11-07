### Fixed

- The per-prefix Add-Path receive cap now also covers VPNv4/VPNv6 (SAFI 128,
  per RD + prefix) and IPv4/IPv6 labeled unicast (SAFI 4), the other families
  `add_path.receive` advertises. Before, a peer could send any number of path
  IDs for one VPN or labeled NLRI: 32,000 IDs cost the RIB about 4.7 s of CPU,
  and the per-family `max_prefixes_*` bounds could not stop it because the
  paths collapse to one prefix. Past the cap the excess is withheld and
  counted in `bgp_add_path_receive_limit_attempts_total`, with the family
  label naming the VPN or labeled family. See
  [Add-Path configuration](../docs/reference/configuration.md).
