### Added

- Bounded received and advertised VPN, labeled-unicast and RT-Constrain
  route pages, with typed family selectors, exact or longer prefix filters,
  and RD or membership filters as appropriate. Views distinguish the required
  received/advertised neighbor from an optional best-route source filter.
  An additive EVPN best-route page filters MAC, ESI and VXLAN VNI without
  copying the full table. EVPN received/advertised pages also accept the
  explicitly unstable MAC, ESI and VNI filters, with exact raw RD input
  available on the new family pages and existing EVPN peer pages. New `rbgp rib vpn|labeled|rtc received|advertised`
  and `rbgp evpn best` commands expose mutation-fenced continuation tokens
  and JSON page metadata. Group-owned VPN advertised pages refuse reads
  while that destination is resynchronizing. Existing unpaged RPCs and CLI arrays are unchanged;
  the additions remain outside the current v1 inventory.
