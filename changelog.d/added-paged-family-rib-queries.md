### Added

- Bounded received and advertised VPN, labeled-unicast and RT-Constrain
  route pages, with family, RD, prefix and membership filters as appropriate.
  An additive EVPN best-route page filters MAC, ESI and VXLAN VNI without
  copying the full table. New `rbgp rib vpn|labeled|rtc received|advertised`
  and `rbgp evpn best` commands expose mutation-fenced continuation tokens
  and JSON page metadata. Group-owned VPN advertised pages refuse reads
  while that destination is resynchronizing. Existing unpaged RPCs and CLI arrays are unchanged;
  the additions remain outside the current v1 inventory.
