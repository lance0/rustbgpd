### Fixed

- Preserve actual EVPN admissions across group handoffs and same-connection
  replay, and settle recovery only after complete route delivery and ordered
  terminal markers. EVPN update-group ownership remains disabled in production.
- Preserve current EVPN coverage when a full outbound queue refuses another
  family's ready terminal marker while the EVPN marker remains held.
