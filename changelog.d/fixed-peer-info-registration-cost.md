### Fixed

- Peer identity metric publication removes the exact previous label tuple
  instead of scanning every peer's series. Large peer registrations avoid
  quadratic metric work while description, peer-group, and learned ASN
  changes continue to replace stale identity rows.
