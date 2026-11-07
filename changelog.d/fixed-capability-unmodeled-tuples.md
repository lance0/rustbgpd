### Fixed

- One Add-Path tuple for an address family rustbgpd does not model (for
  example AFI 1 / SAFI 200) no longer discards the peer's whole Add-Path
  capability. Before, the session negotiated no Add-Path at all while the
  peer still sent path IDs for the families it had listed, so those UPDATEs
  were misread as prefixes, giving bogus announcements or a session reset.
  Only the unmodeled tuple is now ignored (RFC 5492 §4, RFC 7911). Extended
  Next Hop, Long-Lived Graceful Restart, Paths-Limit and Outbound Route
  Filtering capabilities get the same per-tuple handling.
