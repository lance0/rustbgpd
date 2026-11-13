### Fixed

- An RFC 7313 enhanced route refresh now removes a retained IPv4/IPv6-unicast
  rejection the peer did not re-announce before End-of-RIB-Refresh (or before
  the refresh window timed out), on the same boundary that sweeps stale
  accepted routes. Such a rejection previously stayed in
  `rbgp rib received PEER --rejected` and in BMP RFC 9972 type 22 until the
  session reset. BMP types 7, 18 and 19 are no longer omitted after an
  enhanced route refresh.
