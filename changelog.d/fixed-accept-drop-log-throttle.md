### Fixed

- Inbound connections dropped from an unknown source, from an unmatched IPv6
  link-local source, or at the dynamic neighbor limit, and transient listener
  accept errors, no longer log one line each without limit: a scan or a
  misconfigured remote could fill the journal. Each kind now logs at most one
  line per second at its existing level and fields, with a `suppressed` count
  of the lines skipped since the previous one.
  `bgp_inbound_connections_dropped_total` still counts every drop.
