### Changed

- Reduce unicast fanout work by skipping unrelated EVPN bookkeeping and
  local-source metadata writes when no old or new local provenance exists.
