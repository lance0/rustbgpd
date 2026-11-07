### Fixed

- BLACKHOLE discard-route installs and withdrawals no longer stop until
  restart when an adopted route from a previous daemon lifetime disappears,
  or is replaced by a foreign route, between a failed startup receipt write
  and its retry. The adoption is now dropped together with the prefix's
  ownership, so the later reap no longer finds a pending route that the
  receipt does not name.
