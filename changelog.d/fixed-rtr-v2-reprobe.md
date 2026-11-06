### Fixed

- An RTR cache that fell back to protocol v1 now returns to v2 when it supports
  it. Previously any failure before the first End of Data, such as one connection
  reset at startup, kept that cache at v1, without ASPA, until the daemon
  restarted. A v1 session entered by fallback now reconnects to probe v2 at its
  first refresh at least an hour later. A cache that refuses v2 is resumed at v1
  at once, with its held data and serial. See
  [ASPA conformance](../docs/reference/aspa-conformance.md).
