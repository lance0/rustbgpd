### Changed

- MRT snapshot encoding builds each IPv6 or extended-next-hop route's
  `MP_REACH_NLRI` next-hop attribute on the stack instead of allocating it.
  On a two-feed IPv6 table this removes one allocation per route and makes
  the encoder about 3% faster; the MRT output is byte-identical
  ([receipt](../docs/perf/artifacts/mrt-ipv6-mp-reach-2026-09/README.md)).
