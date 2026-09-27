### Changed

- Stored path attributes take 48 bytes each instead of 208. The
  `rustbgpd-wire` `PathAttribute` enum was sized by its inline
  `MP_REACH_NLRI` payload, which the RIB never stores; that payload and
  `MP_UNREACH_NLRI` are now boxed. At 900,000 prefixes with one attribute set
  per seven prefixes, allocator-live RIB bytes fall 117.7 MiB: 18.7% on the
  full-RIB shape and 12.9% on the route-reflector fanout shape. UPDATE
  parsing is up to 17% faster on the measured fixtures. An UPDATE that
  carries both MP attributes makes two extra small allocations and parses
  2–6% slower on the codec fixture
  ([receipt](../docs/perf/boxed-mp-path-attributes-2026-09.md)).
  **Embedders:** construct `PathAttribute::MpReachNlri` and
  `PathAttribute::MpUnreachNlri` with `Box::new(..)`; see the
  `rustbgpd-wire` 0.22.0 changelog.
