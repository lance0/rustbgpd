### Fixed

- Report AS 0 in an `AS_PATH` (RFC 7607) when an earlier `AS_PATH` copy in
  the same UPDATE was rejected for its attribute flags. The earlier copy
  suppressed the AS 0 cause although it never recorded one, so
  `bgp_update_malformed_causes_total` and the warning omitted it.
