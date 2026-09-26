### Fixed

- An UPDATE with a zero-length `CLUSTER_LIST` from an internal neighbor now
  treats its routes as withdrawn under RFC 7606 section 7.10, while the BGP
  session stays established. External neighbors still discard the attribute
  and keep the routes; valid non-empty lists remain accepted.
