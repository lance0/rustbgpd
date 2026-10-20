### Changed

- Policy `set_next_hop` (TOML) and `set next-hop` (`.rpol`) now refuse an
  unspecified (`0.0.0.0`, `::`) or multicast address with an error naming the
  value, at config load, SIGHUP reload, and API policy edits. Such a next hop
  was previously accepted and the route was later dropped from the FIB or
  refused at export. IPv4 and IPv6 link-local addresses remain accepted.
