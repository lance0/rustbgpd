### Documentation

- Document the `CAP_NET_RAW` requirement for interface-only neighbor
  discovery, including when RA sending is disabled. Add an opt-in systemd
  capability drop-in that composes with the dataplane example, while keeping
  the default unit's capability set unchanged.
