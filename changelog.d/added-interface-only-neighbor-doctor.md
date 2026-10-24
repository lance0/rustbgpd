### Added

- `rbgp doctor` checks interface-only neighbors by interface:
  `interface_only.<if>.discovery` is red for a missing interface, yellow for a
  down link, and yellow with FRR hints (`no bgp ipv6-auto-ra`, `v6only`,
  `router_advertisements = false`) when no peer address has been learned
  after three RA intervals. `interface_only.<if>.multiple_routers` and
  `unnumbered.ra_socket` report a second router on the link and failed
  discovery socket opens. A bound neighbor's session is checked under its
  learned address, and an unbound one is no longer reported as a stuck
  session. See
  [Support bundles with `rbgp doctor`](../docs/reference/operations.md#support-bundles-with-rbgp-doctor).
