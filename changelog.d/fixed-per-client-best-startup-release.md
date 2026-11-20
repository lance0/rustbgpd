### Fixed

- Route-server clients with `per_client_best = true` no longer converge
  slowly after a restart. The paced startup release of a unicast family
  delivered such an update group one prefix and one client at a time while
  the route-processing lane was closed to other input, so a release that
  takes seconds for an ordinary group took tens of seconds and delayed
  unrelated UPDATEs by seconds. The group's prefixes are now ranked in
  bounded steps, staged together and sent to 16 clients a step, in one
  message for each batch of up to 1,024 prefixes. No route was lost or wrong.
  A prefix with more than 128 denied or control-community-suppressible
  candidates is still released on its own.
