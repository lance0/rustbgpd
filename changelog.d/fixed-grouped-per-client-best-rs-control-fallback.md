### Fixed

- A route-server client with `per_client_best` and RFC 7947 control
  communities now receives its own best eligible route when the best path is
  suppressed toward it. Before, a client sharing an update group got nothing
  for the prefix when the best path carried `0:PEER` / `RS:0:PEER` for its
  ASN, or `0:RS` / `RS:0:0` without an override. An ungrouped client got the
  runner-up. A grouped client now gets the same route an ungrouped client
  gets: the runner-up, a later path when the runner-up is the client's own or
  is also suppressed toward it, or a withdrawal when no eligible path
  remains. Per-target prepend and the control-community scrub apply to that
  route. The same applies on join, route refresh and resync, and when a tag
  arrives on an already advertised best path. When the route a client gets
  this way is a local RTBH route, removing it during a graceful-restart
  selection hold withdraws it at once, and RFC 9234 OTC rejection reports
  name the route the client would have received.
  **Operator-visible:** affected clients now receive routes for these
  prefixes. Prefixes whose paths carry no suppression community keep the
  existing shared update-group emission.
