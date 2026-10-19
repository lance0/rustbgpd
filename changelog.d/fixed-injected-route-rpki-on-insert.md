### Fixed

- A route injected with `AddPath` is now validated against the current RPKI
  VRP table when it is created or replaced, as received routes are. It used to
  stay `NotFound` until the next VRP change covering its prefix, so a
  replacement could lose to a received Valid route, or be denied by an export
  policy that matches on validation, until the cache next updated.
