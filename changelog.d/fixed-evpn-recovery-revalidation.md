### Fixed

- Keep EVPN DF recovery deadlines ahead of queued route events, and revalidate
  pending segment starts after withdrawal acknowledgements and configuration
  changes so removed or drained segments do not originate stale candidates.
  Publish each replacement's non-DF forwarding state before waiting for another
  segment's withdrawal, retaining that segment's owned attachment circuit gate.
