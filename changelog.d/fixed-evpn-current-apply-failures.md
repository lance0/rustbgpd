### Fixed

- Show still-current Linux EVPN L2 apply failures in the
  `evpn_current_apply_failures` metric and instance
  status, including host-wide failures and operations held by permanent
  suppression or retry backoff.
  Clear them after success, withdrawal, or a changed operation shape.
