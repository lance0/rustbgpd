### Added

- `rbgp doctor` warns when an established eBGP peer has no effective inbound
  prefix limit after peer-group inheritance, naming the peer and available
  configuration keys. iBGP and route-reflector clients are excluded; the
  advisory warning retains exit status 0.
