### Fixed

- Preserve operator authority when applying EVPN runtime candidates, allowing
  operator callers to stage policy sources outside the running policy roots.
  Automation and other callers below `operator_only` remain confined.
