### Fixed

- Service RIB readiness queries while installing outbound prefix limits on
  existing update-group members. The admitted-prefix inventory reserves its
  family capacity before filling and releases old entries between checkpoints,
  preserving the existing advertised routes and prefix accounting.
