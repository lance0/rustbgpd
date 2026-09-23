### Fixed

- The comments printed by `rustbgpd --init-config lab` now match the profile's
  RFC 8212 enforcement. Omitting the written-out permit-all chains rejects
  routes rather than permitting them, and deleting one leaves the session
  Established with no routes in that direction rather than stopping it. The
  run hint names `config.toml`, the file the quickstart saves.
