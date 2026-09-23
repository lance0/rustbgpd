### Fixed

- A SIGHUP after any runtime mutation no longer logs a false RFC 8212
  posture `ERROR` ("config_epoch or [global].ebgp_requires_policy differs
  from the live config") on every reload until restart. The canonical
  rewrite makes an omitted `config_epoch` or `ebgp_requires_policy` explicit
  without changing the effective posture; the reload now keeps the running
  tuple silently in that case. A real epoch or enforcement-mode edit is still
  pinned and logged as restart-required.
