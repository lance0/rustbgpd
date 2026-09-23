### Fixed

- A SIGHUP after any runtime mutation no longer logs false restart-required
  `ERROR` lines ("config_epoch or [global].ebgp_requires_policy differs from
  the live config", and "[global] changed" when the boolean was omitted) on
  every reload until restart. The canonical rewrite makes an omitted
  `config_epoch` or `ebgp_requires_policy` explicit without changing the
  effective posture: epoch 1 with the boolean omitted becomes explicit
  `false`, and epoch 2 with the boolean omitted becomes explicit `true`. The
  reload now keeps the running values silently in that case. A real epoch or
  enforcement-mode edit is still pinned and logged as restart-required.
