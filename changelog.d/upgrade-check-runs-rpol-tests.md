### Upgrade notes

- `rustbgpd --check` now runs the in-language `test` blocks of every
  configured `.rpol` unit and exits 1 when one fails. A deployment gate that
  passed a config whose `.rpol` tests fail will now stop it; run
  `rbgp policy check` on the named file to see the failure. The running
  daemon's behavior is unchanged unless `[policy] require_passing_tests` is
  set.
