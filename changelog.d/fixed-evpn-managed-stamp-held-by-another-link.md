### Fixed

- Creating a managed EVPN netdev no longer leaves an unstamped link behind
  when another link already holds its ownership altname. The kernel
  rejects the stamp with `EEXIST`, which rustbgpd treated as
  already-stamped. The new link then stayed unstamped, was reported as
  `foreign-present` and was never reaped. rustbgpd now rolls the create
  back and reports the conflict until the other link's altname is
  removed.
