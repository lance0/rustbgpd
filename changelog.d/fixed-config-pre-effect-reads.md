### Fixed

- Bound config transactions' initial snapshot and planning waits, including
  gNMI Set's config snapshot and requested history rollback preparation, by
  the owner's pre-effect deadline. Queue admission and missing read replies
  now end with a clean `UNAVAILABLE`
  response before runtime mutation; confirmed transactions discard any
  uncommitted revert authority. Post-commit planning, mutation acknowledgements,
  and compensation retain their existing settlement behavior.

  **Operator-visible:** an unavailable config read or initial plan no longer
  consumes the full settlement budget and triggers fail-stop with nothing
  applied. Retry after the peer manager becomes responsive.
