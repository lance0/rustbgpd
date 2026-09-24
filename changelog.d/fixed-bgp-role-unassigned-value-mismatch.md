### Fixed

- A peer whose BGP Role capability carries an unassigned value (5-255) is
  now refused with a Role Mismatch NOTIFICATION (2/11) when a local `role` is
  configured, as RFC 9234 section 4.2 requires. A Role capability with a
  length other than 1 is refused the same way; RFC 9234 has no requirement
  for that case, so this is rustbgpd's local policy. Previously both were
  ignored and the session established as if the peer had sent no Role,
  unless `strict_role` was set. An OPEN with several Role capabilities that
  include an unassigned value, such as Customer plus 7, is now also refused
  with 2/11, with or without a local `role`. **Operator-visible:** such a
  session no longer establishes. `bgp_role_mismatch_total` reports the first
  assigned Role in the OPEN as `remote_role`, so Customer plus 7 counts as
  `remote_role="customer"`; it uses `remote_role="none"` only when the OPEN
  carries no assigned Role value. See
  [RFC notes](../docs/reference/rfc-notes.md#rfc-9234--roles-and-only-to-customer).
