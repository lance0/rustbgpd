### Fixed

- A peer whose BGP Role capability carries an unassigned value (5-255) or a
  length other than 1 is now refused with a Role Mismatch NOTIFICATION (2/11)
  when a local `role` is configured, as RFC 9234 section 4.2 requires.
  Previously the capability was ignored and the session established as if
  the peer had sent no Role, unless `strict_role` was set. An OPEN with
  several Role capabilities that include an unassigned value, such as
  Customer plus 7, is now also refused with 2/11, with or without a local
  `role`. **Operator-visible:** such a session no longer establishes, and
  `bgp_role_mismatch_total` counts it with `remote_role="none"`. See
  [RFC notes](../docs/reference/rfc-notes.md#rfc-9234--roles-and-only-to-customer).
