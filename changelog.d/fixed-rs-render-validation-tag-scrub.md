### Fixed

- In arouteserver mode, `rs-config-render` now scrubs every configured
  `*_validated_*` tag community (`route_validated_via_white_list`,
  `prefix_validated_via_rpki_roas`, `prefix_validated_via_arin_whois_db_dump`,
  `prefix_validated_via_registrobr_whois_db_dump`) from received routes,
  whether or not `irrdb.tag_as_set` is on or the feature that sets the tag is
  enabled, as arouteserver's `scrub_communities_in()` does. Previously only
  the white-list and ROA tags were scrubbed, and only when the render also set
  them, so a member could send a lookalike validation tag that other clients
  received unchanged.
  **Operator-visible:** rendered `rs-hygiene.rpol` gains a `scrub-*-tag` term
  for each configured tag, and member-sent copies of those communities are
  removed on import. An `ext` form or a malformed value of the ARIN or
  registro.br tag is now refused (exit 2), as it already was for the
  white-list and ROA tags. See the
  [renderer README](../tools/rs-config-render/README.md).
