### Fixed

- In arouteserver mode, `rs-config-render` now also scrubs the other
  fixed-value communities arouteserver's `scrub_communities_in()` removes from
  received routes: the internal `rpki_bgp_origin_validation_valid`,
  `rpki_bgp_origin_validation_unknown`, `rpki_bgp_origin_validation_invalid`
  and `reject_cause_map_*` communities, and every `custom_communities` entry.
  The renderer sets none of them, but a member-sent copy used to reach other
  clients unchanged. `reject_cause` is still not scrubbed, because rpol cannot
  remove its `dyn_val` range; see the filter-pipeline cookbook,
  `docs/cookbook/ixp-filter-pipeline.md`.
  **Operator-visible:** rendered `rs-hygiene.rpol` gains `scrub-rpki-ov-*`,
  `scrub-reject-cause-map` and `scrub-custom-communities` terms when those
  communities are configured, and candidate hashes change. An `ext` form or a
  malformed value of any of them is refused (exit 2), and so is a client's
  non-empty `attach_custom_communities`, which was previously dropped without
  a warning. A configured `rejected_route_announced_by` is now refused under
  every `reject_policy`, not only `tag_and_reject`.
