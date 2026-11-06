### Added

- `.rpol` `remove <kind> in D` and `remove <kind> not in D` accept a
  community dataset as well as a community-set, directly or through a
  `community-set` parameter. The scan reads the snapshot pinned at walk
  start and filters it by kind at runtime, so it follows the current
  contents literally: an empty snapshot, or one with no member of the
  action's kind, makes `not in` remove every value of the kind, apart from
  the well-known standard communities and, for `ext-community not in`, the
  extended communities that are not route targets or route origins.
  Dataset refresh validation is the guard, as a missing, unreadable or
  malformed file keeps the prior snapshot. A content swap reaches installed
  chains without recompiling them and refreshes the peers whose chains
  remove by the dataset. See
  [Removing by set membership](../docs/reference/rpol-language.md#removing-by-set-membership).
