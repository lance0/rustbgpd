### Changed

- Update-group members now keep the shared encode for a distribution pass that
  mixes unicast withdrawals with announcements, such as a member failover
  where some prefixes move to an alternate source and others have none. Each
  member sends its own withdrawals first, then streams the group's
  once-encoded announcements, instead of re-preparing and re-encoding the
  announcements itself. New winning sources still take the per-member path.
