### Changed

- During synchronous export-policy changes and rollback, neighbor listings
  and detail reads keep entry values for the named peers and members of their
  source and destination update groups. Other peers report current state,
  so a listing can contain observations from different times. Update-group
  comparisons still use a consistent pair of memberships.
