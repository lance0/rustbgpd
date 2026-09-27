### Changed

- A member that becomes the new best source for some prefixes in a
  distribution pass, such as the alternate in a member failover, now stays on
  its update-group's shared announce payload, exact-export probe results and
  once-encoded announcements. It receives the withdrawals for the prefixes it
  took over ahead of the shared announcements, instead of a private copy of
  the pass built and probed for it alone. A member re-announcing its own best
  path with new attributes also stays on the shared payload. Old sources of
  withdrawn prefixes, exception-lane targets and RS-control members in a
  tagged pass keep the per-member path.
