### Fixed

- When a graceful-restart selection hold released, a forced resync it had
  deferred (from an Address Prefix ORF refresh with When-to-refresh
  IMMEDIATE, or an outbound refresh such as a GShut toggle) ran on the
  held best paths before the release selected new ones. A receiver whose
  full outbound queue still owed a withdrawal from before the hold, for a
  route the source announced again inside it, was sent that withdrawal in
  one UPDATE and the new route in the next. For a blackhole (RTBH) host
  route the receiver briefly had no blackhole route. The deferred resync
  now runs after the release's selection, so the receiver gets one UPDATE
  that replaces the row.
  **Operator-visible:** at a selection-hold release, such a receiver no
  longer sees a withdrawal immediately followed by a re-announcement of
  the same prefix.
