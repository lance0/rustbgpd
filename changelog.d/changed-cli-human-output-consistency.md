### Changed

- Human CLI output reads more consistently. `rbgp events` and `rbgp watch`
  lines show RFC 3339 UTC timestamps instead of raw epoch seconds.
  `rbgp neighbor <peer>` aligns every value in one column sized to the
  longest label, indents negotiated-session, graceful-restart, posture,
  TCP-AO and per-family rows under their parent, and prints
  `GShut Advertise Intent` as `true`/`false`/`unknown` like the page's other
  booleans. `rbgp health` labels its peer count `Established peers`, which is
  what it counts. The `rbgp config` transaction trailer uses readable labels
  (`Status:`, `Confirmation:`, `Confirm deadline:` in RFC 3339, and so on)
  instead of snake_case keys. JSON output is unchanged apart from the added
  event field; scripts should parse `--json` rather than these text lines.
