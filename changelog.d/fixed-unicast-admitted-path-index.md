### Fixed

- Avoid scanning every admitted sibling when a unicast Add-Path initial
  table inserts increasing path IDs. Existing route and next-hop-action
  identities remain exact through replacement, withdrawal and slot reuse.
