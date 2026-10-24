### Fixed

- Outbound prefix-limit messages name a link-local session by its scope.
  This covers a refused lowering, the export explain reason, and the
  limit-reached and recovered log lines. A link-local session appears as
  `fe80::2%swp1`, and an interface-only neighbor as `interface:swp1`,
  instead of the bare address that sessions on several links can share.
  **Operator-visible:** the `peer` value in these messages and log events
  changes for link-local and interface-only sessions; other neighbors still
  appear by address.
