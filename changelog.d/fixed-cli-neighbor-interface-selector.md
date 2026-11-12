### Fixed

- `rbgp neighbor` now accepts an unnumbered peer's interface name, so
  `rbgp neighbor swp1 delete|reset|disable|enable` reaches the daemon as the
  [documented](../docs/reference/operations.md) interface-only selector
  (empty address plus `interface`). Before, the argument parser accepted only
  an IP or scoped link-local address, so an unbound interface-only neighbor
  could not be deleted or acted on from the CLI.
  **Operator-visible:** a token that is, or is one typo away from, a
  `neighbor` command word, such as `lst` or `list`, is still a usage error
  (exit 64), and its message explains how to select an unnumbered peer.
