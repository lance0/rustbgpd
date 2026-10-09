### Added

- Conditional advertisement status and peer-group attachment (alpha, outside
  the v1 inventory). `rbgp policy conditional-advertisements` (alias
  `conditional`) and the new `PolicyService.ListConditionalAdvertisements` RPC
  (`sensitive_read` tier, 2 s deadline) list each installed definition with
  every condition prefix's observation, the applied gate (`pending`,
  `advertise`, or `suppress`), the settle timer and its remaining time, and
  the attached neighbors; `--json` prints the same fields.
  `[peer_groups.<name>] conditional_advertisements` attaches definitions to
  every static member that sets no list of its own, with the
  `export_policy_chain` override rule; dynamic neighbors do not inherit it.
  `SetPeerGroup` keeps the configured group value, and a SIGHUP reload that
  changes it runs on the generation route. See
  [configuration](../docs/reference/configuration.md#conditional-advertisements).
