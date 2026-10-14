### Fixed

- `[evpn_core_isolation]` now excludes an uplink stacked on a bound interface,
  such as a VLAN on the bound bond, from the uplink signal. The hold's own
  admin-down took carrier from such an uplink, so when it was the only uplink
  with carrier the PE read itself as isolated and the hold never released.
  The daemon follows each uplink's kernel lower device (`IFLA_LINK`); see
  [the configuration reference](../docs/reference/configuration.md#evpn_core_isolation).
  **Operator-visible:** such an uplink is logged as an error and the binding
  reports `uplink_overlap`, as an enslaved uplink already did.
