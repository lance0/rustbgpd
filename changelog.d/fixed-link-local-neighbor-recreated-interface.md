### Fixed

- A static IPv6 link-local neighbor now reconnects after its interface is
  deleted and recreated under the same name. Each outbound connection attempt
  and each inbound match resolves the neighbor's `interface` to its current
  index instead of the index found when the configuration was loaded, a
  configured BFD session moves to the new index (on the link monitor's
  report, or within 5 seconds by interface name when the monitor is not
  running), and routes learned on the
  new session carry the new index as their next-hop scope. Previously the
  session kept dialing the deleted interface's index ("Network is
  unreachable") until a reload or restart. While no interface has the name,
  connection attempts fail and are retried; see
  [scoped neighbor identity](../docs/reference/configuration.md#scoped-neighbor-identity).
