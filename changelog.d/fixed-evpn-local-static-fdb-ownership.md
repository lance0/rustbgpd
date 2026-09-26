### Fixed

- Preserve unmarked static and permanent FDB rows on local bridge ports when
  a remote EVPN route names the same MAC. Include those rows in ownership
  preflight so they cannot be overwritten or force unrelated MACs out of
  their nexthop group. Dynamic local MAC moves remain unchanged.
