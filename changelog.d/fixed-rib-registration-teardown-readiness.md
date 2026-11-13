### Fixed

- The RIB now answers readiness probes during two more actor turns that
  could walk a whole table without serving them: a session registration
  that is the first member of its update group, which builds the group
  table from the whole Loc-RIB before the initial table is sent, and a
  session teardown or reconnect that releases the member's EVPN recovery
  ledger. **Operator-visible:** the readiness endpoint stays answered
  through these turns; the turns themselves are not shorter, and routes and
  wire output are unchanged.
