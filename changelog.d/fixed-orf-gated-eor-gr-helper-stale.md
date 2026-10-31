### Fixed

- Hold an Address Prefix ORF family's initial End-of-RIB behind its gated
  table toward a peer whose previous session advertised Graceful Restart, so
  it does not delete the routes it kept stale from that session before the
  peer's ROUTE-REFRESH brings them back. Previously the End-of-RIB went out at
  once and the peer dropped every stale route of the family, RTBH routes
  included, until the filtered table arrived. A peer that sends no
  ROUTE-REFRESH within 60 seconds gets the End-of-RIB then. Peers whose
  previous session had no Graceful Restart capability keep the immediate
  End-of-RIB.
  **Operator-visible:** every End-of-RIB held for an ORF-gated table now has
  the same 60-second bound. A GR restarter's, and that of any ORF peer whose
  initial table falls inside a startup selection deferral, previously waited
  for the peer's ROUTE-REFRESH without limit; it now goes out after 60
  seconds without one, or when the selection deferral ends if that is later.
