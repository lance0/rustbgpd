### Fixed

- During graceful restart, export disposition and advertised-route explain
  can identify an ordinary local injection already admitted to a grouped
  neighbor, even after the group selects or withdraws a different route.
  Readback stays pending when the current export differs from the admitted
  row or the RIB could not retain proof. This also fixes a false `COMMITTED`
  for a grouped neighbor that had caught up after a missed update but had
  not yet received the route its group now holds.
