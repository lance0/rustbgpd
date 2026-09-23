### Documentation

- The operations reference's `grpc_authz` audit queries read `tier`,
  `result` and `principal` at the top level of each JSON log line, but the
  daemon nests event fields under `.fields`, so the operator-only, denial and
  per-principal queries matched nothing. They now read `.fields.*` and skip
  the plain-text startup banner that shares the unit's journal. The same page
  now describes current `RUST_LOG` handling (bad directives are dropped and
  reported, valid ones kept), the management-listener accept-backoff log lines,
  and the `rbgp top` terminal requirement.
- Reference corrections: the settlement-watchdog guide's ten-minute
  pre-ownership bound covers Confirm, Abort, Rollback and gNMI `Set` as well
  as Apply; the policy resolution order now covers RFC 8212 deny-all for eBGP;
  the reload matrix notes that an unedited canonical rewrite no longer pins the
  RFC 8212 posture; `ListBlackholeDiscards` lists the emitted `reason` values;
  `GetIpVrf` shows real not-ready lines; the Grafana guide says jemalloc is
  the default allocator; and a known-issues entry describing a FlowSpec AFI
  defect that does not exist was removed.
