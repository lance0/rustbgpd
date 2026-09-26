### Changed

- `GetPolicyStats` (`rbgp policy stats`) reads export counters from a roster
  the RIB manager publishes, instead of queueing on the RIB's summary or
  query lane. An export or `both` read no longer waits behind RIB work, a
  synchronous policy replacement, or the commit batches of a grouped policy
  transition; it reports the live counters of the chains installed by the
  RIB's last completed operation, and a grouped transition switches its whole
  cohort at its final commit. Success no longer shows that the RIB manager is
  making progress, and a read that sees, after its capture, that the RIB
  manager has stopped returns `UNAVAILABLE`. Export rows now report the
  counter-instance id in `policy_generation` instead of 0: nonzero, shared by
  update-group members that share counters, and new whenever the counters
  restart. `rbgp policy stats` prints it, as `policy_generation` in JSON
  (previously `null` for export rows) and as `(counter instance N)` in text.
  The `export` entry of the `grpc_authz` `request_summary` audit record is
  unchanged. See the [policy stats reference](../docs/reference/api.md) and
  [ADR-0136](../docs/adr/0136-owner-published-counter-reads.md).
