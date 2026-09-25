### Changed

- `GetPolicyStats` (`rbgp policy stats`) reads peer validation, import
  counters and dataset status from a roster the peer manager publishes,
  instead of queueing on the peer manager's operator lane. A fleet import read
  no longer waits for peer-manager admission or yields to the scheduler per
  peer and term; it waits only for a session publication that is still
  Pending or a busy counter or dataset error lock, under the same 2 s
  deadline. The roster reflects the peer manager's last completed operation,
  so a fleet read during a reload that replaces or removes peers can return
  `UNAVAILABLE` for a session that has already exited. Success no longer
  shows that the peer manager is responsive, and a read that sees, after its
  capture, that the peer manager has stopped returns `UNAVAILABLE`.
  **Operator-visible:** the import entry of the `grpc_authz`
  `request_summary` audit record drops `admission_ms`, `collection_ms` and
  `admission=pending` along with the wait they measured; it keeps
  `publications=read/selected`, and `yields` now counts only the import
  capture's waits: Pending publications and busy counter error-lock retries. See the [policy stats reference](../docs/reference/api.md) and
  [ADR-0136](../docs/adr/0136-owner-published-counter-reads.md).
