### Changed

- A neighbor snapshot admitted while a configuration transaction waits no
  longer holds that transaction until every session has answered. The peer
  manager captures its half of each row and queues every session's state
  query before it resumes; a separate task joins the replies. Reload
  completion therefore no longer waits for a `ListNeighbors`, gNMI neighbor
  or `TestPolicy` peer read that overlaps the RIB commit
  ([ADR-0132 amendment](../docs/adr/0132-operator-read-path.md#amendment-2026-10-10-reads-overlapping-reload-completion)).
