### Fixed

- Receivers that stop reading while sources churn no longer hold an unbounded
  backlog of superseded route versions. Updates for a peer's private families
  (those it holds in its own Adj-RIB-Out, such as EVPN and ungrouped unicast)
  are admitted against a per-peer row credit sized from the number of
  registered peers; a peer that stays stalled past it, about 10 s of RIB work
  at 16–2,048 peers, is marked dirty and later resynchronizes from current
  state. A peer holds at most one whole-table update at a time (initial dump,
  refresh or replay answer, resync, complete EVPN feed); a refresh request
  that arrives meanwhile is answered once it has been sent. An operator
  replay is accepted for all its families and its terminal or refused with
  nothing sent. At shutdown, withdrawals no longer wait on spent credit, and
  shutdown waits at most 5 s to tell the RIB it has begun.
  Update-group members share one copy of the group's withdrawals.
  **Operator-visible:** a new `outbound_credit` reason on
  `bgp_outbound_commit_refusals_total`.
