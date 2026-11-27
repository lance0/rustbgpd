### Changed

- Paged initial tables for joiners of the same update group now share one
  set of admitted-key proof keys instead of holding one each. The keys and
  their index (about 38 bytes per route) are charged to the 512 MiB proof
  budget once per group table, and each joiner adds a mask of one bit per
  route plus the keys it admitted that the shared set lacks. The walk of
  the group table that fills the set also runs once, not once per joiner.
  **Operator-visible:** a mass join of one group no longer waits for proof
  budget below the 64-join limit, and `bgp_update_group_recovery_bytes` and
  its peak grow by the shared keys once rather than per joiner. Joiners of
  different groups still each need their own keys and can wait for budget.
  See the [RIB lifecycle reference](../docs/reference/rib-lifecycle.md).
