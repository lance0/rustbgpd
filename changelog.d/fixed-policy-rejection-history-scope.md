### Fixed

- Export-policy reloads refresh each member's retained policy-rejection
  history from the smaller of the reload scope and that history, instead of
  probing every table prefix once per member. A dirty resync now revisits
  prefixes with retained rejection history, so a denied route withdrawn while
  its target's resync waited on a full channel, or while its send failed,
  emits a new `PolicyFiltered` event when it is denied again. A prefix with
  one retained denial no longer allocates a set.
- Clean incremental distribution again runs synchronously and opens a RIB
  readiness owner only for members with replay or policy-rejection work.
  Readiness queries served during clean ingest are recorded under the
  `actor_loop` seam of `bgp_rib_readiness_query_wait_seconds` again, rather
  than `policy_transition_fence`.
