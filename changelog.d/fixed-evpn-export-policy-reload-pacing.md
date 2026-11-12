### Fixed

- An export-policy reload that moves many EVPN peers no longer resyncs all of
  them in one RIB turn. Peers whose sessions send EVPN are applied a few per
  RIB command, as many as fit a 250 ms turn budget, so UPDATEs from other
  peers, operator queries and timers run between those commands instead of
  waiting for the whole cohort.
  Unicast cohorts are unchanged. The reload still replies once every peer is
  applied and enqueued, and a failure part-way restores every peer's prior
  policy. The `authoritative_batch_phase` log adds `deferred_members`, its
  `fallback_members` no longer counts those peers, and a batch that hands
  peers back with none on the per-member path is classified `paced`; each
  paced command logs as `paced_apply`, with `applied_members` the members it
  applied, `deferred_members` those left for the next command and
  `fallback_members` 0.
