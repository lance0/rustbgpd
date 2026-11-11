### Fixed

- An export-policy reload that moves many EVPN peers no longer resyncs all of
  them in one RIB turn. Each peer carrying EVPN outbound state is applied by
  its own RIB command, so UPDATEs from other peers, operator queries and
  timers run between them instead of waiting for the whole cohort.
  Unicast cohorts are unchanged. The reload still replies once every peer is
  applied and enqueued, and a failure part-way restores every peer's prior
  policy. The `authoritative_batch_phase` log adds `deferred_members`, and its
  `fallback_members` no longer counts those peers.
