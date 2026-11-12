### Fixed

- An export-policy reload whose cohort falls back to the authoritative batch
  no longer resyncs its non-EVPN residual peers in one RIB turn. VPN-,
  labeled-, FlowSpec- and BGP-LS-only peers, ungrouped and per-client-best
  peers, mixed-family peers and peers of a group that moves to several
  destinations are now applied a few per RIB command within the same 250 ms
  turn budget as EVPN peers, so UPDATEs from other peers, operator queries and
  timers run between those commands. Shared unicast cohorts are unchanged.
  **Operator-visible:** for such reloads the `authoritative_batch_phase` log
  now counts those peers in `deferred_members` instead of `fallback_members`,
  classifies the batch `paced`, and logs each paced command as `paced_apply`.
