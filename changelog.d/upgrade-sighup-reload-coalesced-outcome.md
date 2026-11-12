### Upgrade notes

- `bgp_sighup_reload_outcomes_total` replaces the `ignored_in_flight`
  outcome with `coalesced`, counted once per SIGHUP received while
  another reload runs; the follow-up reload that serves it records its
  own outcome separately. Dashboards, alerts and harnesses that select
  `ignored_in_flight` must switch to `coalesced`. A coalesced signal no
  longer publishes an interim `GetLastSighupReload` record with outcome
  `ignored_in_flight`; the record only ever holds a settled reload.
