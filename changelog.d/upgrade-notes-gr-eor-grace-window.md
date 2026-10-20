### Upgrade notes

- `gr_eor_grace_time` is off by default, so a planned restart sends End-of-RIB
  exactly as before. When enabling it, keep the window a few seconds above
  the controller's measured replay time and well below the upstream helper's
  own stale-route limit (FRR 10.7.1 defaults to 360 s, Junos documents 300 s),
  which `--check` cannot see. While End-of-RIB is held, stale routes the
  restarted daemon cannot withdraw (for example a ban lifted during the
  outage) also stay at the upstream until release.
