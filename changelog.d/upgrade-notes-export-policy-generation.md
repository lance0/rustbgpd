### Upgrade notes

- Consumers that compare `GetPolicyStats` export `policy_generation` values
  (or `rbgp --json policy stats` export `policy_generation`, previously
  `null`) now receive a nonzero counter-instance id instead of 0. It changes
  whenever the export counters restart: at each session registration of a
  peer that is not in an update group, at a policy replacement that installs
  a new chain, and when a peer moves to another update group. Compare it
  only for equality; the values are process-wide and not per-peer sequences.
