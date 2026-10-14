### Fixed

- `/readyz` and `GetHealth` no longer report the peer manager as timed out
  while it waits on the RIB for a conditional-advertisement install or
  re-observation, a config-transaction plan's update-group snapshot, or a
  dampening capacity disable, explicit enable or dynamic-peer retirement
  barrier. Each of these acknowledgements queues behind the RIB's
  primary-lane work, which can take seconds after a large export change, and
  the peer manager stopped answering readiness probes for the whole wait. It
  now answers them throughout. Neighbor reads are also answered during the
  conditional-advertisement and update-group waits; they stay queued behind
  the dampening waits, whose peer state is mid-transition. The 200 ms
  deadline and the 5 s RIB reply bound are unchanged.
