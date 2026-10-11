### Fixed

- EVPN Ethernet Segments now hold every DF algorithm in non-DF state during
  the initial three-second wait after startup, live addition, or undrain.
  During boot, election also waits for EVPN End-of-RIB and GR selection
  release, bounded by 30 seconds. Desired BUM suppression and bound
  single-active AC blocking are published before route origination can wait
  for a reply; enabled Linux enforcement applies these asynchronously to
  configured, resolvable ports.
  Ordinary segments advertise their Type 4/EAD-per-ES candidate routes
  during the wait; Don't-Preempt recovery keeps its publication delay.
  The existing `df_recovery_pending` and `df_recovery_remaining_ms` fields
  now expose the wait for all algorithms. Kernel defaults before daemon
  startup are unchanged.
