### Fixed

- The systemd watchdog no longer aborts a daemon whose RIB is busy but
  answering. Before, the watchdog ping was withheld whenever `/readyz` would
  fail, including when the RIB reported a policy transition,
  selection-deferral release or peer teardown as "stalled" after 30 seconds.
  One such unit of work lasting about three to five minutes ended in SIGABRT
  from systemd, every BGP session dropped, and the same work ran again after
  the restart. Now the ping is withheld only when the PeerManager or the RIB
  gives no answer at all (no reply within 5 seconds, a closed channel or a
  dropped reply); `/readyz` is unchanged and still returns `503` for a
  stalled answer. **Operator-visible:** the daemon samples liveness every
  10 seconds, from its own thread, and pings after each good sample, so
  under the shipped `WatchdogSec=5min` the abort comes about five minutes
  (285 to 305 seconds) after an actor stops answering; it was 2.5 to
  5 minutes, documented as five. A RIB that keeps answering "stalled" is
  never aborted, however long its work runs; the new `BgpReadinessRibStalled`
  alert rule covers that case. The new counter
  `bgp_systemd_watchdog_pings_skipped_total` counts each sample that withheld
  the ping and each ping the notify socket refused, and the new
  `BgpSystemdWatchdogPingsSkipped` rule alerts on it. Both shipped native units now set
  `TimeoutAbortSec=2min`, so a watchdog abort waits at most two minutes for
  the core dump instead of the 32-minute stop timeout; reinstall the unit to
  pick it up. The [Kubernetes liveness recipe](../docs/how-to/deployment.md#kubernetes-probes)
  now uses `/livez` for the startup and liveness probes: pointing either at
  `/readyz` restarts a pod for the same stalled answer.
