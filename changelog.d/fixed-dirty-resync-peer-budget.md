### Fixed

- Check the dirty-route recovery work budget after each complete peer replay,
  keeping forced retries inside the same peer selection. Large peer backlogs
  return to the actor between replays instead of accumulating one readiness
  ownership window across several full tables. The existing stalled-operation
  deadline still applies to an individual replay and any enclosing transition.
  **Operator-visible:** healthy full-table recovery can continue answering
  readiness probes without reporting a stalled export-policy transition solely
  because earlier peer replays consumed the same timer tick.
