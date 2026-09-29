### Added

- The IXP reload-stall matrix runs the native rustbgpd daemon in its own
  systemd user scope with swap fenced (`MemorySwapMax=0`), records the
  scope's `memory.peak` as `cg_peak` and its `memory.current` at each RSS
  sample, and the headline summarizer reports both. The rrharness A/B driver
  runs each leg the same way and appends `cg_peak_mib` and
  `cg_settled_current_mib` to `results.csv`; earlier receipts without these
  fields stay valid.
