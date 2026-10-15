### Fixed

- Full outbound replays now service dedicated readiness probes while retiring
  temporary exact-encoding results and prior advertised-route keys. Existing
  stalled-operation bounds and ordinary-query/mutation fencing are preserved.
