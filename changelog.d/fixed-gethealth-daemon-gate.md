### Fixed

- `ControlService.GetHealth`, `rbgp health` and `rbgp doctor` now follow the
  daemon gate that HTTP `/readyz` already used. During coordinated shutdown
  or the runtime-config settlement recovery fence they no longer report a
  healthy daemon while `/readyz` returns 503: `GetHealth` returns
  `UNAVAILABLE` with a `google.rpc.ErrorInfo` reason of `DAEMON_SHUTTING_DOWN`
  or `RUNTIME_CONFIG_RECOVERY_FENCE` (see the
  [API reference](../docs/reference/api.md#health-check)).
  **Operator-visible:** `rbgp health` prints `daemon not ready (<reason>)`
  and exits non-zero, and doctor's `daemon.healthy` is red at once without
  its one-second retry. `CheckLiveness`, `/livez` and the systemd watchdog
  still ignore the gate.
