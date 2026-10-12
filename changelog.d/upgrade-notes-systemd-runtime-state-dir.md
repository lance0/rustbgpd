### Upgrade notes

- The shipped `rustbgpd.service` now starts the daemon with
  `--runtime-state-dir /var/lib/rustbgpd` and runs
  `rustbgpd --release-core-isolation --runtime-state-dir /var/lib/rustbgpd` as
  `ExecStopPost=`. The daemon refuses to start when `--runtime-state-dir`
  differs from the config's `runtime_state_dir`, so a deployment that sets a
  different `runtime_state_dir` must change both unit lines to match before
  restarting. With no core-isolation receipt the stop hook exits 0 without
  touching any link. Supervisors without a stop hook should run the same
  command after the daemon exits when `[evpn_core_isolation]` is enabled. See
  the [systemd notes](../docs/how-to/deployment.md#systemd).
