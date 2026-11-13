### Changed

- A restart-required `[global]` edit is now named by field, with its old and
  new value, on every report: the SIGHUP `[global] changed` `ERROR` line has
  a `fields` value, `rustbgpd --diff` lists the fields under `[global]` and in
  a new JSON `global_changes` array, and a config transaction's
  `restart_required_sections` adds a `[global].<field>: <old> → <new>` entry
  after `[global]`. The diff and the SIGHUP log now use one comparator, so they
  agree on which fields count. Changing `router_id` is no longer
  indistinguishable from changing `telemetry.log_format`. See the
  [reload matrix](../docs/reference/reload-matrix.md#global).
  **Operator-visible:** the BLACKHOLE FIB discard knobs no longer also raise
  the `[global] changed` SIGHUP `ERROR` (their own `ERROR` still fires), and an
  `ebgp_requires_policy`-only edit no longer sets the diff's
  `restart_required.global_changed`; `ebgp_requires_policy_changed` still
  reports it as restart-required.
