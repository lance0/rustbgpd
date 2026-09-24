### Fixed

- The general FIB crash-recovery file `fib-owned.json` is now written
  before a reconcile pass sends installs or replacements to the kernel, and
  every write fsyncs the file and its directory and removes its temporary
  file on failure. Previously it was written once after the whole pass,
  without fsync, and a failed write only logged a warning, so a crash, full
  disk or host failure could leave rustbgpd-installed rows reported as
  `foreign_route_exists` after restart, with manual `ip route del` as the
  only cleanup.
  **Operator-visible:** a failed write now increments the new counter
  `bgp_fib_owned_state_persist_failures_total` and holds route installs and
  replacements with status `failed` / `owned_state_persist_failed:*` until a
  later pass writes the file; removals continue. A runtime FIB table change
  whose owned-state cannot be written is reverted and reported as a
  compensation failure instead of applied. The file keeps its format
  version; an older build ignores the new optional `in_flight` field.
