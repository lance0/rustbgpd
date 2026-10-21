### Fixed

- `rs-config-render activate`, `status` and `recover rollback` now bound
  reading an `--rbgp` or strict-checker child's output by the same settle or
  probe deadline as the child itself. A wrapper that exited while a
  background process kept its stdout or stderr open used to hold the tool
  until that process exited; the cut-off read now counts as an invalid probe
  (refused, `recovery_required` or `daemon: invalid`), never as success.
