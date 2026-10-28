### Fixed

- Prevent debug daemon worker stack exhaustion during inbound session
  establishment by keeping owned policy-change state out of the command
  dispatcher.
