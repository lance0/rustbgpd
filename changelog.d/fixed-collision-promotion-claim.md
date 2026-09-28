### Fixed

- Collision resolution no longer retires the configured session for an
  inbound candidate that fell to Idle after the manager's last check, for
  example when its 10 s verdict wait expired just before promotion. The
  manager now asks the candidate to confirm promotion first and keeps the
  current session if it does not. A confirmed candidate whose activation is
  then lost is released after the same 10 s instead of being closed.
  **Operator-visible:** a narrow simultaneous-open race no longer costs one
  extra reconnect.
