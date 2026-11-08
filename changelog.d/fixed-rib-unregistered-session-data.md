### Fixed

- Discard and count RIB route messages from sessions that never registered,
  protecting retained Graceful Restart routes from late announcements or
  withdrawals. Deferred session registration continues to accept ingress.
