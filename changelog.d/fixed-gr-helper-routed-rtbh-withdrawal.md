### Fixed

- A Graceful Restart helper that flaps while our End-of-RIB toward it is held
  no longer keeps a deleted RTBH, such as a BLACKHOLE aggregate its owner
  still announces, until that End-of-RIB just because the prefix has another
  route. rustbgpd now withdraws it inside the hold unless the ended session
  also had an ordinary route at that key, before or after the RTBH, or the
  receiver changed update group during the hold: only then can the helper's
  stale row at the key be the ordinary route, which it rightly keeps. An RTBH whose ordinary
  replacement at the same key never reached the helper still stays until
  End-of-RIB; [known issues](../docs/reference/known-issues.md) has the
  details.
