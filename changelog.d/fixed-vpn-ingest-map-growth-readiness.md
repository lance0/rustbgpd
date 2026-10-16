### Fixed

- Service readiness during VPN table growth by moving received, selected, and
  advertised routes through checkpointed map reservations. Growing updates retain
  exclusive RIB ownership while response tasks can run; this bounds readiness
  opportunities without promising a bound on whole-UPDATE completion time.
