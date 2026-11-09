### Upgrade notes

- gRPC event consumers that read a string `timestamp` must read
  `timestamp_unix_ms` (Unix epoch milliseconds) instead; whole seconds are
  `timestamp_unix_ms / 1000`. A client built against an older
  `rustbgpd.proto` that still reads `timestamp` now gets an empty string.
  This removal is a named pre-v1 waiver of the two-minor / 90-day
  deprecation floor. It covers all eight string `timestamp` fields: the two
  on `BgpEvent` and `RouteEvent`, deprecated in 0.79.0, and the six on
  `SessionEvent`, `NotificationEvent`, `PolicyEvent`, `DataplaneRouteEvent`,
  `EvpnRouteEvent` and `BfdSessionEvent`, which were never deprecated. The
  general floor is unchanged.
