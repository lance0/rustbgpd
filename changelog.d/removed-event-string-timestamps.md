### Removed

- Event messages no longer carry the decimal-string Unix-seconds `timestamp`
  field. Every event now reports its time only as `int64 timestamp_unix_ms`:
  `BgpEvent` and `RouteEvent` already did, and `SessionEvent`,
  `NotificationEvent`, `PolicyEvent`, `DataplaneRouteEvent`,
  `EvpnRouteEvent` and `BfdSessionEvent` gain it in this release. The removed
  fields' numbers and names are reserved. This affects `WatchEvents`,
  `ListRouteEvents`, `ListSessionEvents`, `ListPolicyEvents` and
  `ListEvpnEvents`. `rbgp events` JSON keeps its `timestamp` and
  `timestamp_unix_seconds` keys, now derived from the millisecond time, and
  the MCP event tools keep their `timestamp` string. See the
  [API reference](../docs/reference/api.md#eventservice).
