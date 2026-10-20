### Added

- The [v1 inventory](../docs/reference/v1-stable-contract.md) now pins
  `NeighborService.ResetNeighbor` and the everyday command paths:
  `rbgp neighbor add`, `delete`, `enable`, `disable`, `reset`, `refresh-in`
  and `refresh-out`; `rbgp peer-group list`, `get`, `set`, `delete`,
  `attach` and `detach`; `rbgp neighbor-set list`, `get`, `set` and
  `delete`; `rbgp dynamic-neighbor list`, `add` and `delete`; and
  `rbgp policy chain` with its `show`, `set-import`, `set-export`,
  `clear-import` and `clear-export` subcommands.
  **Operator-visible:** `rbgp neighbor <addr> softreset` is now
  `rbgp neighbor <addr> refresh-in`, pairing with `refresh-out` and
  `replay-out`; `softreset` remains accepted as an alias. Its `--json`
  result reports `"action": "refresh_inbound"` (previously `"softreset"`),
  matching `refresh_outbound` and `replay_outbound`.
- `RouteEvent` and `BgpEvent` carry a typed `int64 timestamp_unix_ms`. The
  decimal-string `timestamp` field is still populated but deprecated; new
  clients should read the typed field, which carries the event time at
  millisecond resolution, so it orders events within the same second.
