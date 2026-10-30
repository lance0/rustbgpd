### Upgrade notes

- `.rpol` `remove community *` now keeps standard communities in the RFC 1997
  well-known range, `65535:0` through `65535:65535`: `NO_EXPORT`,
  `NO_ADVERTISE`, `NO_EXPORT_SUBCONFED`, `NOPEER`, `BLACKHOLE`,
  `GRACEFUL_SHUTDOWN` and the rest. Previously it removed them, so the replace
  idiom `remove community *; add community X` dropped `NO_EXPORT` and could
  advertise a route beyond the scope its sender set. IOS-XR RPL `delete
  community all` also keeps well-known communities. A policy that relied on
  the scrub to remove a well-known value must now name it, for example
  `remove community BLACKHOLE`; `for c in route.communities { remove
  community c }` still removes every value. The `removes community *` test
  assertion now checks only the values outside that range. `remove
  large-community *:*:*` and `remove ext-community *` are unchanged.
  [Actions](../docs/reference/rpol-language.md#actions) has the details.
