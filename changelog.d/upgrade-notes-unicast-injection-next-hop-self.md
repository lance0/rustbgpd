### Upgrade notes

- `AddPath` with next hop `0.0.0.0` or `::` used to return
  `INVALID_ARGUMENT`; it now injects a next-hop-self route. A client that
  relied on that rejection to catch a missing next hop must validate the
  field itself. `DeletePath` of an absent route still returns `NOT_FOUND`
  unless the new `allow_missing` is set, and a daemon that predates these
  fields leaves `outcome` unset (`UNSPECIFIED`).
