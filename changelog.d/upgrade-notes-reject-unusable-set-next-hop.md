### Upgrade notes

- A config that previously loaded can now fail to load if a policy sets the
  next hop to `0.0.0.0`, `::`, or a multicast address; a SIGHUP reload or API
  policy edit with one is refused and the running config is kept. Use
  `set_next_hop = "self"` or a reachable unicast address instead.
