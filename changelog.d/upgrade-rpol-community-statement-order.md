### Upgrade notes

- `.rpol` policies that add a community and later remove it, or the reverse,
  in the same term change outcome: the later statement now wins. A scan run
  after additions, in the same policy or in a later chain member, now cancels
  the additions it selects: a strip-all form cancels every earlier addition of
  its kind except well-known standard communities, which `remove community *`
  keeps, and `remove … in` / `not in` cancels only the additions its set
  selects. Move an addition after the scan to keep it. For example, a chain
  whose first member adds `65000:1` and whose second member runs
  `remove community *; add community 65000:100` now ends with only
  `65000:100` and the well-known communities, as IOS-XR RPL
  `set community` does. Run `rbgp policy check` on the policy files:
  in-language tests that pinned the old outcome fail.
