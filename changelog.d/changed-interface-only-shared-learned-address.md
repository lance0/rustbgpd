### Changed

- Interface-only neighbors on different interfaces may now learn the same
  link-local address, for example parallel links to one device that reuses
  its router MAC on every port. Previously every link after the first was
  refused with `duplicate_link_local_address`. While `[bmp]` collectors are
  configured, a learned address that another neighbor holds is still refused
  before the session starts, now with reason `bmp_identity_conflict`, and the
  neighbor admitted first keeps its session. See the
  [configuration reference](../docs/reference/configuration.md).
