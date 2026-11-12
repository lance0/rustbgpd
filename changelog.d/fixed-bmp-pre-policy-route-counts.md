### Fixed

- BMP Stats Report type 7 ("routes in Adj-RIBs-In", the pre-policy table in
  RFC 7854) carried the post-policy accepted count summed across every
  family, with Add-Path paths collapsed to prefixes, so it duplicated type
  20 under a pre-policy label. It now carries the exact pre-policy count:
  accepted IPv4/IPv6-unicast routes plus retained rejections other than
  treat-as-withdraw. The same value is sent as RFC 9972 type 18, with type 19
  per negotiated IPv4/IPv6-unicast family. These statistics are sent only
  while rejected-route retention is enabled with no eviction or max-prefix
  `Block` withholding since the session reset and unicast Add-Path receive is
  off; types 7 and 18 also need a session with no other negotiated family.
  Otherwise they are omitted. See the
  [BMP statistics contract](../docs/reference/configuration.md#what-is-streamed).
