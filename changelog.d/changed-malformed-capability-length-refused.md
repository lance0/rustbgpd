### Changed

- An OPEN whose Add-Path, Multiprotocol, Graceful Restart, Long-Lived
  Graceful Restart, Extended Next Hop or Paths-Limit capability value is not
  a whole number of its tuples (for example an Add-Path length of 3), or
  whose Four-Octet AS capability is not 4 octets, is now refused with OPEN
  Message Error / Unspecific (2/0), as RFC 4271 §6.2 prescribes. Before, the
  capability was ignored, so an Add-Path peer could send path IDs that were
  read as prefixes, and a Four-Octet AS peer's `AS_PATH` was parsed as
  two-octet. See
  [RFC notes](../docs/reference/rfc-notes.md).
