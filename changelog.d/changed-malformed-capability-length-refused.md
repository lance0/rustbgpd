### Changed

- An OPEN whose Add-Path, Multiprotocol, Graceful Restart, Long-Lived
  Graceful Restart, Extended Next Hop or Paths-Limit capability value is not
  a whole number of its tuples (for example an Add-Path length of 3) is now
  refused with OPEN Message Error / Unspecific (2/0), as RFC 4271 §6.2
  prescribes and FRR and BIRD do. Before, the capability was ignored, so an
  Add-Path peer could send path IDs that were read as prefixes. See
  [RFC notes](../docs/reference/rfc-notes.md).
