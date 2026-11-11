### Changed

- The Adj-RIB-In stores VPNv4/VPNv6 and labeled-unicast routes the way it
  stores unicast routes: route bodies in dense slots behind 4-byte handles,
  with each key's Add-Path index holding the handles. When an UPDATE replaces
  or withdraws a key's selected path, selecting a new one reads the key's
  stored paths by handle instead of looking each one up in a hash table.
  Stored routes and selection results are unchanged.
