### Changed

- **Breaking:** `.rpol` sets of every kind share one namespace, as datasets
  already did. A prefix-set, community-set and asn-set can no longer share a
  name; the collision is a compile error naming both definitions. Before,
  `x in shared` with an asn-set and a community-set both named `shared`
  probed the asn-set, so `for c in route.communities { if c in shared { reject } }`
  let a route carrying the community pass and rejected one carrying its
  digits as an ASN.
