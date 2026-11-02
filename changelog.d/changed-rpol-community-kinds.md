### Changed

- **Breaking:** an `.rpol` community-set probe reads only the kind of its
  field. `route.communities in S` matches standard communities against the
  set's standard members, and `route.large-communities` /
  `route.ext-communities` likewise; before, `route.large-communities in tags`
  with `tags { 65000:1 }` matched a route carrying the standard community
  65000:1. A named set member of another kind is now a compile error for that
  probe, and for `remove <kind> in S` / `not in S`. Sets that mix kinds, such
  as the standard and large twins of a route-server action community, use
  the new kind-agnostic forms `route.any-community in S` and
  `remove any-community in S`. Datasets and set parameters filter by kind at
  runtime. Each probe still makes one pass over the route's communities of
  its kind. Policy explain output renders a kind-agnostic probe of a set that
  mixes kinds, including a TOML community list that mixes kinds, as
  `route.any-community in S` instead of `route.communities in S`.
- **Breaking:** `.rpol` values carry a type. `route.origin-as`, `peer.asn`
  and loop variables over `route.as-path` or an asn-set are ASNs: they
  compare with `==`, `!=`, `>=` and `<=` against an integer literal or u32
  parameter, so `route.origin-as >= 64512 && route.origin-as <= 65534` checks
  a private range, compare with another ASN by `==`/`!=`, probe asn-sets and
  can be set as a whole value, but take no arithmetic. A standard community
  literal such as `65000:1`, a `community` parameter and a loop variable over
  `route.communities` are communities: they compare with another community
  by `==`/`!=`, probe community-sets whose members are standard and are added
  or removed, but take no arithmetic, probe no asn-set and never equal an
  ASN or an integer. A `let` takes its initializer's type. Before,
  `for a in route.as-path { if a in tags ... }` matched ASN 64500 against the
  community 0:64500, and so did `if a == 0:64500`.
