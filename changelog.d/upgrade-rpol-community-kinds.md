### Upgrade notes

- **`.rpol` community-set probes and removals are per kind.** A policy that
  probes a set mixing kinds with `route.communities in S` (or the large or
  extended list), or removes from it with `remove community in S` or
  `remove community not in S` (or the large or extended form), no longer
  loads; the error names the member of the other kind.
  - A probe that should match every kind becomes `route.any-community in S`.
  - A removal keeps its behaviour when the set is split by kind and each
    removal keeps its kind and its `in` or `not in` over its own part.
    `remove any-community in S` also replaces an `in` removal that should
    take the listed values of every kind; there is no `not in` form,
    because a `not in` allow-list is per kind and `any-community` would
    remove the allowed values instead.

  Datasets and set parameters filter by kind at runtime instead:
  `route.large-communities in D` used to ignore its field and match a route
  whose standard communities were in `D`; it now reads only large
  communities.
- **`.rpol` ASNs and communities are typed values.** These forms no longer
  load:
  - arithmetic on `route.origin-as`, `peer.asn`, an AS-path or asn-set loop
    variable or a `let` of one (`route.origin-as + 0 == 64500`,
    `route.origin-as % 2`), or one of them passed to a builtin or function;
  - two ASNs ordered against each other (`>=`, `<=`), or an ASN compared
    with a runtime u32 value (`let m = route.med; if route.origin-as >= m`);
  - an ASN or community probing a set of the other kind, any u32 probing a
    community-set (a `u32` parameter, or `let x = 4259840001; if x in tags`),
    and a runtime u32 probing an asn-set;
  - an ASN in `add`/`remove community`;
  - a community compared with an integer or u32 parameter
    (`c == 4259840001`), ordered with `>=`/`<=`, or set with `set med` or
    `set local-pref`;
  - a community literal in arithmetic, compared with an ASN, probing an
    asn-set or returned by a function (`set med 65000:1 + 1`,
    `if a == 0:64500`).

  Compare an ASN directly (`route.origin-as == 64500`, or `>=`/`<=` against
  a constant for a range) and probe an asn-set; write a community as a
  literal (`c == 65000:1`, `let x = 65000:1`) or declare its parameter
  `community` instead of `u32`.
