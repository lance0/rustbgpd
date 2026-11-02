### Upgrade notes

- **`.rpol` community-set probes and removals are per kind.** A policy that
  probes a set mixing kinds with `route.communities in S` (or the large or
  extended list), or removes it with `remove community in S`, no longer
  loads; the error names the member of the other kind. Write
  `route.any-community in S` or `remove any-community in S` to keep matching
  every kind, or split the set by kind. A route that matched only because a
  standard member and a large community (or the reverse) shared digits no
  longer matches.
- **`.rpol` ASNs take no arithmetic, and values probe sets of their own
  kind.** A policy with arithmetic on `route.origin-as`, `peer.asn` or an
  AS-path loop variable (`route.origin-as + 0 == 64500`,
  `route.origin-as % 2`), an ASN passed to a function, an ASN or runtime u32
  probing a community-set, a community probing an asn-set, or an ASN in
  `add`/`remove community` no longer loads. Compare the ASN directly
  (`route.origin-as == 64500`, or `>=`/`<=` for a range), probe an asn-set,
  and declare a community parameter as `community` instead of `u32` where it
  probes a community-set.
