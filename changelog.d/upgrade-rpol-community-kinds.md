### Upgrade notes

- **`.rpol` community-set probes and removals are per kind.** A policy that
  probes a set mixing kinds with `route.communities in S` (or the large or
  extended list), or removes it with `remove community in S`, no longer
  loads; the error names the member of the other kind. Write
  `route.any-community in S` or `remove any-community in S` to keep matching
  every kind, or split the set by kind. A route that matched only because a
  standard member and a large community (or the reverse) shared digits no
  longer matches.
