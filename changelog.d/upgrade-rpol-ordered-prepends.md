### Upgrade notes

- **Prepends now add up.** A chain, or a policy, that prepends more than once
  on a path now places every prepend, where only the last used to take
  effect. A "default 1× prepend, then a per-peer 3× override" chain, with
  `prepend as 65000 1` in one member and
  `if peer.asn == 64500 { prepend as 65000 3 }` in the next, now prepends 4
  ASNs for AS 64500 instead of 3. Make the two exclusive in one policy so
  exactly one applies:
  `if peer.asn == 64500 { prepend as 65000 3 } else { prepend as 65000 1 }`.
  Two TOML policies with `set_as_path_prepend` in one chain add up the same
  way. A policy or chain whose prepends could exceed 255 ASNs, including any
  prepend inside a loop over `route.communities` or `route.as-path`, no longer
  loads; `rustbgpd --check` and `rbgp policy check` name it. In-language tests
  that pinned the replaced prepend with `with prepend as ASN COUNT` fail and
  need the whole sequence, for example `with prepend "65000 65000 65000 65000"`.
- **gRPC and `rbgp` JSON clients** reading `as_path_prepend_asn` and
  `as_path_prepend_count` from explain and test results read the
  `as_path_prepend` ASN list instead: `{asn: 65000, count: 2}` is now
  `[65000, 65000]`.
