### Fixed

- Received FlowSpec rules from one UPDATE share one copy of its path
  attributes in the Adj-RIB-In, the Loc-RIB and RFC 9117 validation state.
  Each rule used to keep its own copy, so a single 65,535-byte UPDATE with
  about 6,500 rules and a large COMMUNITIES attribute could retain about
  400 MB. Rules that import policy modifies get one copy per distinct
  modification, and LLGR promotion keeps shared rules shared. The
  [configuration reference](../docs/reference/configuration.md#flowspec-rfc-8955)
  now recommends `max_prefixes_ipv4_flowspec` and
  `max_prefixes_ipv6_flowspec` for FlowSpec peers that are not fully trusted.
