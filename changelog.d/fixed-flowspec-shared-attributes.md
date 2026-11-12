### Fixed

- Received FlowSpec rules from one UPDATE share one copy of its path
  attributes in the Adj-RIB-In, the Loc-RIB and RFC 9117 validation state,
  and equal FlowSpec attribute sets are shared across UPDATEs as in the
  other families. Each rule used to keep its own copy, so a single
  65,535-byte UPDATE with about 6,500 rules and a large COMMUNITIES
  attribute could retain about 400 MB. Rules that import policy modifies
  share one copy per distinct modification outcome, export policy that
  modifies FlowSpec rules shares one modified copy across the rules and
  neighbors of a distribution pass, and LLGR promotion and clearing keep
  shared rules shared. The
  [configuration reference](../docs/reference/configuration.md#flowspec-rfc-8955)
  now recommends `max_prefixes_ipv4_flowspec` and
  `max_prefixes_ipv6_flowspec` for FlowSpec peers that are not fully trusted.
- Import policy that produces more than eight distinct modification
  outcomes within one UPDATE no longer copies the attribute set for every
  further route that receives one of those outcomes, for any address
  family; routes with an equal outcome share one copy.
