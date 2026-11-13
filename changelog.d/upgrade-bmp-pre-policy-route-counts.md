### Upgrade notes

- BMP collectors no longer receive Stats Report type 7 from every
  established peer. It is now omitted for sessions that negotiate any family
  other than IPv4/IPv6 unicast, negotiate unicast Add-Path receive, run with
  `[policy.reject_retention] enabled = false`, or, since the session reset,
  have evicted a retained rejection or had max-prefix `Block` withhold an
  announcement.
  Where it is still sent, its value is the pre-policy route count and can
  exceed the post-policy count. Dashboards that read type 7 as the
  accepted-route count can read RFC 9972 type 20 (total) or type 21 (per
  family) on unicast-only sessions without unicast Add-Path receive. Type 20
  does not replace it elsewhere: it covers IPv4/IPv6 unicast only, while the
  old type 7 summed every family, and Add-Path receive omits types 20 and 21.
  For those sessions, read the per-peer accepted count from the API
  (`NeighborState.prefixes_received` from `GetNeighborState`) or the
  `Prefixes Received` line of `rbgp neighbor <addr>`.
