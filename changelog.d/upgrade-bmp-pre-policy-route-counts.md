### Upgrade notes

- BMP collectors no longer receive Stats Report type 7 from every
  established peer. It is now omitted for sessions that negotiate any family
  other than IPv4/IPv6 unicast, negotiate unicast Add-Path receive, run with
  `[policy.reject_retention] enabled = false`, or have evicted a retained
  rejection or had max-prefix `Block` withhold an announcement since the
  session reset. Where it is still sent, its value is the pre-policy route
  count and can exceed the post-policy count. Dashboards that read type 7 as
  the accepted-route count should read RFC 9972 type 20 (total) or type 21
  (per family) instead.
