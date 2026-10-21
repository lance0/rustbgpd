### Documentation

- Clarify that IPv6 unicast over IPv4 eBGP without `local_ipv6_nexthop`
  remains a valid configuration with an export-suppression warning. Plain
  `--check` succeeds with that warning; `--check --strict` fails. Document
  how to validate fixtures that intentionally exercise the suppression.
