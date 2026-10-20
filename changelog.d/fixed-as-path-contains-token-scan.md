### Fixed

- `.rpol` `route.as-path contains N`, and any single-ASN `_N_` AS_PATH
  pattern in TOML policy, is now matched by a token scan instead of a
  compiled regex. Each distinct ASN previously compiled its own regex, so
  a policy naming many ASNs could take gigabytes and tens of seconds to
  load (100,000 distinct values: about 3.6 GiB and 23 s in
  `rustbgpd --check`, now about 300 MiB and under a second). Match results
  are unchanged.
