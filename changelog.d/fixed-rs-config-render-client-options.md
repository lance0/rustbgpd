### Fixed

- In arouteserver mode, `rs-config-render` no longer drops per-client options
  without a word. A client `password` now renders as the neighbor's
  `md5_password`, an effective `roles.strict_mode: true` renders
  `strict_role = true`, and per-client `irrdb.enforce_origin_in_as_set` and
  `enforce_prefix_in_as_set` apply to that client only. A client value of
  `ipv4_pref_len`, `ipv6_pref_len`, `reject_invalid_as_in_as_path`, or
  `rpki_bgp_origin_validation.reject_invalid` that differs from the general
  one, `graceful_shutdown.enabled: false`, `prepend_rs_as`, a `local_role`
  other than `rs`, `custom_options`, and `16bit_mapped_asn` while control
  communities are on are refused with exit 2 naming the client and key.
  An unknown key in a client's `cfg` or `filtering` map now fails the parse
  with exit 1. See the
  [renderer README](../tools/rs-config-render/README.md).
  **Operator-visible:** an MD5 member previously never established, and a
  strict-role or stricter per-client filter setting was silently relaxed; a
  site that relied on any refused override now gets exit 2 until it is
  removed. `roles.enabled: false` remains a documented divergence: rendered
  sessions still advertise the route-server Role.
