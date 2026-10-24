### Changed

- Interface-only neighbors that learn the same link-local address on
  different interfaces may now use different GTSM (`ttl_security`) and
  `log_level` settings. Previously such a link was refused with
  `shared_address_feature`, so enabling GTSM on one of several parallel
  links to a device kept the others down. Each neighbor's GTSM selector
  matches its arrival interface as well as the address, and its log level
  matches its interface label. A static link-local neighbor at the same
  address must still agree with them. See the
  [configuration reference](../docs/reference/configuration.md#interface-only-neighbors).
