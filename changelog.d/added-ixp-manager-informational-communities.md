### Added

- In IXP Manager mode, `rs-config-render` now adds IXP Manager v7.4's
  informational large communities to accepted routes, where its BIRD
  templates add them: `RS:1000:1` RPKI valid, `RS:1000:2` RPKI unknown,
  `RS:1000:3` RPKI not checked, `RS:1001:1` IRRDB valid and `RS:1001:2` IRRDB
  not checked. An RPKI-valid route skips the IRRDB prefix check, so it carries
  only `RS:1000:1`. The existing `ixp-manager-own-as-export-scrub` removes the
  tags toward members, as IXP Manager's export filter does.
  **Operator-visible:** looking-glass badges such as RPKI VALID and IRRDB
  VALID appear on accepted routes after cutover. Rendered client policies and
  candidate hashes change. Rejected routes still carry only the adapter's
  `RS:1101:*` reason; see the
  [IXP Manager cookbook](../docs/cookbook/ixp-manager-route-server.md#the-boundary).
