### Changed

- The shipped route-server hygiene no longer carries an AS_SET reject term.
  `examples/route-server/hygiene.rpol`, and the `policy/rs-hygiene.rpol` and
  IXP Manager-mode `policy/ixp-hygiene.rpol` that `rs-config-render`
  generates, dropped `reject-as-set` and its in-language test. The daemon
  already treats an UPDATE whose AS_PATH or AS4_PATH carries an AS_SET or
  AS_CONFED_SET as withdrawn when it decodes it (RFC 9774), so no received
  route could match the term.
  **Operator-visible:** regenerated hygiene files lose that term and test.
  `rbgp policy explain` names no deciding term for an AS_SET announcement;
  `rbgp rib received <member> --rejected` lists it with reason
  `treat_as_withdraw`, and
  `bgp_update_malformed_causes_total{reason="as_set_prohibited"}` counts it.
  The [route-server cookbook](../docs/cookbook/route-server.md)
  troubleshooting text now says so.
