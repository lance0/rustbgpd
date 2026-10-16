### Changed

- A SIGHUP dataset content swap now re-evaluates only the export routes
  whose prefix or origin AS the old and new contents answer differently,
  instead of every route of every referencing receiver. This applies when
  each receiver probes the dataset only with `route.prefix in` or
  `route.origin-as in` and sends only IPv4/IPv6 unicast; community,
  peer-ASN and binding probes, VPN and other families, conditional
  advertisement, compensation and the legacy dataset refresh keep the full
  re-evaluation. A new `dataset export re-evaluation complete` log event
  reports `mode` (`delta` or `full`), `affected_prefixes` and `elapsed_ms`.
  See [Datasets](../docs/reference/rpol-language.md#refresh-failure-and-observability).
