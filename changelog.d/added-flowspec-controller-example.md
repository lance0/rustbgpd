### Added

- [`examples/flowspec-controller/`](../examples/flowspec-controller/config.toml)
  is a FlowSpec controller backend profile: border-router neighbors that carry
  only `ipv4_flowspec` / `ipv6_flowspec`, with rules injected over gRPC. From
  the first release that ships it, the v1 upgrade chain archives it beside the
  route-server and route-reflector examples, so a later release that stops
  accepting that configuration fails the archived-fixture parse test.
