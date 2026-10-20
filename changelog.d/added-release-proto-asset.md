### Added

- Each tagged release publishes the exact tagged `proto/rustbgpd.proto` as the
  `rustbgpd.proto` release asset, with a `rustbgpd.proto.sha256` checksum, so
  controllers can pin generated stubs to a daemon release instead of
  hand-vendoring the file. The
  [API reference](../docs/reference/api.md#pinning-the-proto-to-a-release) has
  the download, verify and regenerate recipe. Publishing the file promotes no
  alpha field into the v1 contract.
