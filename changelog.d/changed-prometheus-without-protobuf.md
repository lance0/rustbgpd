### Changed

- The daemon no longer builds the `protobuf` crate or `thiserror` 1.x. The
  `prometheus` dependency's unused protobuf exposition feature is off;
  `/metrics` and the gRPC metrics output are the same text format as before.
  Five unused dependency declarations were also removed.
