### Fixed

- A route that import policy had rejected and later accepts now leaves the
  rejected-route store even when the max-prefix `block` action withholds the
  accepted announcement. Before, the stale policy rejection stayed listed in
  `rbgp rib received PEER --rejected` and counted in the RFC 9972 BMP
  policy-rejection statistic (type 22). Max-prefix accounting is unchanged.
