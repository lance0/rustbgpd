### Changed

- Cache attribute-derived best-path inputs on each shared attribute set, avoiding
  repeated scans during route comparison. Selection rules are unchanged; each
  unique attribute set carries 24 additional bytes of cached inputs.
