### Changed

- Cache attribute-derived unicast best-path inputs on each shared attribute set,
  avoiding repeated scans during unicast comparison. Selection rules are unchanged;
  each unique attribute set carries 24 additional bytes of cached inputs.
