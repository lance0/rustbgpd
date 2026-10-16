### Added

- Policy tests support `removes large-community GA:*:*`, `not removed`
  community assertions, and `with only` to require an exact modification
  set. The IXP Manager renderer tests pin the wildcard export scrub and
  retention of other ASNs' communities. RT/RO removal checks follow their
  decoded identity across encodings.
