### Fixed

- Canonical config persistence omits default-valued optional sections while
  retaining configured values and explicit safety defaults. Routine runtime
  changes no longer add unused feature tables such as `[flowspec]`; downgrade
  compatibility still depends on the features, receiving-release defaults and
  field spellings in use.
