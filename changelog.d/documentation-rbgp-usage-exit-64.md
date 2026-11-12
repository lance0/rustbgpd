### Documentation

- The operations reference for `policy chain set` without a scope and
  `gshut` without `--all` or `--neighbor`, and the API reference for
  malformed `rpki aspa` and `rpki verify-path` input, now give the actual
  `rbgp` usage-error exit status, 64 (`EX_USAGE`), instead of 2. The daemon's
  own invocation errors, such as `rustbgpd --strict` without `--check`, still
  exit 2.
