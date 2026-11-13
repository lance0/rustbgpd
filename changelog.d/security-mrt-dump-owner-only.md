### Security

- MRT dump files are now created 0600 and a missing `[mrt] output_dir` is
  created 0700, instead of following the process umask (0644 and 0755 under
  umask 022). Dumps carry routes, peer addresses, ASNs and router IDs. An
  existing `output_dir` and the directories above it are now held to the
  `runtime_state_dir` ownership and mode rules before each dump. See
  [`[mrt]`](../docs/reference/configuration.md#output-files).
