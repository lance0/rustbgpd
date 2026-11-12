### Security

- MRT dump files are now created 0600 and a missing `[mrt] output_dir` is
  created 0700, instead of following the process umask (0644 and 0755 under
  umask 022). Dumps carry routes, peer addresses, ASNs and router IDs.
  **Operator-visible:** an existing `output_dir` must be owned by the daemon
  user, must not be world-writable, and may be group-writable only by the
  daemon's own group; otherwise each dump fails with a permission error. A
  group- or other-readable directory is logged as a warning and left
  unchanged. See [`[mrt]`](../docs/reference/configuration.md#mrt).
