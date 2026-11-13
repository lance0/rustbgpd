### Added

- `[mrt] max_files` keeps at most that many dumps, deleting the oldest
  `<file_prefix>.*.mrt[.gz]` files after each successful publish. Unset keeps
  every dump, as before; 0 is rejected. Restart-required like the rest of
  `[mrt]`. See [`[mrt]`](../docs/reference/configuration.md#mrt).
