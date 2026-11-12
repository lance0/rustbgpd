### Fixed

- `rbgp neighbor` with no peers now prints its empty-state line and exits 0
  when the dynamic-neighbor range query fails, noting that the range count is
  unavailable. Before, the human view exited 1 with no output while `-j`
  printed `[]` and exited 0.
  **Operator-visible:** `-j` on `policy fmt`, `diff snapshot from-mrt`,
  `diff snapshot from-bmp`, `completions` and `man` now prints one
  `warning: --json has no effect` line on stderr, as `metrics` and `top`
  already did; stdout and the exit code are unchanged. A failed daemon-side
  write with EACCES or EROFS, such as config persistence under
  `ProtectSystem=strict`, now adds a hint naming `chown` and
  `ReadWritePaths=`; other EACCES failures, such as an unreadable policy
  source, get a neutral ownership-and-mode hint.
