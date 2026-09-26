### Fixed

- Crash reports under `<runtime_state_dir>/crash/` are now written to a
  temporary file and renamed into place, and their names add the process ID
  and a per-process sequence number to the millisecond timestamp. Previously
  two threads that panicked in the same millisecond wrote one file, so a
  report could be lost or mixed with the other, and a process that died
  mid-write could leave an empty or truncated report for `rbgp doctor` to
  collect.
  **Operator-visible:** reports are named `panic-<ts>-<pid>-<n>.toml` and
  created owner-read-write only; an interrupted write can leave a
  `panic-*.toml.tmp` file, which `rbgp doctor` and retention ignore.
