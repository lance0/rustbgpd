### Fixed

- `rbgp doctor` now warns about a config file saved again while a SIGHUP
  reload was still applying. The daemon's last-persist marker records the
  file's mtime when the reload read it, not when the reload finished, so a
  second save in that window no longer reads as already applied.
