### Security

- `rbgp doctor`'s `daemon.config_freshness` check now compares the config
  file's mtime with the daemon's last config-file marker at full filesystem
  timestamp resolution. The daemon records the marker as seconds and
  nanoseconds; before this, both sides were whole seconds, so an edit saved
  in the same second as the daemon's own read or write was reported as
  current. Any difference from the marker now warns, including a file
  replaced with an older timestamp. A whole-second marker from an older
  daemon keeps the previous comparison. Two saves within one filesystem
  timestamp tick still cannot be told apart.
