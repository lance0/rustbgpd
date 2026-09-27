### Changed

- The daemon raises its soft `RLIMIT_NOFILE` to the hard limit at startup and
  logs the before and after values. A foreground run from a login shell
  (soft 1024) or a default `docker run` no longer leaves `rbgp doctor`
  failing `daemon.rlimit.nofile`, and the
  [quickstart](../docs/tutorials/quickstart.md) drops its `ulimit -n` step.
  **Operator-visible:** the hard limit is now the effective limit. systemd
  `LimitNOFILE=` and container `--ulimit nofile=` settings still set that
  ceiling; a hard limit below 4096 still fails `rbgp doctor`.
