### Fixed

- The gRPC TCP, gRPC Unix-socket and metrics listeners no longer spin a
  runtime worker when `accept()` fails with EMFILE, ENFILE, ENOMEM or ENOBUFS.
  They now back off like the BGP listener, from 100 ms doubling to a 1 s cap
  and resetting on the next accepted connection. Previously each failed
  accept was retried immediately. The metrics listener also logged every
  failure at `ERROR`.
  **Operator-visible:** the per-failure `metrics server accept error` record
  is replaced by `listener accept failing; backing off` at `ERROR`, naming
  the listener. It is logged on the first failure and then about once a
  minute while exhaustion persists; `listener accept recovered` at `INFO`
  marks the end. If the listening socket itself becomes unusable (EBADF,
  ENOTSOCK, EINVAL, EOPNOTSUPP), the listener logs `listener socket unusable;
  stopping its accept loop` and stops; for gRPC, that shuts the daemon down
  through the existing gRPC listener-exit handling. Transient per-connection
  accept errors now log at `DEBUG`.
