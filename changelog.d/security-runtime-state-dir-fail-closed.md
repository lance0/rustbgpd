### Security

- `runtime_state_dir` validation now fails closed. The daemon refuses to
  start unless the directory is a real directory (not a symlink) owned by the
  daemon user and not group- or world-writable, reached through directories
  that only root or the daemon user can rewrite; previously it logged a warning
  and continued, and some state files were still written through the
  unvalidated path. The config last-persist marker, the general FIB
  ownership receipt and its `.stale` evidence copy, and panic reports are now
  published by renaming a fresh owner-only file into place, so a symlink at
  one of those paths is replaced instead of followed. `fib-owned.json`, which
  decides which kernel routes the daemon may replace or delete, is loaded only
  when it is a regular file owned by the daemon user and not group- or
  world-writable; anything else is ignored with a warning and the daemon owns
  no routes from it. See
  [`runtime_state_dir`](../docs/reference/configuration.md#global).
