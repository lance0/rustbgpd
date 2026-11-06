### Upgrade notes

- A `runtime_state_dir` that the daemon cannot create or open, that is not
  owned by the daemon user, or that is group- or world-writable now stops
  startup with exit code 1 and the log line `refusing to start:
  runtime_state_dir must be a directory owned by the daemon user and not
  group- or world-writable`. Earlier releases logged `runtime-state
  marker/checkpoint storage unavailable` and ran without the graceful-restart
  marker, warm checkpoint, and BLACKHOLE receipt. Before upgrading, check the
  directory (default `/var/lib/rustbgpd`) with `stat`, then `chown` it to the
  daemon user and `chmod 0700` it. Container deployments that override the
  image user need a host bind mount owned by that user.
