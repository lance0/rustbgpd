### Upgrade notes

- `rustbgpd --check --strict` now exits 1 when a gRPC `token_file` or TLS
  private key is readable by every local user, owned by someone other than
  the daemon user or root, or open to a group other than the daemon's. A
  pipeline that ran the strict check cleanly on such a file now fails, and
  the daemon logs the same warning at startup and on each credential reload
  while still loading the file. To restore a clean check, run `chmod 600` on
  the file and make the daemon user its owner, or use mode `0640` owned by
  `root:<daemon group>`. A token bind-mounted into a container keeps its
  host owner and mode, so stage a copy with those permissions inside the
  container. See
  [credential file permissions](../docs/reference/configuration.md#grpc-credential-file-permissions).
