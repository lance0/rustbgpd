### Upgrade notes

- Config load, startup, SIGHUP reload, both `rustbgpd --check` modes and API
  config candidates now read and validate each gNMI dial-out `tls_ca_file`,
  `tls_cert_file` and `tls_key_file`. A file that is missing, empty, not
  UTF-8, without a PEM block of the expected kind, larger than 4 MiB, not a
  regular file, or world-writable now refuses boot and keeps a reload on the
  last-known-good config. Previously a missing or unreadable file only made
  that target retry at connect time. Before upgrading, run `rustbgpd --check`
  and install every configured dial-out file, or remove the TLS keys from a
  target that is not in use.
- A world-writable listener `tls_cert_file`, `tls_client_ca_file` or
  `tls_client_crl_file` is now refused like a world-writable token or key;
  certificates, CA bundles and CRLs were previously accepted regardless of
  mode. Run `chmod o-w` on the file.
- The primary config file must be a regular file no larger than 64 MiB, and
  the normalized document written by API changes must also fit 64 MiB. Pass
  the daemon the config file itself rather than a FIFO or device. See
  [credential file permissions](../docs/reference/configuration.md#grpc-credential-file-permissions).
