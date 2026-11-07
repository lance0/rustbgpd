### Security

- gRPC credential files are now checked before they are read, at config
  load, startup, every SIGHUP credential reload, `--check`, and in
  `rbgp doctor`. A `token_file`, `tls_cert_file`, `tls_key_file`, or
  `tls_client_ca_file` whose target is not a regular file is refused, as is
  a world-writable token or private key; previously a FIFO at one of these
  paths could stall startup. A token or private key readable by every local
  user, owned by someone other than the daemon user or root, or open to a
  group other than the daemon's is still accepted, with one warning per load
  or reload that names the file, its mode and owner, and the remedy. The
  warning counts toward `--check --strict`, and doctor reports it as
  `credentials.<listener>.<field>`. Mode `0600`, or `0640 root:<daemon group>`,
  passes silently. See
  [credential file permissions](../docs/reference/configuration.md#grpc-credential-file-permissions).
