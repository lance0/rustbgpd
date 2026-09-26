### Added
- `rbgp` supports HTTPS gRPC endpoints with an explicit CA bundle, client
  certificate/key and server-name override through `--tls-ca`, `--tls-cert`,
  `--tls-key`, `--tls-server-name` and matching `RUSTBGPD_TLS_*` environment
  variables. Doctor reports TLS credential kinds, and TLS certificate failures
  carry targeted diagnostics while Unix sockets and plaintext TCP remain unchanged.
