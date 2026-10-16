### Security

- Update rustls to 0.23.46, fixing RUSTSEC-2026-0346 (session `Debug` output
  could expose TLS secrets) and RUSTSEC-2026-0347 and RUSTSEC-2026-0349
  affecting the gRPC TLS listener and `rbgp` client.
