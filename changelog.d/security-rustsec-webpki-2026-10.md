### Security

- Updated `rustls-webpki` to 0.103.16 for RUSTSEC-2026-0382, which rejects
  certificate paths through distrusted emSign intermediates whose private keys
  are public. `rustbgpd` uses it to verify gRPC mTLS client certificates and
  gNMI dial-out collector certificates, and `rbgp` uses it to verify the
  daemon's gRPC server certificate. Both verify against the operator-configured
  CA bundle, not a bundled root store, so exposure requires a configured trust
  anchor that chains to an emSign root.
- Updated `webpki-roots` and `webpki-root-certs` to 1.0.10 for
  RUSTSEC-2026-0381 and RUSTSEC-2026-0383, which remove the `emSign ECC Root
  CA - G3` root. Only the `rs-config-render` tool's HTTPS fetches use these
  bundled roots; the `rustbgpd` and `rbgp` binaries do not link them.
