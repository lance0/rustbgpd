### Security

- Native gRPC mTLS listeners accept an optional `tls_client_crl_file`: PEM
  certificate revocation lists checked against every client certificate
  chain at the TLS handshake. A revoked operator certificate was previously
  accepted until it expired. The CRL reloads with the other credentials on
  SIGHUP. Once configured it fails closed: a missing, empty, or unparsable
  file fails startup, `--check`, and the credential reload, and a CRL past
  its `nextUpdate` refuses every client until a fresh one is reloaded. A
  listener with a CRL offers no TLS session resumption, so a client cannot
  reuse a session from before an expiry or revocation.
  Listeners without the field are unchanged. See
  [client certificate revocation](../docs/reference/configuration.md#grpc-client-certificate-revocation).
