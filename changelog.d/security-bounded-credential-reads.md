### Security

- Bound credential reads to 4 MiB and configuration reads to 64 MiB, refusing
  non-regular and world-writable credential files, including public listener
  certificates, CA bundles and CRLs. Read gNMI dial-out TLS credentials outside
  runtime workers and report their permissions in doctor. Enforce the same
  config limit before normalized documents are accepted or written, confine
  dial-out candidate credential paths, and scrub validation buffers.
