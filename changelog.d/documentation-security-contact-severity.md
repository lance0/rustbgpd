### Documentation

- [`SECURITY.md`](../SECURITY.md) now accepts vulnerability reports by email
  at `lance@lance0.com` as well as through GitHub private vulnerability
  reporting, and defines a four-level severity scale. A crash, hang or wedged
  RIB caused by BGP peer, RPKI cache or BFD input is High, and the 72-hour fix
  commitment covers Critical and High, so remote crashes and session
  hijacking keep their existing response time.
- `.oss-scanner/` holds a build and threat model for automated security
  scanning: an offline-capable image that builds the workspace and fuzz
  targets and runs the test suite as an unprivileged user.
