### Documentation

- [`SECURITY.md`](../SECURITY.md) now accepts vulnerability reports by email
  at `lance@lance0.com` as well as through GitHub private vulnerability
  reporting, and defines a four-level severity scale. A crash, hang or wedged
  RIB caused by BGP peer, RPKI cache or BFD input is High. The 72-hour
  patch-and-release commitment still covers remote crashes and session
  hijacking, and now covers every Critical issue. Other High issues are
  prioritized for the next patch release.
- `.oss-scanner/` holds a build and threat model for automated security
  scanning: an offline-capable image that builds the workspace and fuzz
  targets and runs the test suite as an unprivileged user.
