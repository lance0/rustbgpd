### Fixed

- The first outbound advertisement honors the session's negotiated prefix
  filter even when sender registration is deferred. An `IMMEDIATE` update
  releases that family's initial advertisement. A `DEFER` update keeps the
  family waiting for a later refresh.
