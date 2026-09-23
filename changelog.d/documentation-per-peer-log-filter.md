### Documentation

- The operations reference and deployment guide gave the per-peer `RUST_LOG`
  filter as `peer{peer_addr=10.0.0.1}=debug`. That form does not parse, so
  it never selected the peer's events; how the daemon now handles an
  unparseable directive is in the `RUST_LOG` entry under Fixed. Both now
  give the bracketed `[peer{peer_addr=10.0.0.1}]=debug`. The operations
  reference also says which events the span filter selects, and shows how to
  select a peer's out-of-span events from the JSON log by the `peer` field.
  CONTRIBUTING gains a logging-style section covering field names, `%` and
  `?`, error fields and levels.
