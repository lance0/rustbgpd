### Documentation

- The operations reference and deployment guide gave the per-peer
  `RUST_LOG` filter as `peer{peer_addr=10.0.0.1}=debug`. That form does not
  parse, and one unparseable directive makes the daemon ignore `RUST_LOG`
  and log at `info`. Both now give the bracketed
  `[peer{peer_addr=10.0.0.1}]=debug`. The operations reference also says
  which events the span filter selects, and shows how to select a peer's
  out-of-span events from the JSON log by the `peer` field. CONTRIBUTING
  gains a logging-style section covering field names, `%` and `?`, error
  fields and levels.
