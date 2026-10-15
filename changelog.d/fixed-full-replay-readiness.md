### Fixed

- Full outbound resyncs triggered by route ingestion now service dedicated readiness probes within each peer replay. Existing stalled-operation bounds and ordinary query and mutation fencing are preserved.
