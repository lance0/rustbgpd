### Fixed

- The RIB actor now yields once a run of queued route or End-of-RIB messages
  exceeds its 25 ms poll budget, as its timer drain already did. With a deep
  ingest backlog, such as a full-table VPN churn, it used to apply up to
  Tokio's whole cooperative budget of messages (128) in one poll. A `/readyz`
  probe answered during that poll then waited for the rest of it before it
  could send its response. **Operator-visible:** `/readyz` no longer returns
  late or with 503 while the RIB drains a large VPN UPDATE backlog on a small
  worker pool. Message order is unchanged.
