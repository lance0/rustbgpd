### Fixed

- A v1-only RTR cache that answers rustbgpd's v2 query with a v1 response no
  longer receives a fatal "Unexpected Protocol Version" Error Report. The client
  closes the connection and reconnects at v1 without the report.
