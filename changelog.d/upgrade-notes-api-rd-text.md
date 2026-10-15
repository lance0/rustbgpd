### Upgrade notes

- RD-bearing API and CLI output uses raw hexadecimal for a Type 2 Route
  Distinguisher whose ASN is at most 65535, distinguishing it from a
  different Type 0 RD. Clients can pass the returned spelling back to RD
  filters and selectors. Ordinary RD output is unchanged; persisted
  historical event labels and payloads are not migrated. See
  [Route Distinguisher identity](../docs/reference/api.md#route-distinguisher-identity)
  for the accepted input grammar and optional versus required fields.
- Invalid export-explain RD input reports the RD diagnostic once instead
  of naming a nonexistent `rd_filter` field. The status remains
  `INVALID_ARGUMENT`.
