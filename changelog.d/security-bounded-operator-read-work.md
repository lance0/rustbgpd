### Security

- Bound Birdwatcher route requests to four concurrent workers and a ten-second
  HTTP deadline. Empty and oversized peer views now avoid the global primary
  route scan; other adapter scans refuse incomplete results above the new
  `--max-scan-routes` matching/returned-row limit (10,000 rows by default).
  This bounds adapter transfer and retention, not native RIB query CPU work.
  Operators serving larger nonempty views may need to raise this limit.
- Prepare FIB status rows and filter indexes before publication, so paged
  `ListFibRoutes` requests copy only their returned rows instead of converting
  and sorting the complete FIB on every page. Retired publications are released
  by the blocking publisher rather than by an API reader.
