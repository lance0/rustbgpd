### Security

- Bound Birdwatcher route requests to four concurrent workers and a ten-second
  HTTP deadline. Empty and oversized peer views now avoid the global primary
  route scan; other route scans refuse incomplete results above the new
  `--max-scan-routes` limit (10,000 rows by default). Operators serving larger
  nonempty views may need to raise this limit.
- Prepare FIB status rows and filter indexes before publication, so paged
  `ListFibRoutes` requests copy only their returned rows instead of converting
  and sorting the complete FIB on every page. Retired publications are released
  by the blocking publisher rather than by an API reader.
