### Fixed

- When a full outbound queue refuses End-of-RIB after selection release,
  a receiver whose release replay had no missing rows retries the marker
  without rebuilding and resending routes from unrelated families.
