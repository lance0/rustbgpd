### Fixed

- FIB peer filters match both the retained address and interface, keeping
  same-address link-local neighbors separate in paged and unpaged responses.
- FIB status publication prepares only the unfiltered order eagerly. Filter
  indexes are built on first use and reused within that publication, reducing
  publication latency and memory for unused filter combinations.
