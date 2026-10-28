### Fixed

- Keep an owed initial End-of-RIB behind its family's ORF gate when a
  negotiated family becomes sendable during selection or replay grace.
  Its own ROUTE-REFRESH sends the table before completing that family.
