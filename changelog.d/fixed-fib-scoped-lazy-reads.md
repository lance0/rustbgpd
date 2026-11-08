### Fixed

- FIB peer filters match both the retained address and interface, keeping
  same-address link-local neighbors separate in paged and unpaged responses.
  A scoped peer selector such as `fe80::1%eth0` now excludes rows with no
  recorded interface, including rows restored from owned-state files written
  before the peer interface was persisted; those rows match again once they
  are re-projected.
- FIB status publication prepares only the unfiltered order eagerly. Filter
  indexes are built on first use and reused within that publication, reducing
  publication latency and memory for unused filter combinations. The first
  filtered read after each publication sorts the full publication to build
  that filter's order; later reads of the same publication reuse it. If index
  preparation fails, the read returns `INTERNAL`.
