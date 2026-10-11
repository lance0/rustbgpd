### Fixed

- Bound peer-pushed Address-Prefix ORF state to 4,096 entries per peer and
  AFI/SAFI. An overflowing group is rejected without changing the installed
  filter or ending the session; `REMOVE` and `REMOVE-ALL` can free capacity.
  Sequence-keyed entries avoid rescanning the list for each update. Warnings
  and `bgp_orf_capacity_rejections_total{peer,family}` report rejected groups.
