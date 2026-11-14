### Changed

- MRT dumps encode and write bounded chunks instead of retaining a second
  complete route table and encoded file. Peer metadata is captured at the
  start; peers joining during a dump are excluded. EVPN steps visit at most
  4,096 slots, including vacancies, and use temporary disk sorting to retain
  record order. Owned route chunks and encoded records each have an 8 MiB
  cap; an oversized prefix fails the dump without publishing a partial
  file. A neighbor whose EVPN table is removed or replaced mid-dump keeps
  the rows already read and the rest is skipped as withdrawn. The dump is
  staged in the output directory for its whole duration, and startup
  removes stage files a previous process left behind. See
  [dump consistency and limits](../docs/reference/configuration.md#what-one-dump-shows).
