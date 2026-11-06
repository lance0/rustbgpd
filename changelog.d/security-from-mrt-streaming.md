### Security

- `rbgp diff snapshot from-mrt` now reads the dump one record at a time, in
  a validation pass and a writing pass, instead of loading the whole file
  and every decoded route. Memory stays near one record; previously a
  21 MB dump could request a single 768 MiB allocation and abort instead of
  exiting 2. A record longer than 16 MiB, or a snapshot longer than 4 GiB,
  refuses the dump with exit 2 and nothing on stdout. Output bytes are
  unchanged. See
  [the MRT view contract](../docs/how-to/ribdiff.md#rbgp-diff-snapshot-from-mrt-and-the---view-contract).
