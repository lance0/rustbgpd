### Fixed

- Keep readiness answered while a large VPN table is learned. The received,
  selected and advertised VPN route maps now split into 64 hash shards once
  they pass 16,384 entries, so a table resize rehashes one shard instead of
  the whole table inside a single UPDATE. Previously several full-table
  resizes could land in one UPDATE near one million keys and hold the RIB for
  more than 600 ms; total resize work and memory are unchanged.
