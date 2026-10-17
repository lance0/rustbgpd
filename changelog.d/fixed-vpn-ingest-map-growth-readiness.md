### Fixed

- Keep readiness answered while a large VPN table is learned. The received,
  selected and advertised VPN route maps now split into 16 hash shards once
  they pass 16,384 entries, so a table resize rehashes one shard instead of
  the whole table inside a single UPDATE. Previously several full-table
  resizes could land in one UPDATE near one million keys and hold the RIB for
  about 600 ms. Total resize work, settled memory and peak memory are
  unchanged in the measured 1.23M-key initial load.
