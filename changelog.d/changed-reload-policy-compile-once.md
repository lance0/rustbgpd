### Changed

- SIGHUP reload and config validation compile `.rpol` policy chains less
  often on large rosters. Validation no longer compiles every named chain a
  second time to check the chain node bound; the bound itself is unchanged
  and still rejects an oversized chain on file load, SIGHUP, and the policy
  API paths. Each AS-path regex now compiles once per 32-neighbor resolution
  chunk instead of once per chain, and each chain compile copies only the
  dataset bindings its policy file declares.
