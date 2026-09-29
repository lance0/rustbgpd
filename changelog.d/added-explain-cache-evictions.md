### Added

- Import-policy explain reports cache eviction.
  `ExplainImportPolicyResponse` gains optional `cache_size` and
  `evictions_since_reset` fields, `rbgp policy explain --direction import`
  prints them (JSON: `cache_size`, `evictions_since_reset`, null when the
  daemon does not report them), and the new per-peer counter
  `bgp_import_explain_cache_evictions_total{peer}` counts decisions evicted
  from the explain cache. See
  [operations](../docs/reference/operations.md#explain-an-import-decision-adr-0073).
