### Changed

- Clean grouped export-policy transitions retain successful prestaged wire
  probes across route additions and withdrawals, rechecking changed rows and
  each target's wire ceiling before publication. Rejected or stale proofs retain
  the full fenced validation path.
