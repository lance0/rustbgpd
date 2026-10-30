### Fixed

- When a held receiver's Graceful Restart recovery proof is refused,
  deleting the higher-ranked of two Add-Path RTBH paths on one prefix now
  withdraws the deleted path immediately instead of leaving it advertised
  until selection resumes. The surviving RTBH path stays on its existing
  path ID until release. A single-best RTBH replacement still keeps the
  previous route advertised, so the prefix is never left without a
  blackhole.
