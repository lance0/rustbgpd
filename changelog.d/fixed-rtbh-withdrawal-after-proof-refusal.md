### Fixed

- Remove deleted, expired or BLACKHOLE-demoted RTBH advertisements during
  Graceful Restart selection deferral even when recovery-proof allocation
  fails. Other pending advertisements and End-of-RIB remain held. If
  incomplete Add-Path state cannot prove the last path at a prefix left,
  outbound capacity remains unknown until recovery completes.
