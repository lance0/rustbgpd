### Upgrade notes

- On startup, the general FIB installer rewrites a valid v1–v4
  `fib-owned.json` as v5 and reads it back to verify the replacement.
  If you have an older receipt, run this release and verify the on-disk
  version before moving to a release that requires v5. See the
  [package upgrade procedure](../docs/how-to/deployment.md#upgrade).
