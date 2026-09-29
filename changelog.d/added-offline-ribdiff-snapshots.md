### Added

- `rbgp diff snapshots INCUMBENT RUSTBGPD` compares two complete advertised
  snapshots offline, including ORIGINATOR_ID and CLUSTER_LIST wire bytes.
  It preserves the existing `rbgp-ribdiff/1` report and 0/1/2 exit contract,
  refuses mismatched generations or peer ASNs, and bounds both inputs.
  The [RR comparison prerequisites](../docs/cookbook/route-server-migration.md#route-reflector-snapshot-comparison)
  document capture requirements; incumbent RR qualification remains pending.
- Bash file-path completion accounts for flags and option values before or
  between positional paths, preserving filenames that contain spaces.
