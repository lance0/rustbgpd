### Security

- Refuse `<config>.unconfirmed-*` backups beside the resolved config target as
  candidate policy sources below `operator_only`, and check opened source file
  identities so hardlinks cannot bypass protection of the running config and
  credential files. Confined candidate loads fail closed when the accepted
  physical target is missing or replaced.

- Retain accepted config target authority across launch-link changes and rollback,
  reject backup hardlink aliases and source-open symlink swaps, and use the
  accepted config at EVPN candidate admission. Below `operator_only`, fail closed
  when the config directory exceeds 4096 entries or changes during source reads.
  Recheck accepted target and parent identities on each source read to reject
  ancestor-directory replacement without repeating the backup inventory.
