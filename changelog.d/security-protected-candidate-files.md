### Security

- Refuse `<config>.unconfirmed-*` backups beside the resolved config target as
  candidate policy sources below `operator_only`, and check opened source file
  identities so hardlinks cannot bypass protection of the running config and
  credential files. Confined candidate loads fail closed when a terminal config
  symlink has no resolvable target.
