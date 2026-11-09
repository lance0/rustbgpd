### Security

- Refuse config-adjacent `<config>.unconfirmed-*` backups as candidate policy
  sources below `operator_only`, and check opened source file identities so hardlinks
  cannot bypass protection of the running config and credential files.
