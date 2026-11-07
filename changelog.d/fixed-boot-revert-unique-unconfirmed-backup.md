### Fixed

- A second commit-confirm boot revert lost its unconfirmed candidate. Every
  revert saved the candidate as `<config>.unconfirmed`. When that file was
  left over from an earlier revert, the save was skipped and the restore
  overwrote the new candidate, while the boot banner pointed at the old copy.
  Each revert now saves its candidate as `<config>.unconfirmed-<id>`, with
  16 hex digits derived from that transaction, and the banner names the
  suffix. A restart that interrupted the same revert still finds its own
  save. If a different file already holds the name, boot is refused and the
  candidate, the file and the pending authority are left untouched. The
  daemon never deletes these copies; remove them after recovery.
  **Upgrade note:** scripts that look for `<config>.unconfirmed` must match
  `<config>.unconfirmed-*` instead.
