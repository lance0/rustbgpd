### Security

- Keep config history, persistence markers, FIB ownership state, pending
  commit-confirm files, and panic reports under the runtime directory opened
  at startup when an ancestor symlink changes. Confirmed apply refuses an
  unsafe pending directory or a recovery pathname that no longer names that
  directory. Staged configuration writes still refuse replaced config paths.
