### Fixed

- The ownership and mode check on the directories above `[mrt] output_dir`
  and `runtime_state_dir` now walks up from the directory already opened
  for writing, instead of resolving the configured path again. A symlink in
  that path repointed between the open and the check can no longer let the
  check approve one directory while dumps or runtime state go to another.
  The MRT bytes-written metric now takes the dump's size from the written
  file, so a dump whose directory is renamed while it is published is no
  longer reported as failed or with another file's size.
