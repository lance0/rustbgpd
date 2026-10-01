### Changed

- Build scale harnesses as root workspace members with the shared `Cargo.lock`.
  They remain outside `default-members`; explicit builds use the `scale`
  profile, preserving the former release settings and writing to `target/scale/`.
