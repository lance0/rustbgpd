### Fixed

- Local `docker build` runs no longer link another tree's code when the
  source files are older than the artifacts in the shared Cargo target
  cache. The builder stages touch the copied sources before `cargo build`,
  so every workspace crate is rebuilt from the build context. Images also
  record a content hash of their Rust build inputs at
  `/usr/local/share/rustbgpd/source-id`; compare it with
  `scripts/source-id.sh` in the intended tree, as described in
  [the interop guide](../docs/interop.md#prerequisites).
