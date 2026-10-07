### Upgrade notes

- The prepared embedding crate set is wire 0.24, FSM 0.11, and RPKI 0.6.
  `UpdateValidationOptions` is now `#[non_exhaustive]` and gains
  `link_local_next_hop`: replace struct literals with
  `UpdateValidationOptions::default()` plus field assignment. The default
  retains strict validation.
  Upgrade crates sharing wire types together. Published dependency examples
  remain on the previous release set until coordinated publication.
