### Upgrade notes

- The prepared embedding crate set is wire 0.24, FSM 0.11, and RPKI 0.6.
  `UpdateValidationOptions` struct literals must supply `link_local_next_hop`
  or use `..Default::default()`; leave it false to retain strict validation.
  Upgrade crates sharing wire types together. Published dependency examples
  remain on the previous release set until coordinated publication.
