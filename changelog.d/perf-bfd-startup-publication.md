### Changed

- Batch redundant BFD desired-session publications during configured peer
  registration, reducing startup work for BFD-heavy configurations. Genuine
  enable/disable transitions still publish immediately, and strict BFD peers
  retain their post-registration admission acknowledgement.
