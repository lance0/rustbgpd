### Fixed

- Bound shared unicast/VPN recovery capture work by sorting a fallible, capacity-accounted buffer of borrowed OLD route references, then merging into the shared admission mask. Sparse additions, temporary allocation overlap, flat fallback, and readiness checkpoints retain their existing limits. The same capture preparation applies to dormant EVPN grouping.
