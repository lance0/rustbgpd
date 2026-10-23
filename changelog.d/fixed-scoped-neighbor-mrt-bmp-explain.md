### Fixed

- MRT `TABLE_DUMP_V2` snapshots give each neighbor its own
  `PEER_INDEX_TABLE` entry, so two neighbors on one link-local address are
  written as two entries. Each route references its own neighbor's entry, as
  FRR and GoBGP write them. A snapshot taken before an interface-only neighbor
  learns a new address files that neighbor's routes under the address that
  held them. `rbgp rib --prefix P --explain` names the interface when it
  decides the final tie, for example
  `peer fe80::1%eth0 < fe80::1%eth1 (scope tie-break)`; the reason code stays
  `lower_peer_address`. Explain replies and route pages render the addresses
  their rows were learned on, even when converted after such an address
  change. MRT and BMP output for ordinary peers is unchanged, and
  configuration still rejects one link-local address on two interfaces.
