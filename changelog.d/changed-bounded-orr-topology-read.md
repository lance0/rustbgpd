### Changed

- Add bounded `ListOrrTopologyNodes` and `ListOrrTopologyLinks` reads of the
  RFC 9107 ORR topology, with the shared family page contract: 100-row
  default, 1000-row clamp and mutation-fenced continuation tokens. Links are
  ordered by endpoint keys and Link NLRI, so parallel links each appear once.
  They replace the whole-graph `ListTopologyNodes` and `ListTopologyLinks` in
  the scoped BGP-LS route-reflector role; the older reads are deprecated and
  outside v1, with signatures and behavior retained. `rbgp topology nodes` and
  `rbgp topology links` now walk every page and print the same JSON arrays.
  See the
  [API reference](../docs/reference/api.md#list-orr-topology-nodes-and-links).
