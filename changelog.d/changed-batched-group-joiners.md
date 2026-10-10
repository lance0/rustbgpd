### Changed

- Peers that reconnect together into the same plain update group now get
  their initial tables in one deferred-registration turn. The group table is
  replayed once, one exact-export probe pass covers every member whose
  session profile is proven equivalent, and transport encodes the shared
  announcement once, with each member's own routes excluded. Previously each
  joiner paid a full replay, probe and encode, one after another. Each
  member keeps its own route-server control, OTC, ORF, policy-filtered
  counters, prefix limits and End-of-RIB, sent after its table. Per-client-best,
  Add-Path, ORR, ORF, conditional-advertisement and mismatched-profile peers,
  and route-server members whose table carries control communities for them,
  are still served one at a time. A turn takes at most 64 joiners.
