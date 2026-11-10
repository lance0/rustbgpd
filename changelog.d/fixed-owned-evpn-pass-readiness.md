### Fixed

- An EVPN-owning update group now serves the readiness lane while it
  distributes a batch its receivers refuse. Each refused member's recovery
  capture takes a readiness owner for its table-sized walk, and the member
  loop serves the lane at every member boundary. Before, one inbound batch
  ran every refused member's capture back to back with no service: with 150
  receivers paused, fourteen captures held the RIB manager for 348 ms and
  `/readyz` returned 503. EVPN group ownership is not enabled in release
  builds, so no shipped configuration takes this path.
