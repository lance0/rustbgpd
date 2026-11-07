### Fixed

- An RTR v1 cache that announces a VRP with host bits set and later withdraws
  the same prefix in canonical form no longer leaves the VRP authorizing that
  prefix. Each cache's VRPs are now keyed by the canonical prefix, as validation
  reads them, so `bgp_rpki_vrp_count` also no longer counts one VRP twice.
