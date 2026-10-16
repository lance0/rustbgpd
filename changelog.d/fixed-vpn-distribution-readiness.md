### Fixed

- VPN UPDATE distribution now answers pending `/readyz` probes at each peer
  boundary of its per-peer loop, as unicast ingest already does. With many
  dirty grouped members on the per-member recovery path (a refused shared
  proof, a peer-limit fallback, or ungrouped VPN peers), one UPDATE's
  distribution could hold the RIB for about 200 ms on a small host.
  **Operator-visible:** `/readyz` no longer times out with 503 while VPN
  UPDATEs are applied during a mass-dirty recovery on that path.
