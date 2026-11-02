### Fixed

- Memory owed to receivers that stop reading is now bounded. The channel from
  the RIB to each session was bounded only by update count, so when receivers
  stalled while sources churned, queued route versions, and for owned EVPN
  update-group members repeated full-table complete feeds, grew until the
  daemon ran out of memory. Each route update now carries an estimate of the
  bytes it retains, charged against a 512 MiB per-session budget and a 2 GiB
  daemon-wide budget until the update is dropped. Over budget, the RIB refuses
  the peer's next route update exactly as for a full channel: the peer is
  marked dirty and resyncs once it drains, and the RIB never waits. A session
  holding less than 1 MiB is always admitted, so stalled receivers do not hold
  back healthy ones. An owned EVPN member also never has more than one full
  complete feed queued or being sent; its resync is deferred until that feed
  drains.
  **Operator-visible:** new metrics describe the RIB-to-session channel:
  `bgp_peer_outbound_queued_updates`, `bgp_peer_outbound_reserved_slots`,
  `bgp_peer_outbound_enqueued_updates_total`,
  `bgp_peer_outbound_dequeued_updates_total`,
  `bgp_peer_outbound_discarded_updates_total`,
  `bgp_peer_outbound_retained_updates`, `bgp_peer_outbound_retained_bytes`,
  `bgp_peer_outbound_retained_bytes_high_watermark`,
  `bgp_rib_outbound_retained_bytes` and
  `bgp_rib_outbound_retained_bytes_high_watermark`. A refusal over budget is
  counted in `bgp_outbound_route_drops_total`, like a full channel. See the
  [metrics reference](../docs/reference/operations.md).
