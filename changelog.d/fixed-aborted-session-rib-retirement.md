### Fixed

- A session whose task is aborted now still ends in the RIB. A session
  holds its final `PeerDown` or graceful-restart notice while the RIB
  mailbox is full. When the bounded 500 ms session shutdown expired in
  that state, for example while an inbound connection replaced a session
  whose TCP had just failed, or when the task was aborted after an
  unacknowledged TCP-AO reset, the held messages were dropped with the
  task. The old session's routes then stayed installed with no bound; or,
  once a replacement session established, the old session stayed
  registered as live, and a later graceful-restart teardown of that peer
  failed over to the dead session instead of retaining its routes. The
  held messages, and a `PeerDown` for an Established session that had not
  queued one, are now delivered in session order as soon as the mailbox
  has room, without the peer manager waiting for them. An aborted
  Established session that had not queued its own end is closed with a
  plain `PeerDown`, so its routes are withdrawn rather than retained under
  graceful restart. A session whose `PeerUp` was itself still held is not
  announced to the RIB at all. Because such an end can now arrive late,
  the RIB discards a session end from a session that a later end for the
  same peer has already passed, so it cannot abort or restart the
  graceful-restart retention of a newer session; discards are counted in
  `bgp_rib_stale_peer_down_ignored_total`.
  **Operator-visible:** after a session is replaced or stopped under RIB
  backpressure, its routes are withdrawn, or retained as its graceful
  restart capability says, and
  `bgp_rib_outbound_registration_failover_total` no longer increments on
  that peer's next graceful-restart teardown.
