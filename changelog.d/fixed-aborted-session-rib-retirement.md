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
  has room, without the peer manager waiting for them.
  **Operator-visible:** after a session is replaced or stopped under RIB
  backpressure, its routes are withdrawn, or retained as its graceful
  restart capability says, and
  `bgp_rib_outbound_registration_failover_total` no longer increments on
  that peer's next graceful-restart teardown.
