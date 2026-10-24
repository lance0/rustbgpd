### Fixed

- Preserve the link provenance of Graceful Restart routes when an inbound
  reconnect replaces the session actor, so carrier loss during the new
  handshake purges routes retained from the lost connection.
- Honor planned-restart End-of-RIB grace for interface-only neighbors,
  including a late first binding, without extending the startup deadline.
- Retry failed BFD removal acknowledgements during interface-only neighbor
  deletion and endpoint changes, including a neighbor that never completed
  its first binding. A replacement waits for confirmed cleanup, and a
  deleted neighbor's held operator state does not enter a re-added stanza.
