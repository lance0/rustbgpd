### Security

- The RIB now discards End-of-RIB, Beginning- and End-of-RIB-Refresh and
  refresh-window timeouts from a session that has no registration for the
  peer. A peer whose routes were retained under Graceful Restart could
  otherwise reconnect and send an End-of-RIB before its KEEPALIVE. That
  marker completed the stale-route sweep, and the retained routes were
  removed before the restarted session re-advertised them. The transport no
  longer forwards such a marker before Established; this closes the same
  path in the RIB. The discards are counted in
  `bgp_rib_stale_session_message_ignored_total{kind="eor"|"refresh"}`.
