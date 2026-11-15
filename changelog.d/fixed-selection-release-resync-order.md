### Fixed

- Complete family selection and shared group staging before replaying pending
  outbound resyncs at graceful-restart selection-hold release. A receiver whose
  writer was full and whose outbound refresh was pending could receive a
  withdrawal followed by a re-announcement of a route re-received during the
  hold. This affected grouped unicast, received FlowSpec rules, VPN, labeled
  unicast, private EVPN, and BGP-LS. Resyncs now use the released
  selection and staged group tables, with End-of-RIB afterward; refused sends
  retain their recovery obligations.
  **Operator-visible:** avoids transient removal of re-received RTBH routes and
  FlowSpec discard rules when an outbound refresh, including a graceful-shutdown
  toggle, overlaps selection-hold release and writer backpressure.
