### Upgrade notes

- `bgp_rib_outbound_credit_rows` keeps its name and still counts rows, but
  the outbound credit is now admitted in bytes: alert or graph on
  `bgp_rib_outbound_credit_bytes` to see how close peers are to it. With 150
  registered peers a peer now holds about 57,000 queued unicast announcements
  before its further changes become owed keys, about half the previous row
  limit. Owed keys are sent from current state without a resync only while
  the peer is clean: a dirty, forced or closing peer, EVPN with a private
  handoff, a grouped peer's OTC diagnostics, a pass refused at commit, and
  repeated drain refusals still mark the peer dirty and resync it. No path
  resets the session.
