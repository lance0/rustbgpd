### Upgrade notes

- `bgp_rib_outbound_credit_rows` keeps its name and still counts rows, but
  the outbound credit is now admitted in bytes: alert or graph on
  `bgp_rib_outbound_credit_bytes` to see how close peers are to it. With 150
  registered peers a peer now holds about 57,000 queued unicast announcements
  before its further changes become owed keys, about half the previous row
  limit; owed keys are sent from current state without a resync.
