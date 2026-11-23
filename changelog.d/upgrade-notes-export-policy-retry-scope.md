### Upgrade notes

- A successful export-policy replacement applies the change and gives each
  affected peer a retry before replying. Unrelated dirty peers recover on
  the RIB resync tick. Operators waiting for all peers to catch up should
  check outbound convergence and `bgp_rib_outbound_dirty_peers` after the
  policy reply. A full writer can also leave an affected peer pending.
