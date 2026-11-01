### Fixed

- For a route-server client that enforces RFC 7947 control communities and
  shares an update group, the advertised-route listing, the advertised count,
  the per-family `bgp_rib_adj_out_prefixes` gauge and BMP stat 17 now report
  what the client was actually sent. They used to count and list a best path
  the control communities suppress toward the client and show shared rows
  without its prepends and community scrub. With `per_client_best` they now
  show the client's fallback route. Ungrouped clients already reported this.
