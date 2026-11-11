### Fixed

- Stop reading the whole RIB at each End-of-RIB and peer down while an
  exact-export rejection exists. While any peer held a route its session
  could not encode (for example an IPv6 route with no usable next hop,
  counted in `bgp_exact_export_rejections_total`), every received
  End-of-RIB, every peer down and every graceful-restart, long-lived
  graceful-restart or route-refresh window expiry collected every
  Adj-RIB-In and Loc-RIB row to decide which rejections were still live,
  without servicing readiness queries. With a large table and many peers
  establishing together, the daemon could miss its readiness probe. These
  events now look up only the rejected routes, so their cost follows the
  number of rejections instead of the table size. The routes advertised,
  withdrawn and rejected are unchanged.
