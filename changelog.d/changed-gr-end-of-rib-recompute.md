### Changed

- A Graceful Restart or Long-Lived Graceful Restart End-of-RIB now
  recomputes and redistributes only the unicast routes it removed or
  changed. Previously every End-of-RIB, including those for other address
  families such as VPN, walked all of the restarting peer's unicast prefixes.
  Stale routes that were not re-advertised are still removed, retained
  routes still drop their stale state, and GR completion is unchanged. In a
  manager benchmark with 1,000,000 IPv4 and 200,000 IPv6 routes, one restart
  (three End-of-RIB markers) dropped from about 2.9 s of RIB work to about
  34 ms, and to about 34 ms from about 7.3 s with per-client-best clients.
