### Changed

- A Graceful Restart or Long-Lived Graceful Restart End-of-RIB now
  recomputes and redistributes only the unicast routes it removed or
  changed. Previously every End-of-RIB, including those for other address
  families such as VPN, walked all of the restarting peer's unicast prefixes.
  Stale routes that were not re-advertised are still removed, retained
  routes still drop their stale state, and GR completion is unchanged. In a
  manager benchmark with 1,000,000 IPv4 and 200,000 IPv6 routes, one restart
  (three End-of-RIB markers) dropped to about 34 ms of RIB work from about
  2.9 s with two plain update-group clients, 7.3 s with a two-member
  per-client-best update group, and 10.3 s with two ungrouped
  per-client-best clients.
