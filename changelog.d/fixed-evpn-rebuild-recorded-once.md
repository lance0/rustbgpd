### Fixed

- After post-restart EVPN selection resumes, a receiver whose EVPN rebuild
  has been sent no longer waits for an IPv4, IPv6 or VPN selection hold
  before its EVPN ROUTE-REFRESH is answered, and the eviction-recovery
  histogram counts that rebuild once.
