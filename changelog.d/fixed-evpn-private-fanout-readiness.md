### Fixed

- Answer `/readyz` during private EVPN route distribution. One received EVPN
  UPDATE is committed to every receiving peer's Adj-RIB-Out in a single RIB
  actor step, and receivers that learn the same table resize their EVPN route
  maps in the same step. With 75 route-reflector clients learning 37,500 EVPN
  routes, one step held the actor for over 300 ms and `/readyz` returned 503
  (`rib_timeout`) during initial load. The readiness lane is now served at each
  receiver boundary, as VPN and unicast distribution already do.
