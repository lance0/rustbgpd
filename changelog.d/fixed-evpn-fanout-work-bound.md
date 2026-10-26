### Fixed

- Bound the RIB actor's work for one received EVPN UPDATE on a route
  reflector. The UPDATE's private fanout to every receiving peer now pauses at
  a peer boundary once it has used its 25 ms share and resumes on the next
  actor turn, before any later UPDATE is applied. Previously, peers that learn
  the same table resized their advertised EVPN tables in the same step: with
  75 clients learning 37,500 EVPN routes one step held the actor for about
  300 ms, and with 150 clients learning 75,000 routes for about 1.2 s.
