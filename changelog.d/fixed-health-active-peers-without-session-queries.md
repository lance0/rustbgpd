### Fixed

- Keep `GetHealth` (and so `rbgp doctor`'s `daemon.healthy` check) inside its
  200 ms deadline on a CPU-starved daemon right after a reload. `GetHealth`
  counted Established peers by sending a state query to every session and
  joining the replies. With 1,000 route-server clients on four threads, the
  task joining those replies could still be waiting when the deadline passed,
  up to two seconds after a reload settled, and the RPC failed with
  `peer manager probe timed out (200ms deadline)`. Each session now publishes
  whether it is Established on every FSM transition and clears it when it
  ends, and the peer manager counts from that published state without querying
  any session. The deadline is unchanged.
  **Operator-visible:** `active_peers` counts a session that is Established
  but busy writing exports. It previously excluded a session that did not
  answer its state query within 100 ms, so the count could dip during a
  reload.
