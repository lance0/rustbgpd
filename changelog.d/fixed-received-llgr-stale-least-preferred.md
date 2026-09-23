### Fixed

- Best-path selection now treats a route received with the `LLGR_STALE`
  community as least preferred, as RFC 9494 §4.3/§4.4 requires, in IPv4
  and IPv6 unicast and every route-reflection family (VPN, labeled unicast,
  EVPN, FlowSpec, BGP-LS and RTC). Previously only routes this speaker had
  itself moved into long-lived stale state were demoted, so a path another
  helper had already tagged competed on `LOCAL_PREF` and the later steps,
  and a reflector could select and reflect it over a fresh alternative. Two
  least-preferred routes still fall back to normal tie-breaking.
  **Operator-visible:** such a path now loses to any fresh or GR-stale
  alternative, and best-path explain reports the decision as
  `llgr_stale_community` (see the [explain guide](../docs/how-to/explain.md)).
  The rule applies whatever the LLGR state of the session the path arrived
  on; see the [RFC notes](../docs/reference/rfc-notes.md).
