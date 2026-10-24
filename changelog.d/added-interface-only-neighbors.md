### Added

- Interface-only unnumbered neighbors (ADR-0142): a `[[neighbors]]` entry may
  name only an `interface`, with no `address`, as FRR's
  `neighbor swp1 interface remote-as external` does. The daemon learns the
  peer's IPv6 link-local address from the Router Advertisements it sends on
  that link, advertises itself there so the peer can do the same, and opens
  an ordinary scoped link-local session to the learned address. Discovery
  never ends an Established session: a changed address is taken up only after
  the session fails, and the move purges the routes learned from the old
  address. Confirmed carrier loss, admin down or removal of the interface ends
  the session at once without Graceful Restart retention; an operator disable
  or a max-prefix shutdown stays in force across it. A learned address
  that another neighbor already holds is refused with
  `duplicate_link_local_address`. `[global.unnumbered]` sets
  `ra_interval_secs` (default 10 s; Router Lifetime is three times it) and
  `router_advertisements = false` to stop sending. See
  [the configuration reference](../docs/reference/configuration.md#interface-only-neighbors).
  **Operator-visible:** an interface-only neighbor needs `CAP_NET_RAW`;
  `rustbgpd --check` and startup fail with an error naming it when it is
  missing. Conditional advertisements apply to the learned endpoint, gated
  from the session's first UPDATE. TCP-AO, MD5, GTSM (`ttl_security`), BFD,
  per-neighbor `log_level` and outbound prefix maxima, and explicit
  `listen_addresses` are rejected on these neighbors (peer-group outbound
  maxima apply). Adding, removing or editing one, or
  `[global.unnumbered]`, is restart-required. Operator deletion of a
  discovery-owned peer is refused with `FAILED_PRECONDITION`.
- `remote_asn` accepts `"external"` (any ASN except `global.asn`) and
  `"internal"` (`global.asn`) on every static neighbor, in addition to a
  number. Both are checked against the ASN the peer sends in OPEN; a mismatch
  is refused with Bad Peer AS.
