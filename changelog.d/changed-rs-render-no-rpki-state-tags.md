### Changed

- In arouteserver mode, `rs-config-render` no longer adds RFC 8097 `OV_*`
  origin-validation-state extended communities in `rs-hygiene.rpol`. The
  `tag-ov-valid` and `tag-ov-not-found` terms, and `tag-ov-invalid` when
  `reject_invalid` is off, are gone. Route-server-client export keeps
  extended communities, so every member received the tag, and
  [draft-ietf-sidrops-avoid-rpki-state-in-bgp §6](https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-avoid-rpki-state-in-bgp-12#section-6)
  says "Operators MUST NOT signal RPKI-derived validation states using BGP
  Path Attributes carried over EBGP sessions across administrative
  boundaries." The renderer now matches ARouteServer as well as the draft:
  ARouteServer 1.23.2 tags RFC 8097 state internally, but BIRD and OpenBGPD
  strip non-transitive extended communities on eBGP export, so its clients
  never receive it. The `reject-rpki-invalid` term is kept, and no accept
  or reject decision changes.
  **Operator-visible:** a re-rendered site stops sending RFC 8097
  validation-state extended communities to members, and candidate hashes
  change. A member policy that matched those communities loses that signal;
  members should validate routes themselves.
