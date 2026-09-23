### Changed

- The route-server example's `hygiene.rpol` no longer adds RFC 8097 `OV_*`
  origin-validation-state extended communities. Route-server-client export
  keeps extended communities, so every member received the tag, and
  [draft-ietf-sidrops-avoid-rpki-state-in-bgp §6](https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-avoid-rpki-state-in-bgp-12#section-6)
  says operators MUST NOT signal RPKI-derived validation state over eBGP
  across administrative boundaries. The tag also turned an RTR cache outage
  into a replacement UPDATE for every tagged route to every member. Accept
  and reject decisions are unchanged, and rpol can still add `OV_*`
  communities. `rs-config-render` in IXP Manager mode embeds this file, so
  its rendered `policy/ixp-hygiene.rpol` drops the same terms.
  **Operator-visible:** the route-server example no longer tags RPKI state;
  configs derived from it can drop the `tag-ov-valid`, `tag-ov-not-found`
  and `tag-ov-invalid` terms and their tests.
