### Added

- `.rpol` `exists <field>` tests whether a route carries an optional value:
  `route.origin-as`, `peer.asn`, `route.med`, `route.local-pref` or
  `route.next-hop`. Use `if !exists route.origin-as { reject }` to reject a
  route whose value cannot be told; `exists route.med` and
  `exists route.local-pref` are the only way to tell an absent attribute from
  its default. `exists` is contextual, so a binding or parameter named
  `exists` keeps working.
