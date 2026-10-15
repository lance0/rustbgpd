### Changed

- Add the bounded `ListBgpLsRibRoutes` read with best, received and advertised
  views, family and NLRI-type filters, a 100-row default page, a 1000-row clamp
  and mutation-fenced continuation tokens. It replaces the whole-table
  `ListBgpLsRoutes` in the scoped BGP-LS route-reflector role; the older read
  is deprecated and outside v1, with its signature and behavior retained.
  `rbgp rib bgpls` now walks every bounded page and prints the same JSON array.
  See the [API reference](../docs/reference/api.md#list-bgp-ls-routes).
