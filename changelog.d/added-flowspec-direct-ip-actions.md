### Added

- FlowSpec injection and read-back accept direct target-IP redirect/copy
  actions for IPv4 and IPv6, distinct from the existing VRF redirect action.
  The IPv6 target uses path attribute 25, with lossless 20-octet raw values
  exposed in `ipv6_extended_communities`; `rbgp flowspec` renders the typed
  targets and includes nonempty raw values in JSON. Ordinary eBGP export
  filters non-transitive 20-octet values under the existing community policy,
  preserving received Partial flags; empty attribute 25 values cannot be
  encoded. BMP unicast snapshots retain attribute 25 in `unknown_attrs`,
  preserving value order, duplicates and received Partial flags. See the
  [API contract](../docs/reference/api.md#list-flowspec-routes) and
  [ADR-0143](../docs/adr/0143-flowspec-direct-ip-actions.md). Controllers need
  an implementing daemon release; an older server may ignore new fields.
  This does not add bounded lease mutations, qualify router forwarding, or
  enable a scrubber controller.
