### Fixed

- `bgp_as_path_loop_detected_total` now counts the EVPN routes and FlowSpec
  rules of an UPDATE discarded for an `AS_PATH` loop. Those announcements
  were already discarded, but the counter skipped them, so a looped UPDATE
  carrying only EVPN or FlowSpec NLRI left it unchanged.
  **Operator-visible:** the counter now advances for loop-rejected EVPN and
  FlowSpec announcements, and its help text and the
  [operations reference](../docs/reference/operations.md) describe it as
  announced NLRI of every address family rather than prefixes.
