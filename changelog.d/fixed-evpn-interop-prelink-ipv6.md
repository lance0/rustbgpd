### Fixed

- Disable IPv6 before containerlab creates M66/M67 attachment circuits, preventing
  startup MLD and duplicate-address-detection packets from producing unrelated
  segment MAC advertisements. The drivers reject failed setup and preserve the
  existing forwarding, nexthop-group, and standby assertions.
