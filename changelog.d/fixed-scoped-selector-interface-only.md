### Fixed

- A scoped selector such as `fe80::3%swp1` now selects the interface-only
  neighbor on `swp1` for any link-local address, bound or not, in
  `GetNeighborState` and the neighbor action RPCs, as ADR-0142 describes.
  Before, it found the neighbor only when the address was the one it had
  learned, so a selector copied from a log line after an address change was
  not found. A neighbor that matches the selector exactly is still selected
  first.
