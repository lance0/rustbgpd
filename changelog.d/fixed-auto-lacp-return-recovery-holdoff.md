### Fixed

- An `esi = "auto-lacp"` Ethernet Segment whose bond regains the same LACP
  partner now waits `recovery_delay_seconds` before it originates again, as
  after a carrier return. Before, the link coordinator treated the returning
  segment as a new binding and released it at once, so it attracted traffic
  before the segment had re-converged. That included an operator undrain
  made just after the partner returned. A different partner is still a new
  segment and originates without the wait. See the
  [ADR-0085 amendment](../docs/adr/0085-evpn-es-interface-binding.md).
