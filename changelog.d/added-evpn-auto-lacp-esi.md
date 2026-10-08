### Added

- `[[ethernet_segments]]` accepts `esi = "auto-lacp"`, which derives the
  RFC 7432 §5 Type 1 ESI from the CE's LACP system MAC and port key as
  reported by the 802.3ad bond named by `interface`. Readiness is checked at
  runtime: the daemon and `rustbgpd --check` do not depend on the bond. The
  segment originates nothing while its bond is missing, down, not 802.3ad,
  or partnerless, logging the reason. It is added when LACP converges, and
  it is withdrawn and re-originated under the new ESI when the CE is
  replaced, with no restart. Type 2 (STP) derivation is not implemented.
  See
  [Auto-derived ESI](../docs/reference/configuration.md#auto-derived-esi-lacp-type-1).
