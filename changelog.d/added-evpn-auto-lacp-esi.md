### Added

- `[[ethernet_segments]]` accepts `esi = "auto-lacp"`, which derives the
  RFC 7432 §5 Type 1 ESI from the CE's LACP system MAC and port key as
  reported by the 802.3ad bond named by `interface`. Derivation fails closed:
  a missing, non-802.3ad, down, or partnerless bond rejects the config with
  the reason. The derived value is pinned until restart. Type 2 (STP)
  derivation is not implemented. See
  [Auto-derived ESI](../docs/reference/configuration.md#auto-derived-esi-lacp-type-1).
