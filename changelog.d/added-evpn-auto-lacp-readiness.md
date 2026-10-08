### Added

- `esi = "auto-lacp"` Ethernet Segment readiness is visible outside the log.
  The new `evpn_es_auto_esi_state{interface, state}` gauge is a state set
  per configured bond, with `state` either `ready` or the not-ready reason
  (`no_partner`, `down`, `not_lacp_mode`, …). `rbgp doctor` adds an
  `evpn.es.<interface>.auto_esi` check that names the reason, and the shipped
  alert rules add `EvpnAutoLacpSegmentNotReady` (not ready for 10 minutes).
  See
  [Auto-derived ESI](../docs/reference/configuration.md#auto-derived-esi-lacp-type-1).
