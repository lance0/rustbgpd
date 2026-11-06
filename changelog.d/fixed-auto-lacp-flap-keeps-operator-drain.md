### Fixed

- An operator drain on an `esi = "auto-lacp"` Ethernet Segment now survives
  its bond losing and regaining the LACP partner, for example across a
  carrier flap. The segment leaves the runtime while the bond is not ready,
  but the `operator` drain reason stays on its last derived ESI, so the
  segment returns drained instead of re-originating at once. A different
  partner is still a new segment and starts undrained, and removing the
  segment from the config still drops the drain
  ([ADR-0085](../docs/adr/0085-evpn-es-interface-binding.md)).
