### Fixed

- When a Non-DF segment or a single-active AC binding leaves the
  configuration, the EVPN dataplane restores the bridge ports it had
  suppressed or blocked, as before. It now restores a port only while
  the port still has the name it had when it was managed. Previously the
  restore targeted the remembered ifindex alone. If the port had been
  deleted and an unrelated bridge port had taken that ifindex, the
  restore rewrote the unrelated port's flood flags or set it forwarding.
