### Fixed

- Keep readiness responsive while retiring disconnected sessions and checking
  interface-only neighbor bindings. Independent session waits now share one
  500 ms round deadline, and healthy peers finish while stalled peers wait.
  A full RIB mailbox makes retention checks retry without waiting for admission.
