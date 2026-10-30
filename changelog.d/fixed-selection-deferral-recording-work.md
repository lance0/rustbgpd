### Fixed

- Service RIB readiness while retaining selection-deferral identities for all
  route families, including EVPN and RT-Constrain. Sharded identity storage
  bounds each insertion's resize work while preserving duplicate accounting,
  retained-key limits, overflow fallback and family release ordering.
