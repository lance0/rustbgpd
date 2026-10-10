### Added

- Alpha route flap dampening configuration preparation and a pure RFC 2439
  penalty/decay engine with bounded, removable reuse scheduling. Effective
  enablement is rejected until received-route integration exists; no routes
  are dampened, and omitted settings preserve existing behavior. See the
  [configuration reference](../docs/reference/configuration.md#route-flap-dampening-preparation-alpha).
