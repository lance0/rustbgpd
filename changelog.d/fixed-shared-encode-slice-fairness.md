### Fixed

- Yield after every two published slices of shared update-group encoding so other
  session tasks can run during large exports. Cancellation wakes followers for
  ordinary fallback, preserving source exclusion and command order.
