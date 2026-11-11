### Fixed

- Replacement sessions preserve the last RIB-registered predecessor after the
  old actor stops, including registration admitted during retirement of a
  replaced session or of a dynamic session that went idle, and collision
  promotions whose intervening handshakes never established. A collision
  candidate promoted over a primary that had registered with the RIB now names
  that primary in its registration, so the RIB retires the primary's record at
  once instead of keeping it as a collision fallback.
