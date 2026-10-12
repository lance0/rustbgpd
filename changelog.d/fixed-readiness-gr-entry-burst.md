### Fixed

- `/readyz` and `GetHealth` no longer miss their 200 ms deadline when many
  peers enter graceful restart at once. The RIB answered the probe promptly,
  but then kept its runtime worker while it applied the rest of the queued
  GR entries, and the answered probe could not run on another worker. At
  200 simultaneous disconnects that delay was about 200 ms. The RIB now
  yields after it answers a readiness probe. Graceful-restart handling and
  the deadline are unchanged.
