### Fixed

- Scoped EVPN, dataplane and BFD event filters match the recorded interface,
  keeping neighbors on the same link-local address separate. EVPN events
  retain both current and previous interfaces in history and CLI output.
- Event history remains readable for removed scoped neighbors after another
  interface starts using their address. Bare link-local selectors still need
  an explicit interface.
