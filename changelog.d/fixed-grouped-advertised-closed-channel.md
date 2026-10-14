### Fixed

- Grouped VPN advertised pages refuse reads after the outbound receiver
  closes and before peer teardown, including when retry flags have cleared.
  Unicast advertised listing and export explain use the retained admitted
  baseline in this window, or refuse when none exists. Shared staged routes
  are no longer reported as admitted updates for a closed receiver.
