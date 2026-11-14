### Fixed

- Keep validation-table recovery running if its restart-counter observer
  panics. A failure to reconstruct the newest full table now ends the
  forwarder consistently, including on receive, instead of silently
  recovering with an older table. The daemon's existing coordinated shutdown
  handles failures whose state or expiry duties cannot be recovered safely.
