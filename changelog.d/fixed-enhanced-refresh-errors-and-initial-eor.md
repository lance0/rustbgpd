### Fixed

- Enhanced Route Refresh now sends notification 7/1 for malformed BoRR/EoRR
  lengths, preserving the complete received PDU when it fits the peer's
  receive limit. Oversized diagnostics use empty data and log the received
  length. Unknown identifiable subtypes are ignored before ORF parsing.
  A GR restarter's initial flood remains unmarked until its initial EoR,
  including ORF-deferred and backpressured dumps; subsequent refreshes use
  normal BoRR/EoRR brackets. BMP records the notification's actual encoding.
