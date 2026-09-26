### Fixed

- Negotiate Notification GR from the two advertised N bits even when the
  peer advertises no GR or LLGR route-retention families. Max-prefix and BFD
  teardown now send Hard Reset to helper-only peers such as FRR, preserving
  the original Cease reason and data while preventing stale-route retention.
