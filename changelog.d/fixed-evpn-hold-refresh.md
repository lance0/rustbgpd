### Fixed

- During post-restart EVPN selection deferral, a receiver that needs an EVPN
  rebuild continues to receive resyncs and refreshes for its other families.
  Its EVPN withdrawals precede the family's End-of-RIB after selection resumes.
