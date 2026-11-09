### Changed

- The resync tick still sends an owed End-of-RIB that nothing holds, and now
  logs `End-of-RIB sent by the resync tick` at WARN with `peer` and
  `families` when no refused send explains it. An End-of-RIB is otherwise
  sent by the event that clears its last hold, so the log marks a hold that
  ended without sending its marker.
