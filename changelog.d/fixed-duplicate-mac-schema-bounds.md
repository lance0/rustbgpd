### Fixed

- The config JSON Schema advertised a minimum of 0 for
  `duplicate_mac_detection.window_seconds`, `threshold`, and
  `recovery_seconds`, so schema-driven editors accepted values the daemon
  rejects. The schema now carries the validator's bounds: each field is at
  least 1, and `recovery_seconds` is at most 31536000. The Ethernet Segment
  `recovery_delay_seconds` schema entry now carries its maximum of 3600.
  **Operator-visible:** `rustbgpd.schema.json` changes only in these
  `minimum`/`maximum` values and the renamed key (the old spelling stays
  as a deprecated property); accepted configs are unchanged.
