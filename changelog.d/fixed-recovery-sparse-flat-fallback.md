### Fixed

- Retry bounded flat recovery proofs when an older shared unicast/VPN snapshot
  and its immediate sparse additions exceed the proof budget, preserving exact
  admitted keys without unnecessary conservative withdrawals.
