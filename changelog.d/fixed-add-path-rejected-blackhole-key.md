### Fixed

- An Add-Path receiver no longer briefly loses an RTBH path when a
  blackholing path that its session cannot send replaces it in the same
  pass as one it can. An example is a path whose attributes push a single
  UPDATE past a 4096-byte receiver's message ceiling. The unsendable path
  could take over the departing RTBH path's ID. The rejection then withdrew
  that ID before the sendable path's announcement. Path ID planning now
  checks such paths with the session's encoder whenever the prefix already
  has a blackholing row on the wire. A path the encoder rejects never keeps
  or takes a blackhole path ID, so the sendable path replaces the RTBH path
  in place. Prefixes with no blackholing row do no extra work.
