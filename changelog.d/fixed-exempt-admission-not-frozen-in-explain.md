### Fixed

- During Graceful Restart selection deferral, `ExplainAdvertisedRoute` no
  longer reports `selection_deferred` for an RTBH route admitted before the
  hold whose injection has since become ordinary. Deferral lets that route's
  withdrawal go out; while the withdrawal waits on the session writer,
  explain now describes the pending export instead of claiming the peer
  keeps the row until release.
