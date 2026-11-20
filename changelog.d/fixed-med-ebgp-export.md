### Fixed

- Ordinary eBGP advertisements now omit a learned route’s MULTI_EXIT_DISC
  unless outbound policy sets a MED for that advertisement. Locally
  originated routes, iBGP advertisements and transparent route-server
  exports retain their MED.
