### Fixed

- A SIGHUP reload or API config change now logs the config advisories that
  `rustbgpd --check` reports, such as `orr_vantage` without a `linkstate`
  neighbor or `gr_eor_grace_time` above the advisory ceiling. Before, only
  startup logged them, so an advisory introduced at runtime went unreported.
  **Operator-visible:** after the daemon adopts a reloaded or committed config,
  it logs each advisory the previous config did not raise, using the same WARN
  line as startup. A rejected or discarded candidate logs nothing.
