### Fixed

- Keep each pending initial End-of-RIB behind its own ORF-gated table during
  selection release and dirty recovery. A refresh or recovery for another
  address family no longer completes it early.
