### Fixed

- The RIB no longer scans all peers to arm the End-of-RIB retry timer.
  Each tick checks at most eight peers for marker retries.
