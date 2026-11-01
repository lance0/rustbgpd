### Fixed

- A session ended by a transport-safety abort or by the expiry of its
  shutdown deadline now hands its unsent outbound routes to the same paced
  release as an ordinary teardown, instead of freeing the whole inventory in
  one turn of the worker thread.
