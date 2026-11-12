### Security

- gNMI `Get` accepts at most 16 paths, as `Subscribe` does, and renders paths
  that select the same data once. A request whose paths would render more
  than 65,536 leaf updates returns `RESOURCE_EXHAUSTED` before rendering, and
  rendering runs on the blocking pool, at most four requests at once per
  listener.
  Previously one `Get` could put the all-neighbors path in its prefix and
  send millions of empty paths, each rendering every neighbor in memory on an
  async worker shared with BGP sessions.
  **Operator-visible:** a `Get` with more than 16 paths returns
  `INVALID_ARGUMENT`, and a full-state all-neighbors `Get` against more than
  6,553 neighbors returns `RESOURCE_EXHAUSTED`; request specific neighbors or
  leaves instead ([gNMI reference](../docs/reference/gnmi.md#supported-rpcs)).
