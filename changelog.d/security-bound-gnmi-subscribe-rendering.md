### Security

- gNMI `Subscribe` renders the paths that select the same data once per
  snapshot, poll, sample tick, and heartbeat, and bounds each render at
  65,536 leaf updates, as `Get` does. A subscription whose paths would render
  more than that against the current roster gets `RESOURCE_EXHAUSTED` before
  any update or `sync_response`, and a stream whose roster grows past the
  bound ends with `RESOURCE_EXHAUSTED` at its next render. Renders above 1,024
  updates run on the blocking pool and share `Get`'s four render slots per
  listener.
  Previously each sample tick rendered up to 16 paths against the whole
  roster on an async worker shared with BGP sessions, discarding duplicates
  only after rendering.
  **Operator-visible:** a full-state all-neighbors subscription against more
  than 6,553 neighbors, or an all-neighbors `ON_CHANGE` subscription against
  more than 65,536, is refused or ended with `RESOURCE_EXHAUSTED`; subscribe to
  specific neighbors or leaves instead
  ([gNMI reference](../docs/reference/gnmi.md#supported-rpcs)).
