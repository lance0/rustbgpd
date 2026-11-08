### Security

- CLI unicast, BGP-LS and topology listings stop with an error when a
  daemon repeats a continuation token, including multi-page cycles.
  The repeated page is rejected before its rows are consumed.
