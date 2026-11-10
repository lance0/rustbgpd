### Fixed

- A ROUTE-REFRESH carrying several Address-Prefix ORF groups (RFC 5291) is now
  applied as one update followed by at most one re-advertisement pass. Each
  group previously cost its own pass over the peer's table and its own wait
  of up to 500 ms in the session, so a peer with `prefix_orf_receive`
  negotiated could multiply that work by splitting a message into many
  groups. Groups still apply in message order, a group over the entry limit
  is still rejected on its own, and a malformed group still resets the list.
