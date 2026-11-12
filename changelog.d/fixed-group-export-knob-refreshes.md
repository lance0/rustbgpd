### Fixed

- A reload or `SetPeerGroup` that changes `remove_private_as` or
  `local_ipv6_nexthop` for a peer group no longer waits for each member's
  outbound re-emission in turn. Once a member's session accepts the new knobs,
  its re-emission is queued on the background outbound refresher that
  graceful-shutdown toggles already use, and the edit (or its rollback) moves
  on to the next member. Previously the peer manager waited for one full-table
  RIB replay per member, and a single replay slower than 5 s failed the reload
  as ambiguous, which stopped the daemon (exit 70). A slow or failed
  re-emission is now logged and no longer fails the edit. The refresher's log
  lines are renamed to `forced outbound refreshes complete`,
  `forced outbound refresh failed` and `forced outbound refresh reply dropped`,
  since they no longer come only from graceful shutdown. An IPv6 unlock that
  the session already re-emitted is still confirmed with the RIB before the
  edit continues. See [operations](../docs/reference/operations.md).
