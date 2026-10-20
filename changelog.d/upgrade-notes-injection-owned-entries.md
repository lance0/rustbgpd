### Upgrade notes

- An entry added with `AddLeasedPath` or `AddLeasedFlowSpec` can be replaced
  or deleted only by its owner: an unowned `AddPath`, `AddFlowSpec`,
  `DeletePath` or `DeleteFlowSpec` on it returns `FAILED_PRECONDITION`. To
  remove one by hand, pass `--owner <name>` or `--override-owner` to
  `rbgp rib delete` or `rbgp flowspec delete`, or set `owner` or
  `override_owner` on the gRPC delete. Unowned entries behave as before.
