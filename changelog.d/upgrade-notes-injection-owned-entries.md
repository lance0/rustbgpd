### Upgrade notes

- An entry added with `AddLeasedPath` or `AddLeasedFlowSpec` can be replaced
  or deleted only by its owner: an unowned `AddPath`, `AddFlowSpec`,
  `DeletePath` or `DeleteFlowSpec` on it returns `FAILED_PRECONDITION`.
  `rbgp` delete commands do not yet take an owner; delete an owned entry
  through gRPC with `owner`, or with `override_owner: true`. Unowned entries
  behave as before.
