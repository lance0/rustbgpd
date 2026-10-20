### Added

- Every injection lease ownership or generation refusal now carries a
  `google.rpc.ErrorInfo` detail (`domain: "rustbgpd"`) whose `reason` tells
  the cases apart: `OWNER_MISMATCH` when another owner holds the key,
  `KEY_UNOWNED` when no owner holds it, and `GENERATION_NOT_LIVE` when
  `RenewLease` is refused. It applies to `AddLeasedPath`,
  `AddLeasedFlowSpec`, `AddPath` and `AddFlowSpec` on an owned key,
  `DeletePath`, `DeleteFlowSpec` and `RenewLease`. The status code stays
  `FAILED_PRECONDITION`; the reason is contract and the message text is not.
  See [leased injection](../docs/reference/api.md#leased-injection).
