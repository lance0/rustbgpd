### Security

- FSM Error NOTIFICATIONs for unexpected messages identify OpenSent,
  OpenConfirm or Established with RFC 6608 subcodes 1, 2 or 3 and carry
  the unexpected message type. Malformed UPDATEs before Established
  now receive the same FSM Error; malformed headers and OPENs keep
  their existing error codes. Session teardown and route cleanup are
  unchanged.
