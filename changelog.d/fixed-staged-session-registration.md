### Fixed

- Ending one session preserves registration metadata already staged by a
  replacement session, including negotiated capability and export context.
  Peer-group identity follows the registered session through replacement and
  collision failback, so its initial advertisements use the correct group policy
  and outbound prefix limits. Re-registering the same session preserves its
  accepted source and peer group unless explicitly replaced or cleared.
